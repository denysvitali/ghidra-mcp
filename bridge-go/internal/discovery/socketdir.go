// Package discovery enumerates running Ghidra instances via Unix domain
// sockets (the Java plugin's default transport) and falls back to TCP port
// scanning when UDS isn't available.
//
// This is a 1:1 port of the Python bridge's get_socket_dir_candidates +
// discover_instances + _scan_tcp_for_project logic (bridge_mcp_ghidra.py
// lines 134-617). The candidate ordering and the multi-dir glob strategy
// matter: Claude Desktop doesn't forward $TMPDIR, so on macOS the bridge
// must scan both /var/folders/*/*/T/... and /private/var/folders/*/*/T/...
// (the symlink target).
package discovery

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// currentUser returns $USER / $USERNAME with a fallback to "unknown",
// matching the Python implementation at bridge_mcp_ghidra.py:164.
func currentUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	if u := os.Getenv("USERNAME"); u != "" {
		return u
	}
	return "unknown"
}

// currentUID returns the numeric UID on POSIX, or 0 on Windows.
func currentUID() int {
	if runtime.GOOS == "windows" {
		return 0
	}
	// os.Getuid is the standard way.
	return os.Getuid()
}

// SocketDirCandidates returns every plausible socket directory, in the
// order the Python bridge tries them. The list is deduplicated by absolute
// path. Empty candidates are filtered out.
func SocketDirCandidates() []string {
	user := currentUser()
	var candidates []string

	// 1. $XDG_RUNTIME_DIR/ghidra-mcp
	if x := os.Getenv("XDG_RUNTIME_DIR"); x != "" {
		candidates = append(candidates, filepath.Join(x, "ghidra-mcp"))
	}

	// 2. /run/user/<uid>/ghidra-mcp (if /run/user/<uid> exists)
	uid := currentUID()
	if uid > 0 {
		runUser := "/run/user/" + strconv.Itoa(uid)
		if info, err := os.Stat(runUser); err == nil && info.IsDir() {
			candidates = append(candidates, filepath.Join(runUser, "ghidra-mcp"))
		}
	}

	// 3. $TMPDIR/ghidra-mcp-<user> (per-user macOS temp)
	if td := os.Getenv("TMPDIR"); td != "" {
		candidates = append(candidates, filepath.Join(td, "ghidra-mcp-"+user))
	}

	// 4. macOS per-user temp: /var/folders/*/*/T/ghidra-mcp-<user>
	if runtime.GOOS == "darwin" {
		matches, _ := filepath.Glob("/var/folders/*/*/T/ghidra-mcp-" + user)
		candidates = append(candidates, matches...)
		matches2, _ := filepath.Glob("/private/var/folders/*/*/T/ghidra-mcp-" + user)
		candidates = append(candidates, matches2...)
	}

	// 5. /tmp/ghidra-mcp-<user> (POSIX fallback)
	candidates = append(candidates, filepath.Join("/tmp", "ghidra-mcp-"+user))

	// 6. Windows temp
	if runtime.GOOS == "windows" {
		temp := os.Getenv("TEMP")
		if temp == "" {
			temp = os.Getenv("TMP")
		}
		if temp != "" {
			candidates = append(candidates, filepath.Join(temp, "ghidra-mcp-"+user))
		}
	}

	// Deduplicate by absolute path.
	seen := make(map[string]struct{}, len(candidates))
	out := make([]string, 0, len(candidates))
	for _, c := range candidates {
		abs, err := filepath.Abs(c)
		if err != nil {
			abs = c
		}
		if _, ok := seen[abs]; ok {
			continue
		}
		seen[abs] = struct{}{}
		out = append(out, abs)
	}
	return out
}

// SocketDir returns the first candidate. Back-compat shim for the Python
// get_socket_dir() wrapper (bridge_mcp_ghidra.py:134-143).
func SocketDir() string {
	cands := SocketDirCandidates()
	if len(cands) == 0 {
		return ""
	}
	return cands[0]
}

// instanceFromSocket probes a single socket and returns its instance_info
// if it's a live Ghidra server. Stale sockets (dead PID) are deleted.
func instanceFromSocket(ctx context.Context, path string, logger Logger) (*Instance, error) {
	pid, err := parseGhidraPID(path)
	if err != nil {
		// Not a ghidra-<pid>.sock; skip.
		return nil, err
	}
	if !IsPIDAlive(pid) {
		// Stale. Best-effort remove; ignore failures.
		_ = os.Remove(path)
		return nil, fmt.Errorf("stale socket pid %d", pid)
	}

	// Probe /mcp/instance_info over UDS. Use a short timeout.
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &unixTransport{socketPath: path},
	}
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, "http://unix/mcp/instance_info", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		// Connection refused is normal during Ghidra startup; log + skip.
		if logger != nil {
			logger.Debugf("uds probe %s: %v", path, err)
		}
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	var info InstanceInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decode instance_info: %w", err)
	}
	return &Instance{
		Socket:     path,
		PID:        pid,
		Project:    info.Project,
		Programs:   info.Programs,
		Info:       info,
		Discovered: time.Now(),
	}, nil
}

// DiscoverInstances enumerates every live Ghidra instance across all socket
// dir candidates. Returns deduplicated instances keyed by absolute socket
// path. Stale sockets are removed as a side effect.
func DiscoverInstances(ctx context.Context, logger Logger) []*Instance {
	var out []*Instance
	seen := make(map[string]struct{})

	for _, dir := range SocketDirCandidates() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue // missing dir is normal
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if !strings.HasSuffix(name, ".sock") {
				continue
			}
			full := filepath.Join(dir, name)
			abs, err := filepath.Abs(full)
			if err != nil {
				abs = full
			}
			if _, dup := seen[abs]; dup {
				continue
			}
			seen[abs] = struct{}{}

			inst, err := instanceFromSocket(ctx, full, logger)
			if err != nil {
				continue
			}
			out = append(out, inst)
		}
	}

	// Stable order: by socket path.
	sort.Slice(out, func(i, j int) bool { return out[i].Socket < out[j].Socket })
	return out
}

// parseGhidraPID extracts the PID from a socket filename like
// "ghidra-12345.sock". Returns an error if the name doesn't match.
func parseGhidraPID(path string) (int, error) {
	base := filepath.Base(path)
	if !strings.HasSuffix(base, ".sock") {
		return 0, fmt.Errorf("not a .sock file: %s", base)
	}
	stem := strings.TrimSuffix(base, ".sock")
	const prefix = "ghidra-"
	if !strings.HasPrefix(stem, prefix) {
		return 0, fmt.Errorf("not a ghidra socket: %s", base)
	}
	pidStr := strings.TrimPrefix(stem, prefix)
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return 0, fmt.Errorf("invalid pid %q: %w", pidStr, err)
	}
	return pid, nil
}

// ListSockFiles returns every *.sock file in dir (no probing).
func ListSockFiles(dir string) ([]string, error) {
	var out []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(e.Name(), ".sock") {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out, nil
}

// HasFallbackTempDir reports whether the per-platform fallback
// /tmp/ghidra-mcp-<user> directory exists on disk.
func HasFallbackTempDir() bool {
	for _, dir := range SocketDirCandidates() {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			if runtime.GOOS != "windows" && strings.HasPrefix(dir, "/tmp/") {
				return true
			}
		}
	}
	return false
}

// Logger is the minimal interface DiscoverInstances needs. Pass logx.Logger.
type Logger interface {
	Debugf(format string, args ...any)
}

// IsNotExist is re-exported so callers don't need to import os.
func IsNotExist(err error) bool { return err != nil && errorsIs(err, fs.ErrNotExist) }

// errorsIs is a local copy of errors.Is for cheap import-free use.
func errorsIs(err, target error) bool {
	for err != nil {
		if err == target {
			return true
		}
		type unwrapper interface{ Unwrap() error }
		if u, ok := err.(unwrapper); ok {
			err = u.Unwrap()
			continue
		}
		return false
	}
	return false
}

// Ensure bufio is imported (used by future TCP probes).
var _ = bufio.NewReader

// Ensure net is imported (used by future UDS dialers).
var _ = net.Dial
