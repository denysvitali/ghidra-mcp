package discovery

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/xebyte/ghidra-mcp-bridge/internal/config"
)

// ConnectTarget is the resolved upstream to use after running the connect
// algorithm.
type ConnectTarget struct {
	Mode   string // "uds" | "tcp"
	Socket string // UDS path (Mode == "uds")
	URL    string // TCP URL (Mode == "tcp")
	PID    int    // UDS only
}

// Resolve picks the active Ghidra target following the Python bridge's
// connect_instance algorithm (lines 1295-1438):
//
//  1. Discover UDS instances.
//  2. Exact match on project.
//  3. Substring match on project (case-insensitive).
//  4. If user supplied an explicit URL via env or flag, use it directly.
//  5. If UDS found *any* instances but none matched, REFUSE to fall back
//     to TCP (Copilot #196 review).
//  6. If UDS found nothing, scan TCP ports.
//  7. Fall back to DefaultTCPURL.
//
// Logger is optional; pass nil to silence discovery chatter.
func Resolve(ctx context.Context, project, explicitURL string, logger Logger) (*ConnectTarget, error) {
	if explicitURL != "" {
		if err := ValidateServerURL(explicitURL); err != nil {
			return nil, err
		}
		return &ConnectTarget{Mode: "tcp", URL: explicitURL}, nil
	}

	instances := DiscoverInstances(ctx, logger)
	if len(instances) > 0 {
		// Exact match wins.
		for _, inst := range instances {
			if inst.Project == project {
				return &ConnectTarget{
					Mode:   "uds",
					Socket: inst.Socket,
					PID:    inst.PID,
				}, nil
			}
		}
		// Substring match (case-insensitive).
		plower := strings.ToLower(project)
		for _, inst := range instances {
			if strings.Contains(strings.ToLower(inst.Project), plower) {
				return &ConnectTarget{
					Mode:   "uds",
					Socket: inst.Socket,
					PID:    inst.PID,
				}, nil
			}
		}
		// UDS had candidates but none matched → refuse silent fallback.
		names := make([]string, len(instances))
		for i, inst := range instances {
			names[i] = inst.Project
		}
		return nil, &NoMatchError{
			Project: project,
			Found:   names,
		}
	}

	// No UDS instances; scan TCP.
	if url, err := ScanTCPForProject(ctx, project); err == nil {
		return &ConnectTarget{Mode: "tcp", URL: url}, nil
	}

	// Last resort: explicit default URL.
	if _, err := os.Stat("/"); err == nil {
		return &ConnectTarget{Mode: "tcp", URL: config.DefaultTCPURL}, nil
	}
	return nil, fmt.Errorf("no Ghidra instance reachable")
}

// NoMatchError is returned when UDS discovered instances but none matched
// the requested project. It tells the caller what projects *were* available
// so the user can fix the request.
type NoMatchError struct {
	Project string
	Found   []string
}

func (e *NoMatchError) Error() string {
	return fmt.Sprintf("no Ghidra instance matches %q; found: %s", e.Project, strings.Join(e.Found, ", "))
}

// ValidateServerURL refuses non-loopback URLs (SSRF guard).
// Mirrors bridge_mcp_ghidra.py:validate_server_url (lines 297-303).
func ValidateServerURL(u string) error {
	if u == "" {
		return nil
	}
	// Strip scheme if present.
	host := u
	if i := strings.Index(u, "://"); i >= 0 {
		host = u[i+3:]
	}
	// Strip path.
	if i := strings.Index(host, "/"); i >= 0 {
		host = host[:i]
	}
	// Strip port. Handle bracketed IPv6 like [::1]:8089.
	host = strings.TrimPrefix(strings.TrimPrefix(host, "["), "")
	if i := strings.Index(host, ":"); i >= 0 {
		// For IPv6 without brackets, this strips the first ":" which is
		// already after the address; for bracketed form the bracket was
		// stripped above so the first ":" is the port separator.
		if !strings.Contains(host, "]") {
			host = host[:i]
		} else {
			// bracketed IPv6 case: host contains "]" but we've already
			// stripped "[", so the trailing ":port" is still present.
			if j := strings.LastIndex(host, ":"); j > 0 {
				host = host[:j]
			}
		}
	}
	// For unbracketed IPv6 like "::1" (no port), keep it whole.
	switch strings.TrimSuffix(strings.TrimPrefix(strings.TrimSuffix(host, "]"), "["), "") {
	case "127.0.0.1", "localhost", "::1":
		return nil
	}
	return fmt.Errorf("refusing non-local URL %q (only 127.0.0.1/localhost/::1 allowed)", u)
}
