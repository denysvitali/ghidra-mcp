package discovery

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSocketDirCandidates_IncludesXDGAndTmp(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	t.Setenv("USER", "alice")
	t.Setenv("XDG_RUNTIME_DIR", "") // disable XDG path
	t.Setenv("USERNAME", "")

	cands := SocketDirCandidates()
	want := filepath.Join(tmp, "ghidra-mcp-alice")
	found := false
	for _, c := range cands {
		if c == want {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected %q in candidates, got %v", want, cands)
	}
}

func TestSocketDirCandidates_Dedup(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	t.Setenv("USER", "bob")
	t.Setenv("XDG_RUNTIME_DIR", "")
	cands := SocketDirCandidates()

	seen := make(map[string]struct{})
	for _, c := range cands {
		if _, dup := seen[c]; dup {
			t.Errorf("duplicate candidate: %q", c)
		}
		seen[c] = struct{}{}
	}
}

func TestParseGhidraPID(t *testing.T) {
	cases := []struct {
		path string
		want int
		ok   bool
	}{
		{"/tmp/ghidra-mcp-alice/ghidra-12345.sock", 12345, true},
		{"/var/folders/ghidra-987.sock", 987, true},
		{"/tmp/random.sock", 0, false},
		{"/tmp/ghidra.sock", 0, false},
		{"/tmp/ghidra-abc.sock", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			pid, err := parseGhidraPID(tc.path)
			if tc.ok {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if pid != tc.want {
					t.Errorf("got %d, want %d", pid, tc.want)
				}
			} else if err == nil {
				t.Fatalf("expected error")
			}
		})
	}
}

func TestIsPIDAlive_CurrentAndDead(t *testing.T) {
	if !IsPIDAlive(os.Getpid()) {
		t.Errorf("expected os.Getpid() to be alive")
	}
	// A high PID that almost certainly doesn't exist.
	if IsPIDAlive(999999) {
		t.Errorf("expected high PID to be dead")
	}
}

func TestValidateServerURL(t *testing.T) {
	good := []string{"", "http://127.0.0.1:8089", "http://localhost:8080", "http://[::1]:8089"}
	for _, u := range good {
		if err := ValidateServerURL(u); err != nil {
			t.Errorf("ValidateServerURL(%q) = %v, want nil", u, err)
		}
	}
	bad := []string{"http://example.com", "http://10.0.0.1:8089", "http://0.0.0.0:8089"}
	for _, u := range bad {
		if err := ValidateServerURL(u); err == nil {
			t.Errorf("ValidateServerURL(%q) = nil, want error", u)
		}
	}
}

func TestSocketDirCandidates_DarwinMacOSGlobs(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	// Just exercise the function — we don't assert specific paths since
	// the test runner may not have a /var/folders layout. We assert the
	// call doesn't panic and returns something.
	_ = SocketDirCandidates()
}
