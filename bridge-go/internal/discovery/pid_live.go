package discovery

import (
	"os"
	"strconv"
	"syscall"
)

// IsPIDAlive reports whether pid is running. Mirrors the Python is_pid_alive
// helper (bridge_mcp_ghidra.py:261-294).
//
// On POSIX: signal 0 to /proc/<pid>. A successful delivery means the
// process exists (and we have permission to signal it).
//
// On Windows: fall back to os.FindProcess — it always succeeds on Windows,
// so we additionally check that the PID is reasonable (positive). Real
// process liveness on Windows requires OpenProcess via syscall, which is
// left as a follow-up; the worst case is treating a recently-dead process
// as alive, which the next UDS probe will catch and remove.
func IsPIDAlive(pid int) bool {
	if pid <= 0 {
		return false
	}

	// Cross-platform best-effort: try to find the process and signal it.
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	if proc == nil {
		return false
	}

	// On POSIX, Signal(0) returns nil for live processes.
	// On Windows, FindProcess always succeeds and Signal is unsupported.
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		// On Linux, ESRCH = no such process.
		if errno, ok := err.(syscall.Errno); ok {
			switch errno {
			case syscall.ESRCH:
				return false
			case syscall.EPERM:
				return true // exists, but we can't signal it
			}
		}
		return false
	}
	return true
}

// FormatPID is a tiny helper used by tests and log lines.
func FormatPID(pid int) string { return strconv.Itoa(pid) }
