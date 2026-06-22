//go:build !windows

package style

import "os"

// isatty uses os.File.Stat to check whether fd refers to a character
// device. Cross-platform and avoids platform-specific ioctl constants
// (e.g. unix.TCGETS only exists on Linux/BSD, not darwin).
func isatty(fd uintptr) bool {
	f := os.NewFile(fd, "fd")
	if f == nil {
		return false
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}