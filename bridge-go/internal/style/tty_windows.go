//go:build windows

package style

import "golang.org/x/sys/windows"

// isatty checks whether the given file descriptor is a console.
func isatty(fd uintptr) bool {
	var mode uint32
	err := windows.GetConsoleMode(windows.Handle(fd), &mode)
	return err == nil
}
