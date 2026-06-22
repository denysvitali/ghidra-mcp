// Package style provides lipgloss renderers for stderr output.
//
// Lipgloss output MUST go to stderr only. Writing styled text to stdout
// corrupts MCP stdio JSON-RPC framing (see issue #91).
//
// When stderr is not a TTY (e.g. when captured by an MCP client), renderers
// degrade to plain text so logs stay readable and grep-friendly.
package style

import (
	"fmt"
	"io"
	"os"
	"sync"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/colorprofile"
)

// Styles holds the style definitions and the writer used for output.
// Construct via New; the package-level helpers (Banner/OK/Warn/Err/Panel)
// operate on the global instance installed by Init.
type Styles struct {
	w       io.Writer
	tty     bool
	profile colorprofile.Profile

	Title  lipgloss.Style
	OK     lipgloss.Style
	Warn   lipgloss.Style
	Err    lipgloss.Style
	Muted  lipgloss.Style
	Accent lipgloss.Style
	Bullet lipgloss.Style
	Key    lipgloss.Style
	Value  lipgloss.Style
	Panel  lipgloss.Style
	Banner lipgloss.Style
}

var (
	global   *Styles
	globalMu sync.Mutex
	isTerm   = isatty(os.Stderr.Fd())
)

// New builds a Styles renderer writing to w. If tty is true the output is
// color-downsampled by lipgloss.Fprintln; otherwise all renderers degrade
// to plain text.
func New(w io.Writer, tty bool) *Styles {
	s := &Styles{w: w, tty: tty}
	if tty {
		s.profile = colorprofile.Detect(w, os.Environ())
		s.Title = lipgloss.NewStyle().Bold(true)
		s.OK = lipgloss.NewStyle()
		s.Warn = lipgloss.NewStyle()
		s.Err = lipgloss.NewStyle().Bold(true)
		s.Muted = lipgloss.NewStyle()
		s.Accent = lipgloss.NewStyle()
		s.Bullet = lipgloss.NewStyle()
		s.Key = lipgloss.NewStyle()
		s.Value = lipgloss.NewStyle()
		s.Panel = lipgloss.NewStyle()
		s.Banner = lipgloss.NewStyle()
	} else {
		// Identity styles: Render returns the input verbatim.
		s.Title = lipgloss.NewStyle()
		s.OK = lipgloss.NewStyle()
		s.Warn = lipgloss.NewStyle()
		s.Err = lipgloss.NewStyle()
		s.Muted = lipgloss.NewStyle()
		s.Accent = lipgloss.NewStyle()
		s.Bullet = lipgloss.NewStyle()
		s.Key = lipgloss.NewStyle()
		s.Value = lipgloss.NewStyle()
		s.Panel = lipgloss.NewStyle()
		s.Banner = lipgloss.NewStyle()
	}
	return s
}

// Init installs a global Styles bound to stderr.
func Init(tty bool) *Styles {
	globalMu.Lock()
	defer globalMu.Unlock()
	global = New(os.Stderr, tty)
	return global
}

// Set installs a custom global Styles (tests).
func Set(s *Styles) {
	globalMu.Lock()
	defer globalMu.Unlock()
	global = s
}

// Get returns the global styles, initializing a default if needed.
func Get() *Styles {
	globalMu.Lock()
	defer globalMu.Unlock()
	if global == nil {
		global = New(os.Stderr, isTerm)
	}
	return global
}

// IsTTY reports whether stderr is a terminal at startup.
func IsTTY() bool { return isTerm }

// Banner writes a banner-style header to stderr.
func Banner(title string) { Get().printStyled(Get().Title.Render(" " + title + " ")) }

// OK writes a success marker + message.
func OK(msg string) {
	s := Get()
	s.printStyled(s.OK.Render("✓ ") + msg)
}

// Warn writes a warning marker + message.
func Warn(msg string) {
	s := Get()
	s.printStyled(s.Warn.Render("! ") + msg)
}

// Err writes an error marker + message.
func Err(msg string) {
	s := Get()
	s.printStyled(s.Err.Render("✗ ") + msg)
}

// Panel writes a header + body. When not a TTY, falls back to plain
// "header\nbody" so it stays grep-friendly.
func Panel(title, body string) {
	s := Get()
	if !s.tty {
		fmt.Fprintf(s.w, "%s\n%s\n", title, body)
		return
	}
	header := s.Title.Render(" " + title + " ")
	boxed := s.Panel.Render(header + "\n" + body)
	s.printStyled(boxed)
}

// Log writes a single formatted line using the muted style.
func Log(format string, args ...any) {
	s := Get()
	s.printStyled(s.Muted.Render(fmt.Sprintf(format, args...)))
}

// printStyled writes rendered text to the configured writer, routing
// through lipgloss.Fprintln when a TTY profile is available.
func (s *Styles) printStyled(rendered string) {
	if rendered == "" {
		return
	}
	if s.tty {
		_, _ = lipgloss.Fprintln(s.w, rendered)
		return
	}
	fmt.Fprintln(s.w, rendered)
}
