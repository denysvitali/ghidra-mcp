// Package logx provides the Logger interface used throughout the bridge.
//
// Logrus is the v1 implementation (see internal/logging). Wrapping the logger
// behind an interface lets us swap to log/slog or any other backend later
// without touching call sites.
package logx

// Logger is the minimal interface every backend must satisfy.
//
// All level methods take a format string + variadic args (printf-style) to
// keep call sites readable. Structured fields are exposed via WithField,
// which returns a derived logger that prepends the field on every call.
type Logger interface {
	Debugf(format string, args ...any)
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)

	WithField(key string, value any) Logger
	WithFields(fields map[string]any) Logger
	WithError(err error) Logger
}

// Discard is a Logger that drops every message. Useful for tests and for
// branches where logging is intentionally suppressed.
type Discard struct{}

func (Discard) Debugf(string, ...any) {}
func (Discard) Infof(string, ...any)  {}
func (Discard) Warnf(string, ...any)  {}
func (Discard) Errorf(string, ...any) {}
func (Discard) WithField(string, any) Logger {
	return Discard{}
}
func (Discard) WithFields(map[string]any) Logger {
	return Discard{}
}
func (Discard) WithError(error) Logger {
	return Discard{}
}

// noopLogger is the default zero-value used before Init runs.
type noopLogger struct{}

func (noopLogger) Debugf(string, ...any)            {}
func (noopLogger) Infof(string, ...any)             {}
func (noopLogger) Warnf(string, ...any)             {}
func (noopLogger) Errorf(string, ...any)            {}
func (noopLogger) WithField(string, any) Logger     { return noopLogger{} }
func (noopLogger) WithFields(map[string]any) Logger { return noopLogger{} }
func (noopLogger) WithError(error) Logger           { return noopLogger{} }

// Nop returns a Logger that ignores every call.
func Nop() Logger { return Discard{} }

// Noop is preserved as an alias for Nop.
var Noop Logger = noopLogger{}
