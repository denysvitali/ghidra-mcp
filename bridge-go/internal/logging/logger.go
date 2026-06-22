// Package logging wires the logrus-backed logx.Logger implementation.
//
// The writer is always os.Stderr — stdout is reserved for MCP stdio frames
// and must not be polluted with human-readable log lines (see issue #91).
package logging

import (
	"io"
	"maps"
	"os"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/xebyte/ghidra-mcp-bridge/internal/logx"
)

var (
	mu      sync.Mutex
	current logx.Logger = logx.Noop
)

// logrusLogger adapts *logrus.Logger to the logx.Logger interface.
type logrusLogger struct {
	base *logrus.Entry
}

func (l *logrusLogger) Debugf(format string, args ...any) {
	l.base.Debugf(format, args...)
}

func (l *logrusLogger) Infof(format string, args ...any) {
	l.base.Infof(format, args...)
}

func (l *logrusLogger) Warnf(format string, args ...any) {
	l.base.Warnf(format, args...)
}

func (l *logrusLogger) Errorf(format string, args ...any) {
	l.base.Errorf(format, args...)
}

func (l *logrusLogger) WithField(key string, value any) logx.Logger {
	return &logrusLogger{base: l.base.WithField(key, value)}
}

func (l *logrusLogger) WithFields(fields map[string]any) logx.Logger {
	if len(fields) == 0 {
		return l
	}
	logrusFields := make(logrus.Fields, len(fields))
	maps.Copy(logrusFields, fields)
	return &logrusLogger{base: l.base.WithFields(logrusFields)}
}

func (l *logrusLogger) WithError(err error) logx.Logger {
	if err == nil {
		return l
	}
	return &logrusLogger{base: l.base.WithError(err)}
}

// Init configures the global logrus logger and installs the logx adapter.
//
//   - level: one of "debug", "info", "warn", "error" (case-insensitive).
//     Unknown values fall back to info.
//   - writer: defaults to os.Stderr if nil.
func Init(level string, writer io.Writer) logx.Logger {
	mu.Lock()
	defer mu.Unlock()

	if writer == nil {
		writer = os.Stderr
	}

	l := logrus.New()
	l.SetOutput(writer)
	l.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:          true,
		TimestampFormat:        "2006-01-02T15:04:05.000Z07:00",
		DisableColors:          true,
		DisableLevelTruncation: true,
	})
	l.SetLevel(parseLevel(level))

	entry := logrus.NewEntry(l)
	adapter := &logrusLogger{base: entry}
	current = adapter
	return adapter
}

// Logrus exposes the underlying *logrus.Logger for tests and hooks that need
// the full API. It returns nil if Init has not been called.
func Logrus() *logrus.Logger {
	if l, ok := current.(*logrusLogger); ok {
		return l.base.Logger
	}
	return nil
}

// Get returns the currently-installed logger.
func Get() logx.Logger {
	mu.Lock()
	defer mu.Unlock()
	return current
}

// Set installs a custom logger (used by tests).
func Set(l logx.Logger) {
	mu.Lock()
	defer mu.Unlock()
	current = l
}

func parseLevel(s string) logrus.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "trace":
		return logrus.TraceLevel
	case "debug":
		return logrus.DebugLevel
	case "info", "":
		return logrus.InfoLevel
	case "warn", "warning":
		return logrus.WarnLevel
	case "error":
		return logrus.ErrorLevel
	default:
		return logrus.InfoLevel
	}
}
