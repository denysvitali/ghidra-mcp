package schema

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/xebyte/ghidra-mcp-bridge/internal/config"
)

// Patterns and constants lifted from the Python bridge.
var (
	invalidChars   = regexp.MustCompile(`[^a-zA-Z0-9_-]+`)
	repeatedUnders = regexp.MustCompile(`_+`)
	toolNameRegex  = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
)

// SanitizeToolName converts any string into a CAPI-safe MCP tool name.
//
// Algorithm (byte-identical to Python sanitize_tool_name, lines 317-329):
//
//  1. Lowercase.
//  2. Replace every run of invalid chars ([^a-zA-Z0-9_-]+) with a single "_".
//  3. Trim leading/trailing "_".
//  4. Truncate to MaxToolNameLength (64), trimming trailing "_".
//  5. Validate against ^[a-zA-Z0-9_-]+$.
//
// Returns an error if the result is empty (e.g. input "////").
func SanitizeToolName(name string) (string, error) {
	s := invalidChars.ReplaceAllString(strings.ToLower(name), "_")
	s = repeatedUnders.ReplaceAllString(s, "_")
	s = strings.Trim(s, "_")
	if s == "" {
		return "", fmt.Errorf("tool name %q is empty after sanitization", name)
	}
	if len(s) > config.MaxToolNameLength {
		s = strings.TrimRight(s[:config.MaxToolNameLength], "_")
		if s == "" {
			return "", fmt.Errorf("tool name %q is empty after truncation", name)
		}
	}
	if !toolNameRegex.MatchString(s) {
		return "", fmt.Errorf("sanitized tool name %q is still invalid", s)
	}
	return s, nil
}

// AllocateToolName returns base if unused, or base + "_N" (N=2,3,...) with
// the base trimmed to leave room for the suffix. Mutates `used` to mark
// the returned name as taken. Mirrors Python _allocate_tool_name.
//
// used must be seeded with the static tool names before calling this for
// the first time.
func AllocateToolName(base string, used map[string]struct{}) (string, error) {
	if _, ok := used[base]; !ok {
		used[base] = struct{}{}
		return base, nil
	}
	for n := 2; ; n++ {
		suffix := fmt.Sprintf("_%d", n)
		// Trim the base to leave room for the suffix. If the base is already
		// shorter than the available budget, use it whole; the resulting
		// candidate may be shorter than MaxToolNameLength.
		maxBase := config.MaxToolNameLength - len(suffix)
		if maxBase < 1 {
			return "", fmt.Errorf("tool name %q too short to suffix safely", base)
		}
		var trimmed string
		if len(base) > maxBase {
			trimmed = strings.TrimRight(base[:maxBase], "_")
		} else {
			trimmed = base
		}
		if trimmed == "" {
			return "", fmt.Errorf("tool name %q too short to suffix safely", base)
		}
		candidate := trimmed + suffix
		if _, ok := used[candidate]; !ok {
			used[candidate] = struct{}{}
			return candidate, nil
		}
	}
}

// ValidateToolName reports whether s satisfies the CAPI regex.
func ValidateToolName(s string) bool {
	if s == "" || len(s) > config.MaxToolNameLength {
		return false
	}
	return toolNameRegex.MatchString(s)
}
