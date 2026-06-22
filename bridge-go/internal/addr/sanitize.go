// Package addr sanitizes and validates Ghidra memory addresses.
//
// Ghidra addresses can appear in several shapes:
//
//   - "0x401000"        — bare hex, lowercase
//   - "401000"          — bare hex without 0x prefix
//   - "ram:0x401000"    — segment-prefixed (overlay normal)
//   - "ram::0x401000"   — double-colon overlay (preserve case)
//   - "kernel::0xfffe1234" — overlay segment with uppercase hex
//
// sanitize_address normalizes these to a canonical form before they're
// handed to MCP tools. The Python bridge does this at lines 737-764; this
// file is a 1:1 port.
package addr

import (
	"fmt"
	"regexp"
	"strings"
)

// Patterns lifted from the Python bridge (lines 240-258).
var (
	// HexAddressPattern matches "0xHEX" or "HEX" (1+ hex chars).
	HexAddressPattern = regexp.MustCompile(`^(?:0x)?([0-9a-fA-F]+)$`)

	// SegmentAddressPattern matches "segment:HEX" — single colon, no 0x.
	SegmentAddressPattern = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*):([0-9a-fA-F]+)$`)

	// SegmentAddrWith0XPattern matches "segment:0xHEX" — single colon + 0x prefix.
	SegmentAddrWith0XPattern = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*):(0x[0-9a-fA-F]+)$`)

	// OverlayPattern matches "segment::HEX" or "segment::0xHEX" — double colon.
	OverlayPattern = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)::((?:0x)?[0-9a-fA-F]+)$`)
)

// Sanitize normalizes an address string.
//
// Rules (matching the Python implementation):
//   - "space:0xHEX"   → "space:HEX"  (strip 0x after single colon)
//   - "space::0xHEX"  → preserved   (overlay keeps 0x)
//   - "0xHEX"         → "0xHEX"     (already canonical)
//   - "HEX"           → "0xHEX"     (add prefix)
//   - "HEX" (uppercase) → "0x<lowercase>" (canonicalize case)
//   - Overlay segment with uppercase hex → preserve case
//
// Returns the original string (trimmed) if it doesn't match a known shape.
func Sanitize(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("empty address")
	}

	// Overlay form: segment::HEX or segment::0xHEX. Preserve case.
	if m := OverlayPattern.FindStringSubmatch(s); m != nil {
		seg := m[1]
		hex := m[2]
		if !strings.HasPrefix(hex, "0x") {
			hex = "0x" + strings.ToLower(hex)
		}
		return seg + "::" + hex, nil
	}

	// Single-colon segment with 0x: strip the 0x.
	if m := SegmentAddrWith0XPattern.FindStringSubmatch(s); m != nil {
		seg := m[1]
		hex := m[2]
		// hex is "0xHEX"; strip the prefix and lowercase the digits.
		hex = "0x" + strings.ToLower(hex[2:])
		return seg + ":" + hex, nil
	}

	// Single-colon segment without 0x: add it.
	if m := SegmentAddressPattern.FindStringSubmatch(s); m != nil {
		seg := m[1]
		hex := m[2]
		return seg + ":0x" + strings.ToLower(hex), nil
	}

	// Bare hex (with or without 0x): add/normalize.
	if m := HexAddressPattern.FindStringSubmatch(s); m != nil {
		return "0x" + strings.ToLower(m[1]), nil
	}

	// Unknown shape — return as-is. Validation happens at the endpoint.
	return s, nil
}

// ValidateHexAddress reports whether s is a syntactically valid hex address.
// Accepts all forms that Sanitize accepts.
func ValidateHexAddress(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	return HexAddressPattern.MatchString(s) ||
		SegmentAddressPattern.MatchString(s) ||
		SegmentAddrWith0XPattern.MatchString(s) ||
		OverlayPattern.MatchString(s)
}
