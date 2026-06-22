package dispatcher

import (
	"encoding/json"
	"errors"
	"fmt"
)

// ErrorResponse is the JSON envelope returned when a dispatch call fails
// before reaching Ghidra. Mirrors the Python bridge's
// {"error": "..."} responses (e.g. lines 771, 793).
type ErrorResponse struct {
	Error   string `json:"error"`
	Hint    string `json:"hint,omitempty"`
	Details string `json:"details,omitempty"`
}

// MarshalErrorResponse returns a JSON-encoded error envelope. The caller
// should return this string directly from an MCP tool handler.
func MarshalErrorResponse(err error) string {
	resp := ErrorResponse{Error: err.Error()}
	var nce *NotConnectedError
	if errors.As(err, &nce) {
		resp.Hint = "Call connect_instance first."
	}
	out, mErr := json.Marshal(resp)
	if mErr != nil {
		// Fallback to a hand-rolled envelope so we always return valid JSON.
		return fmt.Sprintf(`{"error":%q}`, err.Error())
	}
	return string(out)
}
