package transport

import "strings"

// FilterEmpty removes entries that are nil, empty string, or whitespace-only.
// This is the Go equivalent of the Python bridge's None/empty-string filter
// at lines 1017-1021 — a workaround for Codex-style MCP clients that send
// schema defaults (including "" for optional fields).
func FilterEmpty(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		if v == nil {
			continue
		}
		if s, ok := v.(string); ok {
			if strings.TrimSpace(s) == "" {
				continue
			}
		}
		out[k] = v
	}
	return out
}

// CoerceCommentEntries normalizes the user-supplied "comments" payload for
// /batch_set_comments into a list of {address, comment} dicts.
//
// Accepts:
//   - a JSON string of either shape
//   - a single object {address, comment}
//   - a list of either
//
// Mirrors Python _coerce_comment_entries at lines 646-667.
func CoerceCommentEntries(raw any) ([]map[string]any, error) {
	switch v := raw.(type) {
	case nil:
		return nil, nil
	case string:
		// Try to decode as JSON.
		var probe any
		if err := jsonUnmarshal([]byte(v), &probe); err != nil {
			return nil, err
		}
		return CoerceCommentEntries(probe)
	case []any:
		out := make([]map[string]any, 0, len(v))
		for _, item := range v {
			entry, err := coerceOneComment(item)
			if err != nil {
				return nil, err
			}
			out = append(out, entry)
		}
		return out, nil
	case map[string]any:
		entry, err := coerceOneComment(v)
		if err != nil {
			return nil, err
		}
		return []map[string]any{entry}, nil
	default:
		return nil, &CoerceError{Message: "unsupported comments payload type"}
	}
}

func coerceOneComment(v any) (map[string]any, error) {
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, &CoerceError{Message: "comment entry must be an object"}
	}
	addr, _ := obj["address"].(string)
	comment, _ := obj["comment"].(string)
	if addr == "" {
		return nil, &CoerceError{Message: "comment entry missing 'address'"}
	}
	return map[string]any{"address": addr, "comment": comment}, nil
}

// CoerceError indicates the comment payload was malformed.
type CoerceError struct{ Message string }

func (e *CoerceError) Error() string { return "coerce comments: " + e.Message }
