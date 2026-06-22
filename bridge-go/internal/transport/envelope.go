package transport

import "encoding/json"

// UnwrapResponseData accepts either a bare JSON object or a {"data": {...}}
// envelope and returns the inner payload. Mirrors Python
// _unwrap_response_data (bridge_mcp_ghidra.py:526-531).
func UnwrapResponseData(body string) (map[string]any, error) {
	if body == "" {
		return map[string]any{}, nil
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(body), &raw); err != nil {
		return nil, err
	}
	if data, ok := raw["data"].(map[string]any); ok {
		return data, nil
	}
	return raw, nil
}
