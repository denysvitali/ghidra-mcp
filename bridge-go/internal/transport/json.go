package transport

import "encoding/json"

// jsonUnmarshal is a tiny indirection so transport/payload.go doesn't
// need to import encoding/json directly. Kept here for clarity.
func jsonUnmarshal(data []byte, v any) error { return json.Unmarshal(data, v) }
