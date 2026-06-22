package transport

import "strings"

// indexOfImpl is a thin wrapper around strings.Index so transport/client.go
// doesn't need to import strings directly. Kept here for clarity.
func indexOfImpl(s, sub string) int { return strings.Index(s, sub) }
