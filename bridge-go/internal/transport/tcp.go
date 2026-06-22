package transport

import (
	"net/http"
	"time"
)

// NewTCPHTTPClient returns a stdlib http.Client pointed at a loopback
// Ghidra server. timeout applies to the full request/response cycle.
func NewTCPHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
	}
}
