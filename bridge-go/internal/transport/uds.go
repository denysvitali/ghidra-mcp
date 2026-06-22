// Package transport implements the two upstream HTTP transports the
// Ghidra MCP bridge uses: Unix domain sockets (the default on Linux/macOS)
// and TCP loopback. The dispatcher (internal/dispatcher) serializes all
// calls through a sync.Mutex to prevent stdout framing corruption
// (GH issue #91).
package transport

import (
	"context"
	"net"
	"net/http"
	"time"
)

// unixDialer is a net.Dialer wrapper that always connects to socketPath
// regardless of the (host, port) pair http.Transport passes.
type unixDialer struct {
	socketPath string
}

func (d *unixDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, "unix", d.socketPath)
}

// unixTransport routes every request to socketPath via a custom
// http.Transport. We clone the request so we can rewrite the URL without
// mutating the caller's state.
type unixTransport struct {
	socketPath string
}

func (t *unixTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r2 := req.Clone(req.Context())
	r2.URL.Scheme = "http"
	r2.URL.Host = "unix"
	return (&http.Transport{
		DialContext:       (&unixDialer{socketPath: t.socketPath}).DialContext,
		DisableKeepAlives: true,
	}).RoundTrip(r2)
}

// NewUnixHTTPClient returns an *http.Client that dials over a Unix socket.
// timeout applies to the full request/response cycle.
func NewUnixHTTPClient(socketPath string, timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: &unixTransport{socketPath: socketPath},
	}
}
