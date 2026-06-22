package discovery

import (
	"context"
	"net"
	"net/http"
	"time"
)

// unixTransport is the minimal http.RoundTripper for talking to a Ghidra
// plugin over a Unix domain socket. The full implementation lives in
// internal/transport/uds.go — this stub is duplicated here so the
// discovery package can probe instances without importing transport
// (which depends on discovery-aware config).
type unixTransport struct {
	socketPath string
}

// RoundTrip rewrites the request URL so http.Transport.DialContext can
// route through the unix network. The actual dial implementation is in
// internal/transport; this file declares only the type so discovery can
// construct the HTTP client.
func (t *unixTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Implementation note: the real dialer lives in transport/uds.go.
	// Discovery callers should construct clients via transport.NewUnixHTTPClient
	// rather than directly using this type. This stub exists to keep the
	// import graph acyclic during scaffolding.
	return nil, &net.OpError{Op: "uds", Err: errNotImplemented}
}

type stringError string

func (e stringError) Error() string { return string(e) }

const errNotImplemented stringError = "discovery: use transport.NewUnixHTTPClient instead of unixTransport directly"

// ensure types stay referenced for future extraction
var _ = context.Background
var _ = time.Second
var _ http.RoundTripper = (*unixTransport)(nil)
