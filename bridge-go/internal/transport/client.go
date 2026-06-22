package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/xebyte/ghidra-mcp-bridge/internal/logx"
)

// Mode is the active upstream transport. "none" means no connection yet.
type Mode string

const (
	ModeNone Mode = "none"
	ModeUDS  Mode = "uds"
	ModeTCP  Mode = "tcp"
)

// Client is the unified upstream HTTP client. Exactly one of socketPath or
// baseURL is active at a time; switching happens under mu.
type Client struct {
	mu         sync.RWMutex
	mode       Mode
	socketPath string
	baseURL    string
	http       *http.Client
	log        logx.Logger
}

// New constructs a Client with no active transport (ModeNone).
func New(log logx.Logger) *Client {
	if log == nil {
		log = logx.Nop()
	}
	return &Client{log: log, mode: ModeNone}
}

// Mode returns the currently active transport mode.
func (c *Client) Mode() Mode {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.mode
}

// SocketPath returns the active UDS path (empty if not in UDS mode).
func (c *Client) SocketPath() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.socketPath
}

// BaseURL returns the active TCP URL (empty if not in TCP mode).
func (c *Client) BaseURL() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.baseURL
}

// SetUDS switches to UDS mode with the given socket path.
func (c *Client) SetUDS(socketPath string, timeout time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mode = ModeUDS
	c.socketPath = socketPath
	c.baseURL = ""
	c.http = NewUnixHTTPClient(socketPath, timeout)
}

// SetTCP switches to TCP mode with the given base URL.
func (c *Client) SetTCP(baseURL string, timeout time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := validateServerURL(baseURL); err != nil {
		return err
	}
	c.mode = ModeTCP
	c.baseURL = baseURL
	c.socketPath = ""
	c.http = NewTCPHTTPClient(timeout)
	return nil
}

// Reset clears the active transport (ModeNone).
func (c *Client) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mode = ModeNone
	c.socketPath = ""
	c.baseURL = ""
	c.http = nil
}

// Get performs an HTTP GET. The endpoint should start with "/".
// params is encoded into the query string; pass nil for none.
//
// Returns (body, status, error). Caller is responsible for unmarshalling.
func (c *Client) Get(ctx context.Context, endpoint string, params map[string]string, timeout time.Duration) (string, int, error) {
	c.mu.RLock()
	mode, baseURL, httpc := c.mode, c.baseURL, c.http
	c.mu.RUnlock()

	if mode == ModeNone || httpc == nil {
		return "", 0, ErrNotConnected
	}

	u, err := buildURL(mode, baseURL, c.socketPath, endpoint, params)
	if err != nil {
		return "", 0, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Accept", "application/json")

	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
		req = req.WithContext(ctx)
	}

	resp, err := httpc.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", resp.StatusCode, err
	}
	return string(bodyBytes), resp.StatusCode, nil
}

// Post performs an HTTP POST with a JSON body. queryParams are encoded
// into the URL query string.
func (c *Client) Post(ctx context.Context, endpoint string, body any, queryParams map[string]string, timeout time.Duration) (string, int, error) {
	c.mu.RLock()
	mode, baseURL, httpc := c.mode, c.baseURL, c.http
	c.mu.RUnlock()

	if mode == ModeNone || httpc == nil {
		return "", 0, ErrNotConnected
	}

	u, err := buildURL(mode, baseURL, c.socketPath, endpoint, queryParams)
	if err != nil {
		return "", 0, err
	}

	var bodyReader io.Reader
	if body != nil {
		buf, mErr := json.Marshal(body)
		if mErr != nil {
			return "", 0, fmt.Errorf("marshal body: %w", mErr)
		}
		bodyReader = ioReaderFromBytes(buf)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bodyReader)
	if err != nil {
		return "", 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
		req = req.WithContext(ctx)
	}

	resp, err := httpc.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", resp.StatusCode, err
	}
	return string(bodyBytes), resp.StatusCode, nil
}

// buildURL assembles the request URL from mode + endpoint + params.
func buildURL(mode Mode, baseURL, socketPath, endpoint string, params map[string]string) (string, error) {
	if endpoint == "" {
		return "", fmt.Errorf("empty endpoint")
	}
	// Ensure endpoint starts with "/"
	if endpoint[0] != '/' {
		endpoint = "/" + endpoint
	}

	var base string
	switch mode {
	case ModeTCP:
		base = baseURL
	case ModeUDS:
		// http.Transport will rewrite the URL host to "unix" so we can
		// use any non-empty host here.
		base = "http://unix"
	default:
		return "", ErrNotConnected
	}

	u := base + endpoint
	if len(params) > 0 {
		q := url.Values{}
		for k, v := range params {
			q.Set(k, v)
		}
		u += "?" + q.Encode()
	}
	_ = socketPath // referenced only in mode == ModeUDS via the transport
	return u, nil
}

// ErrNotConnected is returned when no transport is active.
type notConnectedError struct{}

func (notConnectedError) Error() string { return "not connected to a Ghidra instance" }

// ErrNotConnected is the sentinel for the disconnected state.
var ErrNotConnected = notConnectedError{}

// ioReaderFromBytes avoids pulling bytes.NewReader into the top-level set.
type bytesReaderCloser struct {
	b []byte
	i int
}

func ioReaderFromBytes(b []byte) io.Reader {
	return &bytesReaderCloser{b: b}
}

func (r *bytesReaderCloser) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}

// validateServerURL duplicates discovery.ValidateServerURL locally to avoid
// an import cycle. Behavior must match — see internal/discovery/connect.go.
func validateServerURL(u string) error {
	// Implementation copied verbatim from discovery.ValidateServerURL.
	// Keep these in sync.
	if u == "" {
		return nil
	}
	host := u
	if i := indexOf(u, "://"); i >= 0 {
		host = u[i+3:]
	}
	if i := indexOf(host, "/"); i >= 0 {
		host = host[:i]
	}
	if i := indexOf(host, ":"); i >= 0 {
		host = host[:i]
	}
	switch host {
	case "127.0.0.1", "localhost", "::1":
		return nil
	}
	return fmt.Errorf("refusing non-local URL %q", u)
}

// indexOf is a tiny helper that avoids the strings import in hot paths.
func indexOf(s, sub string) int {
	return indexOfImpl(s, sub)
}
