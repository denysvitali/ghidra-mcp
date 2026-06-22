// Package dispatcher serializes all upstream Ghidra HTTP calls through a
// sync.Mutex and implements the retry/reconnect/timeout policies that
// were previously encoded inline in the Python bridge.
//
// The mutex prevents concurrent tool-call responses from interleaving on
// stdio (GH issue #91). Without it, two near-simultaneous MCP tool calls
// could each read part of the other's HTTP body and corrupt JSON-RPC
// framing.
package dispatcher

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/xebyte/ghidra-mcp-bridge/internal/config"
	"github.com/xebyte/ghidra-mcp-bridge/internal/logx"
	"github.com/xebyte/ghidra-mcp-bridge/internal/transport"
)

// Dispatcher is the only entrypoint for outbound HTTP to the Ghidra plugin.
type Dispatcher struct {
	client *transport.Client
	log    logx.Logger

	mu sync.Mutex // _ghidra_lock equivalent

	// reconnectFn is invoked once per call when a connection error occurs.
	// The Python bridge uses _try_reconnect which re-runs the connect
	// algorithm and refetches /mcp/schema. The function returns nil on
	// successful reconnect, or an error if reconnect fails.
	reconnectFn func(ctx context.Context) error

	// connectedProject is the most-recent project we connected to. Used by
	// _try_reconnect to re-resolve the same instance after a drop.
	connectedProject string

	maxRetries int
}

// New constructs a Dispatcher over the given transport client.
func New(client *transport.Client, log logx.Logger) *Dispatcher {
	if log == nil {
		log = logx.Nop()
	}
	return &Dispatcher{
		client:     client,
		log:        log,
		maxRetries: 3,
	}
}

// SetReconnectFunc wires the auto-reconnect hook. Pass nil to disable.
func (d *Dispatcher) SetReconnectFunc(fn func(ctx context.Context) error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.reconnectFn = fn
}

// SetConnectedProject records the most-recent project for reconnect.
func (d *Dispatcher) SetConnectedProject(project string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.connectedProject = project
}

// ConnectedProject returns the recorded project name.
func (d *Dispatcher) ConnectedProject() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.connectedProject
}

// Mode returns the active upstream transport mode.
func (d *Dispatcher) Mode() transport.Mode { return d.client.Mode() }

// SocketPath returns the active UDS path (empty if not UDS).
func (d *Dispatcher) SocketPath() string { return d.client.SocketPath() }

// BaseURL returns the active TCP URL (empty if not TCP).
func (d *Dispatcher) BaseURL() string { return d.client.BaseURL() }

// Client exposes the underlying transport.Client for tests that need to
// set/replace it.
func (d *Dispatcher) Client() *transport.Client { return d.client }

// Result is the normalized response from any dispatch call.
type Result struct {
	Body   string
	Status int
}

// Get performs an HTTP GET with retries on 5xx and ConnectionError.
//
// retry policy (mirrors Python dispatch_get at lines 767-795):
//   - attempt 0: try; on ConnectionError/OSError, try one reconnect; on
//     5xx, retry up to maxRetries with exponential backoff.
//   - attempt 1..maxRetries: retry on any error.
//
// The first ConnectionError triggers a single reconnect attempt; the
// reconnect error itself does not retry.
func (d *Dispatcher) Get(ctx context.Context, endpoint string, params map[string]string, payloadSize int) (*Result, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	timeout := config.TimeoutFor(endpoint, payloadSize)
	var lastErr error
	var lastBody string
	var lastStatus int

	for attempt := 0; attempt < d.maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff: 1s, 2s, 4s, ...
			delay := time.Duration(1<<uint(attempt-1)) * time.Second
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		body, status, err := d.client.Get(ctx, endpoint, params, timeout)
		if err == nil {
			if status >= 500 {
				lastErr = fmt.Errorf("status %d", status)
				lastBody = body
				lastStatus = status
				d.log.Debugf("dispatch_get %s: %d (retry %d)", endpoint, status, attempt+1)
				continue
			}
			return &Result{Body: body, Status: status}, nil
		}

		// Connection error — try one reconnect on attempt 0.
		if errors.Is(err, transport.ErrNotConnected) {
			return nil, &NotConnectedError{Endpoint: endpoint}
		}
		if isConnectionError(err) && attempt == 0 {
			if d.reconnectFn != nil {
				if rcErr := d.reconnectFn(ctx); rcErr == nil {
					d.log.Infof("dispatch_get %s: reconnected after connection drop", endpoint)
					// Don't sleep — retry immediately.
					continue
				} else {
					d.log.Warnf("dispatch_get %s: reconnect failed: %v", endpoint, rcErr)
				}
			}
		}
		lastErr = err
		d.log.Debugf("dispatch_get %s: %v (retry %d)", endpoint, err, attempt+1)
	}

	// Exhausted retries.
	if lastBody != "" {
		return &Result{Body: lastBody, Status: lastStatus}, nil
	}
	return nil, fmt.Errorf("dispatch_get %s after %d retries: %w", endpoint, d.maxRetries, lastErr)
}

// Post performs an HTTP POST without retries on writes (non-idempotent).
//
// Mirrors Python dispatch_post at lines 798-831: only the pre-send
// ConnectionError triggers a single reconnect; once a response is received
// (any status), it surfaces as-is.
func (d *Dispatcher) Post(ctx context.Context, endpoint string, body any, queryParams map[string]string, payloadSize int) (*Result, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	timeout := config.TimeoutFor(endpoint, payloadSize)

	bodyAny, status, err := d.client.Post(ctx, endpoint, body, queryParams, timeout)
	if err == nil {
		return &Result{Body: bodyAny, Status: status}, nil
	}

	if errors.Is(err, transport.ErrNotConnected) {
		return nil, &NotConnectedError{Endpoint: endpoint}
	}

	// Single reconnect on connection error.
	if isConnectionError(err) && d.reconnectFn != nil {
		if rcErr := d.reconnectFn(ctx); rcErr == nil {
			d.log.Infof("dispatch_post %s: reconnected after connection drop", endpoint)
			bodyAny, status, err = d.client.Post(ctx, endpoint, body, queryParams, timeout)
			if err == nil {
				return &Result{Body: bodyAny, Status: status}, nil
			}
		} else {
			d.log.Warnf("dispatch_post %s: reconnect failed: %v", endpoint, rcErr)
		}
	}

	return nil, fmt.Errorf("dispatch_post %s: %w", endpoint, err)
}

// NotConnectedError is returned when no transport is active. The caller
// (a tool handler) should respond with JSON {"error": "...", "hint":
// "call connect_instance"} — see response_helpers.go.
type NotConnectedError struct {
	Endpoint string
}

func (e *NotConnectedError) Error() string {
	return "not connected to a Ghidra instance (call connect_instance first)"
}

// isConnectionError reports whether err looks like a TCP-level failure
// that reconnect can recover from.
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	for _, needle := range []string{
		"connection refused",
		"connection reset",
		"broken pipe",
		"no such file", // UDS socket vanished
		"connect: ",
	} {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}
