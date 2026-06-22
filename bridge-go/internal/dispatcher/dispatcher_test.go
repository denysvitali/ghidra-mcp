package dispatcher

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xebyte/ghidra-mcp-bridge/internal/logx"
	"github.com/xebyte/ghidra-mcp-bridge/internal/transport"
)

func TestGet_RetryOn5xx(t *testing.T) {
	var calls atomic.Int32
	srv := &http.Server{Addr: "127.0.0.1:0", Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n < 3 {
			w.WriteHeader(503)
			fmt.Fprint(w, `{"error":"unavailable"}`)
			return
		}
		fmt.Fprint(w, `{"ok":true}`)
	})}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go srv.Serve(ln)
	defer srv.Close()

	c := transport.New(logx.Nop())
	if err := c.SetTCP("http://"+ln.Addr().String(), 2*time.Second); err != nil {
		t.Fatal(err)
	}
	d := New(c, logx.Nop())

	res, err := d.Get(context.Background(), "/test", nil, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Status != 200 {
		t.Errorf("status = %d", res.Status)
	}
	if calls.Load() != 3 {
		t.Errorf("expected 3 calls (2 retries + 1 success), got %d", calls.Load())
	}
}

func TestGet_NotConnected(t *testing.T) {
	c := transport.New(logx.Nop())
	d := New(c, logx.Nop())

	_, err := d.Get(context.Background(), "/test", nil, 0)
	if err == nil {
		t.Fatal("expected error when not connected")
	}
	var nce *NotConnectedError
	if !errors.As(err, &nce) {
		t.Errorf("expected NotConnectedError, got %T", err)
	}
}

func TestPost_NoRetryOnWrite(t *testing.T) {
	var calls atomic.Int32
	srv := &http.Server{Addr: "127.0.0.1:0", Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(503)
		fmt.Fprint(w, `{"error":"nope"}`)
	})}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go srv.Serve(ln)
	defer srv.Close()

	c := transport.New(logx.Nop())
	if err := c.SetTCP("http://"+ln.Addr().String(), 2*time.Second); err != nil {
		t.Fatal(err)
	}
	d := New(c, logx.Nop())

	res, err := d.Post(context.Background(), "/submit", map[string]any{"a": 1}, nil, 0)
	if err != nil {
		t.Fatalf("expected no error on non-retry 503, got %v", err)
	}
	if res.Status != 503 {
		t.Errorf("status = %d, want 503", res.Status)
	}
	if calls.Load() != 1 {
		t.Errorf("POST should hit server exactly once; got %d", calls.Load())
	}
}

func TestPost_NotConnected(t *testing.T) {
	c := transport.New(logx.Nop())
	d := New(c, logx.Nop())
	_, err := d.Post(context.Background(), "/x", map[string]any{}, nil, 0)
	var nce *NotConnectedError
	if !errors.As(err, &nce) {
		t.Errorf("expected NotConnectedError, got %v", err)
	}
}

func TestMarshalErrorResponse(t *testing.T) {
	json := MarshalErrorResponse(&NotConnectedError{Endpoint: "/x"})
	if json == "" || json[0] != '{' {
		t.Errorf("expected JSON envelope, got %q", json)
	}
}

func TestSetConnectedProject(t *testing.T) {
	c := transport.New(logx.Nop())
	d := New(c, logx.Nop())
	d.SetConnectedProject("proj1")
	if d.ConnectedProject() != "proj1" {
		t.Errorf("got %q", d.ConnectedProject())
	}
}
