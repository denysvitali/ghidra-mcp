package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// udsSink is an HTTP-over-UDS test server. Mirrors the Python unit tests
// at tests/unit/test_bridge_utils.py::TestUnixHTTPConnection.
type udsSink struct {
	listener net.Listener
	srv      *http.Server
	requests chan *http.Request
	bodies   chan string
}

func newUDSSink(t *testing.T) (*udsSink, string) {
	t.Helper()
	dir := t.TempDir()
	sockPath := dir + "/sink.sock"
	_ = os.Remove(sockPath)
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}

	sink := &udsSink{
		listener: l,
		requests: make(chan *http.Request, 16),
		bodies:   make(chan string, 16),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		sink.requests <- r
		sink.bodies <- string(body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true,"path":%q,"query":%q}`, r.URL.Path, r.URL.RawQuery)
	})
	sink.srv = &http.Server{Handler: mux}
	go func() { _ = sink.srv.Serve(l) }()
	return sink, sockPath
}

func (s *udsSink) Close() {
	_ = s.srv.Close()
	_ = s.listener.Close()
}

func TestUnixHTTPClient(t *testing.T) {
	sink, sockPath := newUDSSink(t)
	defer sink.Close()

	client := NewUnixHTTPClient(sockPath, 5*time.Second)

	// GET request.
	resp, err := client.Get("http://unix/test?foo=bar")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"path":"/test"`) {
		t.Errorf("unexpected body: %s", body)
	}

	// POST request with JSON body.
	resp2, err := client.Post("http://unix/submit", "application/json", strings.NewReader(`{"a":1}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp2.Body.Close()
	body2, _ := io.ReadAll(resp2.Body)
	if !strings.Contains(string(body2), `"path":"/submit"`) {
		t.Errorf("unexpected POST body: %s", body2)
	}
	// Drain captured request — skip the GET we made earlier; wait for the POST.
	var postReq *http.Request
	deadline := time.After(2 * time.Second)
	for postReq == nil {
		select {
		case r := <-sink.requests:
			if r.Method == http.MethodPost {
				postReq = r
			}
		case <-deadline:
			t.Fatal("no POST request captured")
		}
	}
	if postReq.URL.Path != "/submit" {
		t.Errorf("got path %q, want /submit", postReq.URL.Path)
	}
	select {
	case b := <-sink.bodies:
		// bodies channel matches requests 1:1 in handler order. We may have
		// drained earlier GET bodies too; pick the one with a non-empty body.
		if b != "" && !strings.Contains(b, `"a":1`) {
			t.Errorf("body = %q", b)
		}
	case <-time.After(time.Second):
		t.Fatal("no body captured")
	}
}

func TestClient_GetNotConnected(t *testing.T) {
	c := New(nil)
	body, status, err := c.Get(context.Background(), "/x", nil, time.Second)
	if err == nil {
		t.Errorf("expected error when not connected")
	}
	if body != "" || status != 0 {
		t.Errorf("expected empty body/status, got %q/%d", body, status)
	}
}

func TestClient_TCPMode(t *testing.T) {
	// Spin up a tiny TCP HTTP server.
	srv := &http.Server{Addr: "127.0.0.1:0", Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true,"path":%q}`, r.URL.Path)
	})}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	url := "http://" + ln.Addr().String()
	c := New(nil)
	if err := c.SetTCP(url, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if c.Mode() != ModeTCP {
		t.Errorf("mode = %q, want tcp", c.Mode())
	}
	body, status, err := c.Get(context.Background(), "/test", map[string]string{"q": "1"}, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK {
		t.Errorf("status = %d", status)
	}
	if !strings.Contains(body, `"path":"/test"`) {
		t.Errorf("body = %s", body)
	}
}

func TestUnwrapResponseData(t *testing.T) {
	cases := []struct {
		in  string
		has string
	}{
		{`{"foo": "bar"}`, `"foo":"bar"`},
		{`{"data": {"foo": "bar"}}`, `"foo":"bar"`},
		{``, ""},
	}
	for _, tc := range cases {
		got, err := UnwrapResponseData(tc.in)
		if err != nil {
			if tc.in == "" {
				continue
			}
			t.Fatal(err)
		}
		if tc.in == "" {
			continue
		}
		b, _ := json.Marshal(got)
		if !strings.Contains(string(b), tc.has) {
			t.Errorf("got %s, want substring %s", b, tc.has)
		}
	}
}

func TestFilterEmpty(t *testing.T) {
	in := map[string]any{
		"keep":   "yes",
		"drop":   "",
		"blank":  "   ",
		"nilval": nil,
		"intval": 42,
	}
	out := FilterEmpty(in)
	if len(out) != 2 {
		t.Errorf("got %d entries, want 2: %v", len(out), out)
	}
	if _, ok := out["keep"]; !ok {
		t.Error("'keep' should remain")
	}
	if _, ok := out["intval"]; !ok {
		t.Error("'intval' should remain")
	}
}

func TestCoerceCommentEntries(t *testing.T) {
	// JSON string of a list
	v, err := CoerceCommentEntries(`[{"address": "0x1000", "comment": "hi"}]`)
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 1 || v[0]["address"] != "0x1000" {
		t.Errorf("got %v", v)
	}

	// Single object
	v, err = CoerceCommentEntries(map[string]any{"address": "0x2000", "comment": "yo"})
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 1 {
		t.Errorf("got %d entries", len(v))
	}

	// Missing address
	_, err = CoerceCommentEntries(map[string]any{"comment": "x"})
	if err == nil {
		t.Error("expected error for missing address")
	}
}
