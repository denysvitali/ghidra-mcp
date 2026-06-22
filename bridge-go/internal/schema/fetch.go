package schema

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/xebyte/ghidra-mcp-bridge/internal/logx"
)

// Fetcher fetches /mcp/schema from an upstream HTTP client.
type Fetcher struct {
	HTTPDoer
	Logger  logx.Logger
	Timeout time.Duration
}

// HTTPDoer is the minimal interface needed by Fetcher. The dispatcher's
// Client satisfies it.
type HTTPDoer interface {
	Get(ctx context.Context, endpoint string, params map[string]string, timeout time.Duration) (string, int, error)
}

// Fetch retrieves the schema from the upstream endpoint and parses it.
// Returns the parsed []ToolDef plus the raw JSON for debugging.
func (f *Fetcher) Fetch(ctx context.Context, staticNames []string) ([]ToolDef, []byte, error) {
	if f.Timeout <= 0 {
		f.Timeout = 10 * time.Second
	}
	body, status, err := f.HTTPDoer.Get(ctx, "/mcp/schema", nil, f.Timeout)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch /mcp/schema: %w", err)
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("fetch /mcp/schema: status %d", status)
	}

	tools, err := ParseJSON([]byte(body), staticNames)
	if err != nil {
		return nil, []byte(body), err
	}
	if f.Logger != nil {
		f.Logger.Debugf("schema: parsed %d tools", len(tools))
	}
	_ = io.Discard // keep io import alive for future streaming parser
	return tools, []byte(body), nil
}
