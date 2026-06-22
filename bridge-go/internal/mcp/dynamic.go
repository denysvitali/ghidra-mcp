package mcp

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/xebyte/ghidra-mcp-bridge/internal/addr"
	"github.com/xebyte/ghidra-mcp-bridge/internal/schema"
)

// registered tracks the per-bridge dynamic tool set so load/unload can
// report what was actually registered and unregistered. We register
// dynamic tools server-wide (via AddTool) rather than per-session for
// v1, matching the Python bridge's `mcp.tool(...)` calls. Per-session
// isolation is a future refinement.
type dynamicRegistry struct {
	mu sync.RWMutex
	// category -> set of tool names registered
	byCategory map[string]map[string]bool
	// tool name -> category
	nameToCategory map[string]string
}

func newDynamicRegistry() *dynamicRegistry {
	return &dynamicRegistry{
		byCategory:     make(map[string]map[string]bool),
		nameToCategory: make(map[string]string),
	}
}

func (r *dynamicRegistry) record(category, name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.byCategory[category] == nil {
		r.byCategory[category] = make(map[string]bool)
	}
	r.byCategory[category][name] = true
	r.nameToCategory[name] = category
}

func (r *dynamicRegistry) forget(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cat, ok := r.nameToCategory[name]
	if !ok {
		return
	}
	if r.byCategory[cat] != nil {
		delete(r.byCategory[cat], name)
		if len(r.byCategory[cat]) == 0 {
			delete(r.byCategory, cat)
		}
	}
	delete(r.nameToCategory, name)
}

func (r *dynamicRegistry) isRegistered(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.nameToCategory[name]
	return ok
}

func (r *dynamicRegistry) categoryCount(category string) int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byCategory[category])
}

func (r *dynamicRegistry) totalRegistered() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.nameToCategory)
}

func (r *dynamicRegistry) namesInCategory(category string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.byCategory[category]))
	for n := range r.byCategory[category] {
		out = append(out, n)
	}
	return out
}

// registerTool builds an mcp.Tool + handler from a ToolDef and registers
// it server-wide via AddTool. The handler dispatches through the bridge's
// dispatcher.
func (s *Server) registerTool(td schema.ToolDef) error {
	if s.registry.isRegistered(td.Name) {
		return nil
	}
	// Skip static-tool collisions — defense in depth even though the
	// schema parser already avoids them.
	for _, n := range s.staticNames {
		if n == td.Name {
			return nil
		}
	}

	tool := buildMCPTool(td)
	handler := buildHandler(s, td)
	s.mcp.AddTool(tool, handler)
	s.registry.record(td.Category, td.Name)
	return nil
}

// unregisterTool removes a single tool from the MCP server.
func (s *Server) unregisterTool(name string) bool {
	if !s.registry.isRegistered(name) {
		return false
	}
	s.mcp.DeleteTools(name)
	s.registry.forget(name)
	return true
}

// buildMCPTool converts a ToolDef into an mcp.Tool.
func buildMCPTool(td schema.ToolDef) mcp.Tool {
	opts := []mcp.ToolOption{
		mcp.WithDescription(td.Description),
	}
	for _, p := range td.Params {
		propOpts := []mcp.PropertyOption{}
		if p.Description != "" {
			propOpts = append(propOpts, mcp.Description(p.Description))
		}
		if p.Required {
			propOpts = append(propOpts, mcp.Required())
		}
		switch p.Type {
		case "integer":
			opts = append(opts, mcp.WithNumber(p.Name, propOpts...))
		case "boolean":
			opts = append(opts, mcp.WithBoolean(p.Name, propOpts...))
		case "number":
			opts = append(opts, mcp.WithNumber(p.Name, propOpts...))
		case "object":
			opts = append(opts, mcp.WithObject(p.Name, propOpts...))
		case "array":
			opts = append(opts, mcp.WithArray(p.Name, propOpts...))
		default: // string + unknown fall through
			opts = append(opts, mcp.WithString(p.Name, propOpts...))
		}
	}
	return mcp.NewTool(td.Name, opts...)
}

// buildHandler returns the mcp tool handler for a single dynamic tool.
func buildHandler(s *Server, td schema.ToolDef) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Collect arguments.
		args := req.GetArguments()
		body := make(map[string]any, len(args))
		query := make(map[string]string)

		for _, p := range td.Params {
			v, present := args[p.Name]
			if !present || v == nil {
				continue
			}
			// Drop empty strings (Codex workaround, mirrors Python line 1019).
			if str, ok := v.(string); ok && str == "" {
				continue
			}
			// Address sanitization.
			if p.ParamType == "address" {
				if str, ok := v.(string); ok {
					if san, err := addr.Sanitize(str); err == nil {
						v = san
					}
				}
			}
			if p.Source == schema.SourceQuery {
				if str, ok := v.(string); ok {
					query[p.Name] = str
				} else {
					buf, _ := json.Marshal(v)
					query[p.Name] = string(buf)
				}
				continue
			}
			body[p.Name] = v
		}

		var (
			bodyStr string
			err     error
		)
		switch td.HTTPMethod {
		case "POST":
			payloadSize := len(body)
			r, e := s.dispatcher.Post(ctx, td.Endpoint, body, query, payloadSize)
			if r != nil {
				bodyStr = r.Body
			}
			err = e
		default: // GET
			r, e := s.dispatcher.Get(ctx, td.Endpoint, query, 0)
			if r != nil {
				bodyStr = r.Body
			}
			err = e
		}
		if err != nil {
			return textResult(map[string]any{"error": err.Error()})
		}
		return textResult(bodyStr)
	}
}
