// Package mcp wires the mcp-go MCP server with the Ghidra bridge's tools.
//
// Layering:
//   - server.go: NewMCPServer + capability/hook setup
//   - static.go: 30 static tools (instance/group/import + 22 debugger proxies)
//   - dynamic.go: per-session registration of /mcp/schema-sourced tools
//   - groups.go: lazy mode + default-groups bookkeeping
//   - sessions.go: sessionID ↔ Ghidra instance tracking
package mcp

import (
	"sync"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/xebyte/ghidra-mcp-bridge/internal/config"
	"github.com/xebyte/ghidra-mcp-bridge/internal/dispatcher"
	"github.com/xebyte/ghidra-mcp-bridge/internal/logx"
)

// Server is the bridge's MCP server.
type Server struct {
	mcp        *server.MCPServer
	dispatcher *dispatcher.Dispatcher
	log        logx.Logger

	// Schema cache (in-process). Populated by FetchAndCache after connect.
	schemaCache *SchemaCache

	// Static tool names — protected from dynamic registration collisions.
	staticNames []string

	// Registry of dynamically registered tools (by category).
	registry *dynamicRegistry

	// Default groups (lazy mode setting).
	muDefaultGroups    sync.RWMutex
	defaultGroupsSlice []string
	lazyMode           bool
}

// SetLazyMode toggles lazy / eager tool loading.
func (s *Server) SetLazyMode(lazy bool) {
	s.muDefaultGroups.Lock()
	defer s.muDefaultGroups.Unlock()
	s.lazyMode = lazy
}

// Lazy reports whether lazy mode is on.
func (s *Server) Lazy() bool {
	s.muDefaultGroups.RLock()
	defer s.muDefaultGroups.RUnlock()
	return s.lazyMode
}

// SetDefaultGroups replaces the default group set.
func (s *Server) SetDefaultGroups(groups []string) {
	s.muDefaultGroups.Lock()
	defer s.muDefaultGroups.Unlock()
	s.defaultGroupsSlice = append([]string(nil), groups...)
}

// defaultGroups returns the configured default category set.
func (s *Server) defaultGroups() []string {
	s.muDefaultGroups.RLock()
	defer s.muDefaultGroups.RUnlock()
	return append([]string(nil), s.defaultGroupsSlice...)
}

// Options configures a new Server.
type Options struct {
	Dispatcher *dispatcher.Dispatcher
	Logger     logx.Logger
}

// NewServer constructs a Server with WithToolCapabilities(true) so that
// AddSessionTools/DeleteSessionTools auto-emit notifications/tools/list_changed.
func NewServer(opts Options) *Server {
	log := opts.Logger
	if log == nil {
		log = logx.Nop()
	}

	mcpSrv := server.NewMCPServer(
		config.ServerName,
		config.ServerVersion,
		server.WithToolCapabilities(true),
		server.WithRecovery(),
	)

	s := &Server{
		mcp:                mcpSrv,
		dispatcher:         opts.Dispatcher,
		log:                log,
		schemaCache:        NewSchemaCache(),
		registry:           newDynamicRegistry(),
		defaultGroupsSlice: append([]string(nil), config.DefaultGroups...),
	}
	s.staticNames = s.registerStaticTools()
	return s
}

// MCPServer returns the underlying mcp-go server (for transport setup).
func (s *Server) MCPServer() *server.MCPServer { return s.mcp }

// StaticNames returns the names of every static tool registered at
// startup. Used to seed collision-avoidance in the schema parser.
func (s *Server) StaticNames() []string { return append([]string(nil), s.staticNames...) }

// Dispatcher returns the bridge's dispatcher.
func (s *Server) Dispatcher() *dispatcher.Dispatcher { return s.dispatcher }

// SchemaCache returns the per-bridge schema cache.
func (s *Server) SchemaCache() *SchemaCache { return s.schemaCache }

// mcpTool is a tiny type alias so we can name the helper signatures
// consistently across static.go and dynamic.go.
type mcpTool = mcp.Tool

// serveResult is a helper to keep handler signatures terse.
type serveResult = *mcp.CallToolResult
