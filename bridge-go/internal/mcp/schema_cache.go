package mcp

import (
	"sync"

	"github.com/xebyte/ghidra-mcp-bridge/internal/schema"
)

// SchemaCache holds the most-recently fetched /mcp/schema payload.
// It's consulted by list_tool_groups, search_tools, load_tool_group, and
// connect_instance, all of which run before any HTTP call.
type SchemaCache struct {
	mu      sync.RWMutex
	defs    []schema.ToolDef
	rawJSON []byte
	loaded  map[string]bool // category -> loaded?
}

// NewSchemaCache constructs an empty cache.
func NewSchemaCache() *SchemaCache {
	return &SchemaCache{loaded: make(map[string]bool)}
}

// Set replaces the cached schema.
func (c *SchemaCache) Set(defs []schema.ToolDef, raw []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.defs = defs
	c.rawJSON = raw
	c.loaded = make(map[string]bool)
}

// ToolDefs returns a snapshot of the cached tool defs.
func (c *SchemaCache) ToolDefs() []schema.ToolDef {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]schema.ToolDef, len(c.defs))
	copy(out, c.defs)
	return out
}

// Raw returns the most recent raw JSON payload.
func (c *SchemaCache) Raw() []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]byte, len(c.rawJSON))
	copy(out, c.rawJSON)
	return out
}

// MarkLoaded records that a category's tools are now registered.
func (c *SchemaCache) MarkLoaded(category string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loaded[category] = true
}

// MarkUnloaded records that a category's tools were unregistered.
func (c *SchemaCache) MarkUnloaded(category string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.loaded, category)
}

// IsLoaded reports whether any tool from category is currently registered.
func (c *SchemaCache) IsLoaded(category string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.loaded[category]
}

// LoadedCategories returns a snapshot of loaded category names.
func (c *SchemaCache) LoadedCategories() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]string, 0, len(c.loaded))
	for k := range c.loaded {
		out = append(out, k)
	}
	return out
}
