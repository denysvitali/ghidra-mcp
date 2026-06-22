package mcp

import (
	"context"
	"fmt"
)

// registerDefaultGroups registers all tools whose category is in the
// default-group set. Called from connect_instance after the schema cache
// is populated. Returns the names of newly-registered tools.
func (s *Server) registerDefaultGroups(ctx context.Context) []string {
	return s.loadGroups(s.defaultGroups())
}

// loadGroups registers every cached tool whose category is in groups.
// If groups contains "all", every category is loaded. Already-loaded
// categories are skipped.
func (s *Server) loadGroups(groups []string) []string {
	var added []string
	cache := s.schemaCache.ToolDefs()
	loaded := s.registry.nameToCategory

	wantAll := false
	for _, g := range groups {
		if g == "all" {
			wantAll = true
			break
		}
	}

	for _, td := range cache {
		// Skip if already registered.
		if _, ok := loaded[td.Name]; ok {
			continue
		}
		if !wantAll && !containsString(groups, td.Category) {
			continue
		}
		if err := s.registerTool(td); err == nil {
			added = append(added, td.Name)
		}
	}
	for _, g := range groups {
		s.schemaCache.MarkLoaded(g)
	}
	return added
}

// loadGroup registers all tools for a single category (or "all").
// Returns the names of newly-registered tools, or nil if nothing matched.
func (s *Server) loadGroup(ctx context.Context, group string) []string {
	if group == "" {
		return nil
	}
	if group == "all" {
		return s.loadGroups([]string{"all"})
	}
	// Verify category exists.
	exists := false
	for _, td := range s.schemaCache.ToolDefs() {
		if td.Category == group {
			exists = true
			break
		}
	}
	if !exists {
		return nil
	}
	return s.loadGroups([]string{group})
}

// unloadGroup unregisters every tool in a category. Returns the names
// removed. Default groups cannot be unloaded (caller should check).
func (s *Server) unloadGroup(group string) []string {
	var removed []string
	for _, name := range s.registry.namesInCategory(group) {
		if s.unregisterTool(name) {
			removed = append(removed, name)
		}
	}
	s.schemaCache.MarkUnloaded(group)
	return removed
}

// registeredCount returns the total number of dynamic tools currently
// registered.
func (s *Server) registeredCount() int {
	return s.registry.totalRegistered()
}

// containsString is a tiny local helper to avoid importing slices just for
// one call site.
func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// connectAndCache fetches /mcp/schema and registers the configured default
// groups. Returns the count of tools registered.
//
// Used as the auto-connect hook for the dispatcher reconnect path.
func (s *Server) connectAndCache(ctx context.Context) error {
	defs := s.schemaCache.ToolDefs()
	if len(defs) == 0 {
		return fmt.Errorf("schema cache empty")
	}
	s.registerDefaultGroups(ctx)
	return nil
}
