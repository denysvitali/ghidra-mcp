package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/xebyte/ghidra-mcp-bridge/internal/addr"
	"github.com/xebyte/ghidra-mcp-bridge/internal/discovery"
	"github.com/xebyte/ghidra-mcp-bridge/internal/schema"
)

// registerStaticTools wires the 30 static tools (instance/group/import +
// 22 debugger proxies) and returns their names. The names are returned
// so the schema parser can avoid collisions when registering dynamic tools.
func (s *Server) registerStaticTools() []string {
	specs := staticToolSpecs()
	for _, sp := range specs {
		s.mcp.AddTool(sp.tool, sp.handler(s))
	}
	return staticToolNames(specs)
}

// staticToolNames returns the registered names from a slice of staticTool.
func staticToolNames(specs []staticTool) []string {
	out := make([]string, len(specs))
	for i, sp := range specs {
		out[i] = sp.tool.Name
	}
	return out
}

// staticTool bundles a Tool with its handler factory.
type staticTool struct {
	tool    mcp.Tool
	handler func(*Server) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error)
}

// staticToolSpecs returns the canonical list of static tools.
//
// Names match the Python bridge's STATIC_TOOL_NAMES exactly so the schema
// parser's collision logic preserves them byte-for-byte.
func staticToolSpecs() []staticTool {
	return []staticTool{
		// Instance + group management.
		listInstancesTool(),
		connectInstanceTool(),
		listToolGroupsTool(),
		loadToolGroupTool(),
		unloadToolGroupTool(),
		checkToolsTool(),
		searchToolsTool(),
		importFileTool(),

		// Debugger proxies (22).
		debuggerAttachTool(),
		debuggerDetachTool(),
		debuggerStatusTool(),
		debuggerModulesTool(),
		debuggerResolveOrdinalTool(),
		debuggerSetBreakpointTool(),
		debuggerRemoveBreakpointTool(),
		debuggerListBreakpointsTool(),
		debuggerContinueTool(),
		debuggerStepIntoTool(),
		debuggerStepOverTool(),
		debuggerRegistersTool(),
		debuggerReadMemoryTool(),
		debuggerStackTraceTool(),
		debuggerReadArgsTool(),
		debuggerTraceFunctionTool(),
		debuggerTraceStopTool(),
		debuggerTraceLogTool(),
		debuggerTraceListTool(),
		debuggerWatchMemoryTool(),
		debuggerWatchStopTool(),
		debuggerWatchLogTool(),
	}
}

// ---- instance + group ----

func listInstancesTool() staticTool {
	return staticTool{
		tool: mcp.NewTool("list_instances",
			mcp.WithDescription("List every running Ghidra instance reachable via UDS or TCP."),
		),
		handler: func(s *Server) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				instances := discovery.DiscoverInstances(ctx, s.log)
				out := make([]map[string]any, 0, len(instances))
				for _, inst := range instances {
					out = append(out, map[string]any{
						"socket":    inst.Socket,
						"pid":       inst.PID,
						"project":   inst.Project,
						"programs":  inst.Programs,
						"discovery": "uds",
						"connected": inst.Socket == s.dispatcher.SocketPath(),
					})
				}
				return textResult(map[string]any{"instances": out, "count": len(out)})
			}
		},
	}
}

func connectInstanceTool() staticTool {
	return staticTool{
		tool: mcp.NewTool("connect_instance",
			mcp.WithDescription("Connect to a Ghidra instance by project name. Auto-discovers over UDS or scans TCP."),
			mcp.WithString("project", mcp.Required(), mcp.Description("Project name (exact or substring).")),
		),
		handler: func(s *Server) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				project, err := req.RequireString("project")
				if err != nil {
					return errResult(err), nil
				}
				target, err := discovery.Resolve(ctx, project, "", s.log)
				if err != nil {
					if nm, ok := err.(*discovery.NoMatchError); ok {
						return textResult(map[string]any{
							"error":     nm.Error(),
							"available": nm.Found,
						})
					}
					return textResult(map[string]any{"error": err.Error()})
				}

				// Apply the target.
				client := s.dispatcher.Client()
				switch target.Mode {
				case "uds":
					client.SetUDS(target.Socket, 0)
				case "tcp":
					if err := client.SetTCP(target.URL, 0); err != nil {
						return textResult(map[string]any{"error": err.Error()})
					}
				}
				s.dispatcher.SetConnectedProject(project)

				// Fetch + cache schema.
				fetcher := &schema.Fetcher{
					HTTPDoer: client,
					Logger:   s.log,
				}
				defs, raw, err := fetcher.Fetch(ctx, s.staticNames)
				if err != nil {
					return textResult(map[string]any{"error": err.Error()})
				}
				s.schemaCache.Set(defs, raw)

				// Eagerly register default groups server-wide so the tools
				// are visible without waiting for a per-session call.
				// (We don't know the session ID yet; the server-wide set
				// acts as a fallback for the first session.)
				_ = s.registerDefaultGroups(ctx)

				loaded := s.schemaCache.LoadedCategories()
				return textResult(map[string]any{
					"connected":        true,
					"transport":        target.Mode,
					"project":          project,
					"socket":           target.Socket,
					"url":              target.URL,
					"pid":              target.PID,
					"tools_registered": s.registeredCount(),
					"tools_total":      len(defs),
					"loaded_groups":    loaded,
					"note":             "Dynamic tools registered. Call list_tool_groups to inspect categories.",
				})
			}
		},
	}
}

func listToolGroupsTool() staticTool {
	return staticTool{
		tool: mcp.NewTool("list_tool_groups",
			mcp.WithDescription("List every tool category with loaded/default flags."),
		),
		handler: func(s *Server) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				defs := s.schemaCache.ToolDefs()
				byCat := make(map[string][]schema.ToolDef)
				for _, d := range defs {
					byCat[d.Category] = append(byCat[d.Category], d)
				}
				loaded := s.schemaCache.LoadedCategories()
				loadedSet := make(map[string]bool, len(loaded))
				for _, c := range loaded {
					loadedSet[c] = true
				}
				defaultSet := make(map[string]bool, len(s.defaultGroups()))
				for _, c := range s.defaultGroups() {
					defaultSet[c] = true
				}

				groups := make([]map[string]any, 0, len(byCat))
				for cat, tools := range byCat {
					names := make([]string, len(tools))
					for i, t := range tools {
						names[i] = t.Name
					}
					groups = append(groups, map[string]any{
						"group":       cat,
						"tool_count":  len(tools),
						"loaded":      loadedSet[cat],
						"default":     defaultSet[cat],
						"description": tools[0].CategoryDesc,
						"tools":       names,
					})
				}
				return textResult(map[string]any{
					"groups":      groups,
					"total_tools": len(defs),
				})
			}
		},
	}
}

func loadToolGroupTool() staticTool {
	return staticTool{
		tool: mcp.NewTool("load_tool_group",
			mcp.WithDescription("Register all tools in a category, or every category if group='all'."),
			mcp.WithString("group", mcp.Required(), mcp.Description("Category name or 'all'.")),
		),
		handler: func(s *Server) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				group, err := req.RequireString("group")
				if err != nil {
					return errResult(err), nil
				}
				added := s.loadGroup(ctx, group)
				if added == nil {
					return textResult(map[string]any{
						"error": "no tools in category '" + group + "' (or schema not yet loaded)",
					})
				}
				return textResult(map[string]any{
					"loaded":         group,
					"new_tools":      len(added),
					"new_tool_names": added,
					"total_loaded":   len(s.schemaCache.LoadedCategories()),
				})
			}
		},
	}
}

func unloadToolGroupTool() staticTool {
	return staticTool{
		tool: mcp.NewTool("unload_tool_group",
			mcp.WithDescription("Unregister all tools in a category. Default groups cannot be unloaded."),
			mcp.WithString("group", mcp.Required(), mcp.Description("Category name.")),
		),
		handler: func(s *Server) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				group, err := req.RequireString("group")
				if err != nil {
					return errResult(err), nil
				}
				for _, d := range s.defaultGroups() {
					if d == group {
						return textResult(map[string]any{
							"error": "cannot unload default group '" + group + "'",
						})
					}
				}
				removed := s.unloadGroup(group)
				return textResult(map[string]any{
					"unloaded":      group,
					"removed_tools": len(removed),
					"total_loaded":  len(s.schemaCache.LoadedCategories()),
				})
			}
		},
	}
}

func checkToolsTool() staticTool {
	return staticTool{
		tool: mcp.NewTool("check_tools",
			mcp.WithDescription("Report per-tool status: callable / not_loaded / not_found."),
			mcp.WithArray("tools", mcp.Required(), mcp.Description("List of tool names to check.")),
		),
		handler: func(s *Server) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				args := req.GetStringSlice("tools", []string{})
				results := make(map[string]any, len(args))
				defs := s.schemaCache.ToolDefs()
				byName := make(map[string]schema.ToolDef, len(defs))
				for _, d := range defs {
					byName[d.Name] = d
				}
				loaded := s.schemaCache.LoadedCategories()
				loadedSet := make(map[string]bool, len(loaded))
				for _, c := range loaded {
					loadedSet[c] = true
				}
				for _, name := range args {
					d, ok := byName[name]
					if !ok {
						results[name] = map[string]any{"status": "not_found"}
						continue
					}
					if loadedSet[d.Category] {
						results[name] = map[string]any{"status": "callable", "group": d.Category}
					} else {
						results[name] = map[string]any{
							"status": "not_loaded",
							"group":  d.Category,
							"fix":    fmt.Sprintf("load_tool_group('%s')", d.Category),
						}
					}
				}
				return textResult(map[string]any{"results": results})
			}
		},
	}
}

func searchToolsTool() staticTool {
	return staticTool{
		tool: mcp.NewTool("search_tools",
			mcp.WithDescription("Substring search across all tool names in the cached schema."),
			mcp.WithString("query", mcp.Required(), mcp.Description("Search query.")),
			mcp.WithNumber("limit", mcp.Description("Max results to return (default 15).")),
		),
		handler: func(s *Server) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				query, err := req.RequireString("query")
				if err != nil {
					return errResult(err), nil
				}
				limit := int(req.GetFloat("limit", 15))
				if limit <= 0 {
					limit = 15
				}
				q := strings.ToLower(query)
				loaded := s.schemaCache.LoadedCategories()
				loadedSet := make(map[string]bool, len(loaded))
				for _, c := range loaded {
					loadedSet[c] = true
				}
				var matches []map[string]any
				for _, d := range s.schemaCache.ToolDefs() {
					if !strings.Contains(strings.ToLower(d.Name), q) &&
						!strings.Contains(strings.ToLower(d.Description), q) {
						continue
					}
					status := "not_loaded"
					if loadedSet[d.Category] {
						status = "callable"
					}
					entry := map[string]any{
						"name":        d.Name,
						"group":       d.Category,
						"status":      status,
						"description": d.Description,
					}
					if status != "callable" {
						entry["fix"] = fmt.Sprintf("load_tool_group('%s')", d.Category)
					}
					matches = append(matches, entry)
					if len(matches) >= limit {
						break
					}
				}
				return textResult(map[string]any{
					"query":       query,
					"match_count": len(matches),
					"matches":     matches,
				})
			}
		},
	}
}

func importFileTool() staticTool {
	return staticTool{
		tool: mcp.NewTool("import_file",
			mcp.WithDescription("Import a binary into Ghidra and (optionally) wait for analysis."),
			mcp.WithString("file_path", mcp.Required(), mcp.Description("Absolute path to the binary to import.")),
			mcp.WithString("project_folder", mcp.Description("Destination folder within the project.")),
			mcp.WithString("language", mcp.Description("Override detected language (e.g. x86:LE:64:default).")),
			mcp.WithString("compiler_spec", mcp.Description("Override compiler spec (e.g. windows-x86_64).")),
			mcp.WithBoolean("auto_analyze", mcp.Description("Auto-analyze after import (default true).")),
		),
		handler: func(s *Server) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				filePath, err := req.RequireString("file_path")
				if err != nil {
					return errResult(err), nil
				}
				body := map[string]any{
					"file_path":      filePath,
					"project_folder": req.GetString("project_folder", "/"),
					"auto_analyze":   req.GetBool("auto_analyze", true),
				}
				if lang, ok := req.GetArguments()["language"].(string); ok && lang != "" {
					body["language"] = lang
				}
				if cs, ok := req.GetArguments()["compiler_spec"].(string); ok && cs != "" {
					body["compiler_spec"] = cs
				}
				res, err := s.dispatcher.Post(ctx, "/import_file", body, nil, 0)
				if err != nil {
					return textResult(map[string]any{"error": err.Error()})
				}
				// Fire-and-forget poll for analysis_status.
				s.pollImportStatusAsync(ctx, filePath)
				return textResult(map[string]any{"result": res.Body, "status": res.Status})
			}
		},
	}
}

// pollImportStatusAsync kicks off a goroutine that polls /analysis_status
// every 5s for up to 30 minutes. Failures are logged but not returned.
func (s *Server) pollImportStatusAsync(ctx context.Context, program string) {
	go func() {
		for i := 0; i < 360; i++ {
			res, err := s.dispatcher.Get(ctx, "/analysis_status", map[string]string{"program": program}, 0)
			if err != nil {
				s.log.Warnf("analysis_status poll: %v", err)
				return
			}
			var info map[string]any
			if jerr := json.Unmarshal([]byte(res.Body), &info); jerr == nil {
				if done, _ := info["analyzing"].(bool); !done {
					s.log.Infof("analysis complete for %s", program)
					return
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}()
}

// ---- debugger proxies ----
//
// Each debugger_* tool calls the standalone Python debugger server at
// GHIDRA_DEBUGGER_URL (default http://127.0.0.1:8099). The bridge merely
// forwards the request and returns the response verbatim.

func debuggerHTTPURL() string {
	if v := os.Getenv("GHIDRA_DEBUGGER_URL"); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "http://127.0.0.1:8099"
}

func debuggerRequest(method, path string, body any, query map[string]string) (string, error) {
	u := debuggerHTTPURL() + path
	if len(query) > 0 {
		q := url.Values{}
		for k, v := range query {
			q.Set(k, v)
		}
		u += "?" + q.Encode()
	}
	req, err := http.NewRequest(method, u, nil)
	if err != nil {
		return "", err
	}
	if body != nil {
		buf, _ := json.Marshal(body)
		req, _ = http.NewRequest(method, u, strings.NewReader(string(buf)))
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, rerr := resp.Body.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if rerr != nil {
			break
		}
	}
	return string(buf), nil
}

// Most debugger tools follow the same shape: take named params, build a
// body, POST it to /debugger/<op>, return the JSON body verbatim.
//
// Handlers below are spelled out for readability and to make the per-tool
// JSON shape obvious to reviewers.

func debuggerAttachTool() staticTool {
	return staticTool{
		tool: mcp.NewTool("debugger_attach",
			mcp.WithDescription("Attach the debugger to a target process."),
			mcp.WithString("target", mcp.Required(), mcp.Description("Process name or PID.")),
		),
		handler: func(*Server) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				target, err := req.RequireString("target")
				if err != nil {
					return errResult(err), nil
				}
				body, derr := debuggerRequest(http.MethodPost, "/debugger/attach", map[string]any{"target": target}, nil)
				if derr != nil {
					return textResult(map[string]any{"error": derr.Error()})
				}
				return textResult(body)
			}
		},
	}
}

func debuggerDetachTool() staticTool {
	return staticTool{
		tool: mcp.NewTool("debugger_detach",
			mcp.WithDescription("Detach from the debugged process (keeps it running)."),
		),
		handler: func(*Server) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				body, err := debuggerRequest(http.MethodPost, "/debugger/detach", nil, nil)
				if err != nil {
					return textResult(map[string]any{"error": err.Error()})
				}
				return textResult(body)
			}
		},
	}
}

func debuggerStatusTool() staticTool {
	return staticTool{
		tool: mcp.NewTool("debugger_status",
			mcp.WithDescription("Get current debugger status (modules, traces, watches)."),
		),
		handler: func(*Server) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				body, err := debuggerRequest(http.MethodGet, "/debugger/status", nil, nil)
				if err != nil {
					return textResult(map[string]any{"error": err.Error()})
				}
				return textResult(body)
			}
		},
	}
}

func debuggerModulesTool() staticTool {
	return staticTool{
		tool: mcp.NewTool("debugger_modules",
			mcp.WithDescription("List loaded modules (DLLs) with runtime + Ghidra bases."),
		),
		handler: func(*Server) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				body, err := debuggerRequest(http.MethodGet, "/debugger/modules", nil, nil)
				if err != nil {
					return textResult(map[string]any{"error": err.Error()})
				}
				return textResult(body)
			}
		},
	}
}

func debuggerResolveOrdinalTool() staticTool {
	return staticTool{
		tool: mcp.NewTool("debugger_resolve_ordinal",
			mcp.WithDescription("Resolve a DLL ordinal to a runtime address."),
			mcp.WithString("dll", mcp.Required(), mcp.Description("DLL name.")),
			mcp.WithNumber("ordinal", mcp.Required(), mcp.Description("Ordinal number.")),
		),
		handler: func(*Server) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				dll, _ := req.RequireString("dll")
				ord := int(req.GetFloat("ordinal", 0))
				body, err := debuggerRequest(http.MethodGet, "/debugger/ordinal", nil, map[string]string{
					"dll":     dll,
					"ordinal": strconv.Itoa(ord),
				})
				if err != nil {
					return textResult(map[string]any{"error": err.Error()})
				}
				return textResult(body)
			}
		},
	}
}

func debuggerSetBreakpointTool() staticTool {
	return staticTool{
		tool: mcp.NewTool("debugger_set_breakpoint",
			mcp.WithDescription("Set a breakpoint at a Ghidra address (auto-translated to runtime)."),
			mcp.WithString("ghidra_address", mcp.Required(), mcp.Description("Ghidra-formatted address.")),
			mcp.WithString("module", mcp.Description("Module name (default = main).")),
			mcp.WithString("bp_type", mcp.Description("Breakpoint type (default: software).")),
			mcp.WithBoolean("oneshot", mcp.Description("One-shot breakpoint (auto-delete after hit).")),
		),
		handler: func(*Server) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				ghidraAddr, _ := req.RequireString("ghidra_address")
				ghidraAddr, _ = addr.Sanitize(ghidraAddr)
				body := map[string]any{
					"ghidra_address": ghidraAddr,
					"module":         req.GetString("module", ""),
					"type":           req.GetString("bp_type", "software"),
					"oneshot":        req.GetBool("oneshot", false),
				}
				out, err := debuggerRequest(http.MethodPost, "/debugger/breakpoint", body, nil)
				if err != nil {
					return textResult(map[string]any{"error": err.Error()})
				}
				return textResult(out)
			}
		},
	}
}

func debuggerRemoveBreakpointTool() staticTool {
	return staticTool{
		tool: mcp.NewTool("debugger_remove_breakpoint",
			mcp.WithDescription("Remove a breakpoint by ID."),
			mcp.WithNumber("bp_id", mcp.Required(), mcp.Description("Breakpoint ID.")),
		),
		handler: func(*Server) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				id := int(req.GetFloat("bp_id", 0))
				out, err := debuggerRequest(http.MethodDelete, "/debugger/breakpoint/"+strconv.Itoa(id), nil, nil)
				if err != nil {
					return textResult(map[string]any{"error": err.Error()})
				}
				return textResult(out)
			}
		},
	}
}

func debuggerListBreakpointsTool() staticTool {
	return staticTool{
		tool: mcp.NewTool("debugger_list_breakpoints",
			mcp.WithDescription("List all active breakpoints."),
		),
		handler: func(*Server) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				out, err := debuggerRequest(http.MethodGet, "/debugger/breakpoints", nil, nil)
				if err != nil {
					return textResult(map[string]any{"error": err.Error()})
				}
				return textResult(out)
			}
		},
	}
}

func debuggerContinueTool() staticTool {
	return staticTool{
		tool: mcp.NewTool("debugger_continue",
			mcp.WithDescription("Resume execution."),
		),
		handler: func(*Server) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				out, err := debuggerRequest(http.MethodPost, "/debugger/go", nil, nil)
				if err != nil {
					return textResult(map[string]any{"error": err.Error()})
				}
				return textResult(out)
			}
		},
	}
}

func debuggerStepIntoTool() staticTool {
	return staticTool{
		tool: mcp.NewTool("debugger_step_into",
			mcp.WithDescription("Step into calls N times."),
			mcp.WithNumber("count", mcp.Description("Number of steps (default 1).")),
		),
		handler: func(*Server) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				count := int(req.GetFloat("count", 1))
				out, err := debuggerRequest(http.MethodPost, "/debugger/step_into", map[string]any{"count": count}, nil)
				if err != nil {
					return textResult(map[string]any{"error": err.Error()})
				}
				return textResult(out)
			}
		},
	}
}

func debuggerStepOverTool() staticTool {
	return staticTool{
		tool: mcp.NewTool("debugger_step_over",
			mcp.WithDescription("Step over calls N times."),
			mcp.WithNumber("count", mcp.Description("Number of steps (default 1).")),
		),
		handler: func(*Server) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				count := int(req.GetFloat("count", 1))
				out, err := debuggerRequest(http.MethodPost, "/debugger/step_over", map[string]any{"count": count}, nil)
				if err != nil {
					return textResult(map[string]any{"error": err.Error()})
				}
				return textResult(out)
			}
		},
	}
}

func debuggerRegistersTool() staticTool {
	return staticTool{
		tool: mcp.NewTool("debugger_registers",
			mcp.WithDescription("Read current CPU registers."),
		),
		handler: func(*Server) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				out, err := debuggerRequest(http.MethodGet, "/debugger/registers", nil, nil)
				if err != nil {
					return textResult(map[string]any{"error": err.Error()})
				}
				return textResult(out)
			}
		},
	}
}

func debuggerReadMemoryTool() staticTool {
	return staticTool{
		tool: mcp.NewTool("debugger_read_memory",
			mcp.WithDescription("Read process memory."),
			mcp.WithString("address", mcp.Required(), mcp.Description("Address (runtime or Ghidra).")),
			mcp.WithNumber("size", mcp.Description("Bytes to read (default 64).")),
			mcp.WithString("address_type", mcp.Description("'runtime' (default) or 'ghidra'.")),
			mcp.WithString("module", mcp.Description("Module name (for ghidra addresses).")),
		),
		handler: func(*Server) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				address, _ := req.RequireString("address")
				size := int(req.GetFloat("size", 64))
				addressType := req.GetString("address_type", "runtime")
				module := req.GetString("module", "")
				out, err := debuggerRequest(http.MethodGet, "/debugger/memory", nil, map[string]string{
					"address":      address,
					"size":         strconv.Itoa(size),
					"address_type": addressType,
					"module":       module,
				})
				if err != nil {
					return textResult(map[string]any{"error": err.Error()})
				}
				return textResult(out)
			}
		},
	}
}

func debuggerStackTraceTool() staticTool {
	return staticTool{
		tool: mcp.NewTool("debugger_stack_trace",
			mcp.WithDescription("Get call stack with Ghidra-mapped return addresses."),
			mcp.WithNumber("depth", mcp.Description("Stack depth (default 20).")),
		),
		handler: func(*Server) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				depth := int(req.GetFloat("depth", 20))
				out, err := debuggerRequest(http.MethodGet, "/debugger/stack", nil, map[string]string{
					"depth": strconv.Itoa(depth),
				})
				if err != nil {
					return textResult(map[string]any{"error": err.Error()})
				}
				return textResult(out)
			}
		},
	}
}

func debuggerReadArgsTool() staticTool {
	return staticTool{
		tool: mcp.NewTool("debugger_read_args",
			mcp.WithDescription("Read args at the breakpoint per calling convention."),
			mcp.WithString("convention", mcp.Description("Calling convention (default __stdcall).")),
			mcp.WithNumber("count", mcp.Description("Number of args (default 4).")),
			mcp.WithString("arg_names", mcp.Description("Comma-separated arg names.")),
		),
		handler: func(*Server) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				convention := req.GetString("convention", "__stdcall")
				count := int(req.GetFloat("count", 4))
				argNames := req.GetString("arg_names", "")
				out, err := debuggerRequest(http.MethodGet, "/debugger/read_args", nil, map[string]string{
					"convention": convention,
					"count":      strconv.Itoa(count),
					"arg_names":  argNames,
				})
				if err != nil {
					return textResult(map[string]any{"error": err.Error()})
				}
				return textResult(out)
			}
		},
	}
}

func debuggerTraceFunctionTool() staticTool {
	return staticTool{
		tool: mcp.NewTool("debugger_trace_function",
			mcp.WithDescription("Start a non-breaking trace at a function entry."),
			mcp.WithString("ghidra_address", mcp.Required(), mcp.Description("Ghidra-formatted address.")),
			mcp.WithString("module", mcp.Description("Module name.")),
			mcp.WithString("convention", mcp.Description("Calling convention.")),
			mcp.WithNumber("arg_count", mcp.Description("Number of args to capture.")),
			mcp.WithString("arg_names", mcp.Description("Comma-separated arg names.")),
			mcp.WithBoolean("capture_return", mcp.Description("Capture return value.")),
			mcp.WithNumber("max_hits", mcp.Description("Stop after N hits (default 1).")),
		),
		handler: func(*Server) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				a, _ := req.RequireString("ghidra_address")
				a, _ = addr.Sanitize(a)
				body := map[string]any{
					"ghidra_address": a,
					"module":         req.GetString("module", ""),
					"convention":     req.GetString("convention", ""),
					"arg_count":      int(req.GetFloat("arg_count", 0)),
					"arg_names":      req.GetString("arg_names", ""),
					"capture_return": req.GetBool("capture_return", false),
					"max_hits":       int(req.GetFloat("max_hits", 1)),
				}
				out, err := debuggerRequest(http.MethodPost, "/debugger/trace/start", body, nil)
				if err != nil {
					return textResult(map[string]any{"error": err.Error()})
				}
				return textResult(out)
			}
		},
	}
}

func debuggerTraceStopTool() staticTool {
	return staticTool{
		tool: mcp.NewTool("debugger_trace_stop",
			mcp.WithDescription("Stop one or all traces."),
			mcp.WithNumber("trace_id", mcp.Description("Trace ID; -1 stops all (default).")),
		),
		handler: func(*Server) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				id := int(req.GetFloat("trace_id", -1))
				out, err := debuggerRequest(http.MethodPost, "/debugger/trace/stop", map[string]any{"trace_id": id}, nil)
				if err != nil {
					return textResult(map[string]any{"error": err.Error()})
				}
				return textResult(out)
			}
		},
	}
}

func debuggerTraceLogTool() staticTool {
	return staticTool{
		tool: mcp.NewTool("debugger_trace_log",
			mcp.WithDescription("Read recent trace log entries."),
			mcp.WithNumber("trace_id", mcp.Description("Trace ID (default -1 = all).")),
			mcp.WithNumber("last_n", mcp.Description("Number of entries to return (default 50).")),
		),
		handler: func(*Server) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				id := int(req.GetFloat("trace_id", -1))
				last := int(req.GetFloat("last_n", 50))
				out, err := debuggerRequest(http.MethodGet, "/debugger/trace/log", nil, map[string]string{
					"trace_id": strconv.Itoa(id),
					"last_n":   strconv.Itoa(last),
				})
				if err != nil {
					return textResult(map[string]any{"error": err.Error()})
				}
				return textResult(out)
			}
		},
	}
}

func debuggerTraceListTool() staticTool {
	return staticTool{
		tool: mcp.NewTool("debugger_trace_list",
			mcp.WithDescription("List active and completed traces."),
		),
		handler: func(*Server) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				out, err := debuggerRequest(http.MethodGet, "/debugger/trace/list", nil, nil)
				if err != nil {
					return textResult(map[string]any{"error": err.Error()})
				}
				return textResult(out)
			}
		},
	}
}

func debuggerWatchMemoryTool() staticTool {
	return staticTool{
		tool: mcp.NewTool("debugger_watch_memory",
			mcp.WithDescription("Set a hardware watchpoint at an address."),
			mcp.WithString("ghidra_address", mcp.Required(), mcp.Description("Ghidra-formatted address.")),
			mcp.WithNumber("size", mcp.Description("Watch size in bytes (default 4).")),
			mcp.WithString("access", mcp.Description("'read', 'write' (default), or 'execute'.")),
			mcp.WithString("module", mcp.Description("Module name.")),
		),
		handler: func(*Server) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				a, _ := req.RequireString("ghidra_address")
				a, _ = addr.Sanitize(a)
				body := map[string]any{
					"ghidra_address": a,
					"size":           int(req.GetFloat("size", 4)),
					"access":         req.GetString("access", "write"),
					"module":         req.GetString("module", ""),
				}
				out, err := debuggerRequest(http.MethodPost, "/debugger/watch/start", body, nil)
				if err != nil {
					return textResult(map[string]any{"error": err.Error()})
				}
				return textResult(out)
			}
		},
	}
}

func debuggerWatchStopTool() staticTool {
	return staticTool{
		tool: mcp.NewTool("debugger_watch_stop",
			mcp.WithDescription("Stop one or all watchpoints."),
			mcp.WithNumber("watch_id", mcp.Description("Watch ID; -1 stops all (default).")),
		),
		handler: func(*Server) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				id := int(req.GetFloat("watch_id", -1))
				out, err := debuggerRequest(http.MethodPost, "/debugger/watch/stop", map[string]any{"watch_id": id}, nil)
				if err != nil {
					return textResult(map[string]any{"error": err.Error()})
				}
				return textResult(out)
			}
		},
	}
}

func debuggerWatchLogTool() staticTool {
	return staticTool{
		tool: mcp.NewTool("debugger_watch_log",
			mcp.WithDescription("Read recent watch log entries."),
			mcp.WithNumber("watch_id", mcp.Description("Watch ID (default -1 = all).")),
			mcp.WithNumber("last_n", mcp.Description("Number of entries to return (default 50).")),
		),
		handler: func(*Server) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				id := int(req.GetFloat("watch_id", -1))
				last := int(req.GetFloat("last_n", 50))
				out, err := debuggerRequest(http.MethodGet, "/debugger/watch/log", nil, map[string]string{
					"watch_id": strconv.Itoa(id),
					"last_n":   strconv.Itoa(last),
				})
				if err != nil {
					return textResult(map[string]any{"error": err.Error()})
				}
				return textResult(out)
			}
		},
	}
}

// ---- helpers ----

// textResult marshals v as JSON and returns an mcp.CallToolResult containing
// the JSON as the Text content. Matches the Python bridge's "return a JSON
// string from every tool handler" behavior.
func textResult(v any) (*mcp.CallToolResult, error) {
	var body string
	switch x := v.(type) {
	case string:
		body = x
	case []byte:
		body = string(x)
	default:
		buf, err := json.Marshal(v)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("marshal: %v", err)), nil
		}
		body = string(buf)
	}
	return mcp.NewToolResultText(body), nil
}

// errResult wraps an error as a tool result with the IsError flag set.
func errResult(err error) *mcp.CallToolResult {
	return mcp.NewToolResultError(err.Error())
}
