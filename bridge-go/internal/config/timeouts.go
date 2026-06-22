package config

import "time"

// EndpointTimeouts mirrors the Python bridge's ENDPOINT_TIMEOUTS map.
//
// Slow operations get longer ceilings; everything else falls through to
// RequestTimeout. Keys are HTTP endpoint paths.
var EndpointTimeouts = map[string]time.Duration{
	"default":                         RequestTimeout,
	"/decompile_function":             45 * time.Second,
	"/decompile":                      45 * time.Second,
	"/get_function_pcode":             45 * time.Second,
	"/get_function_assembly":          45 * time.Second,
	"/run_ghidra_script":              1800 * time.Second,
	"/run_script_inline":              600 * time.Second,
	"/import_file":                    300 * time.Second,
	"/batch_set_comments":             120 * time.Second,
	"/batch_rename_variables":         120 * time.Second,
	"/rename_variables":               120 * time.Second,
	"/batch_create_structs":           120 * time.Second,
	"/batch_set_local_variable_types": 120 * time.Second,
	"/search_functions":               60 * time.Second,
	"/list_strings":                   60 * time.Second,
	"/list_imports":                   60 * time.Second,
	"/list_exports":                   60 * time.Second,
	"/list_classes":                   60 * time.Second,
	"/list_namespaces":                60 * time.Second,
	"/list_methods":                   60 * time.Second,
	"/list_segments":                  60 * time.Second,
	"/list_data":                      60 * time.Second,
	"/list_functions":                 60 * time.Second,
	"/xrefs_to":                       60 * time.Second,
	"/xrefs_from":                     60 * time.Second,
	"/get_call_graph":                 60 * time.Second,
	"/analyze_function_completeness":  60 * time.Second,
}

// BatchTimeoutPerEntry is the per-entry overhead the dispatcher adds when
// the payload is a list — applied to /rename_variables and /batch_set_comments.
const BatchTimeoutPerEntry = 12 * time.Second

// BatchTimeoutCap is the maximum timeout that batch-scaled timeouts are
// clamped to (10 minutes). Matches Python line 643.
const BatchTimeoutCap = 600 * time.Second
