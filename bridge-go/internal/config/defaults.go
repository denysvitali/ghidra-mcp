// Package config holds bridge-wide constants and defaults that don't change
// at runtime. Anything user-configurable lives in internal/config.Config.
package config

import "time"

// DefaultTCPURL is the Ghidra plugin's loopback TCP endpoint when no env
// override or discovered instance is available.
const DefaultTCPURL = "http://127.0.0.1:8089"

// DefaultTCPPort mirrors DefaultTCPURL's port, used by the TCP port scan.
const DefaultTCPPort = 8089

// TCPPortScanRange is the inclusive number of ports probed when looking for
// the active Ghidra instance via TCP. With DefaultTCPPort=8089 and Range=16,
// we probe 8089..8104.
const TCPPortScanRange = 16

// DefaultDebuggerURL is where the standalone Python debugger server listens.
const DefaultDebuggerURL = "http://127.0.0.1:8099"

// ServerName identifies this MCP server to clients.
const ServerName = "ghidra-mcp"

// ServerVersion is the bridge version string. Bumped manually per release.
const ServerVersion = "5.14.1"

// DefaultGroups is the minimum set of categories the bridge always loads on
// connect: listing, function, program. Mirrors Python's CORE_GROUPS.
var DefaultGroups = []string{"listing", "function", "program"}

// MaxToolNameLength caps sanitized MCP tool names at 64 characters to satisfy
// the Claude/Anthropic tool-name CAPI regex.
const MaxToolNameLength = 64

// RequestTimeout is the default HTTP timeout for upstream Ghidra calls.
const RequestTimeout = 30 * time.Second

// DefaultImportPollInterval is the polling cadence for /analysis_status
// after import_file returns.
const DefaultImportPollInterval = 5 * time.Second

// DefaultImportPollMax is the hard cap on import_file polling iterations.
// 5s * 360 = 30 minutes, matching the Python bridge.
const DefaultImportPollMax = 360

// MaxToolRegistrationFailuresReported is how many per-tool registration
// failures we write to stderr before truncating with "...N more". Mirrors
// the Python behavior at lines 1106-1111.
const MaxToolRegistrationFailuresReported = 8

// MaxStaticToolNames is the safety cap on how many static names we keep in
// the protected set before collision logic kicks in. Generous by design.
const MaxStaticToolNames = 64
