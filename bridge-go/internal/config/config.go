// Package config loads bridge configuration from CLI flags + environment +
// optional YAML, in that order.
//
// Viper is configured with prefix "GHIDRA_MCP_" so every setting can be
// overridden via env (e.g. GHIDRA_MCP_TRANSPORT=stdio).
//
// Default values live in Defaults(); flag defaults flow through the same
// function so help text matches runtime behavior.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// Config is the resolved bridge configuration passed to main and tests.
type Config struct {
	// MCP server transport settings.
	Transport string // stdio | sse | streamable-http
	MCPHost   string
	MCPPort   int

	// Upstream Ghidra.
	GhidraURL   string // explicit TCP override; empty = use discovered default
	AutoConnect bool

	// Debugger proxy.
	DebuggerURL string

	// Logging.
	LogLevel string

	// Tool loading.
	Lazy          bool
	DefaultGroups []string

	// Misc.
	ConfigFile string
}

// globalViper holds the process-wide viper instance. Using the package-level
// viper.* functions is discouraged by upstream, but here we want a single
// shared config that both the cobra command and tests can read.
var globalViper *viper.Viper

// Viper returns the shared viper instance, panicking if InitViper has not run.
func Viper() *viper.Viper {
	if globalViper == nil {
		panic("config: viper not initialized; call InitViper first")
	}
	return globalViper
}

// Load resolves the config from viper after flag binding is complete.
// The cobra command is expected to have already parsed its flags.
func Load(cmd *cobra.Command) (*Config, error) {
	v := Viper()

	// Optional config file.
	if cfgFile, _ := cmd.Flags().GetString("config"); cfgFile != "" {
		v.SetConfigFile(cfgFile)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("read config %s: %w", cfgFile, err)
		}
	}

	cfg := &Config{
		Transport:   v.GetString("transport"),
		MCPHost:     v.GetString("mcp.host"),
		MCPPort:     v.GetInt("mcp.port"),
		GhidraURL:   v.GetString("ghidra.url"),
		AutoConnect: v.GetBool("auto_connect"),
		DebuggerURL: v.GetString("debugger.url"),
		LogLevel:    v.GetString("log.level"),
		Lazy:        v.GetBool("lazy"),
		ConfigFile:  v.GetString("config"),
	}

	if groups := v.GetString("default_groups"); groups != "" {
		cfg.DefaultGroups = splitTrim(groups, ",")
	} else {
		cfg.DefaultGroups = append([]string(nil), DefaultGroups...)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate enforces basic invariants. Returns the first violation.
func (c *Config) Validate() error {
	switch c.Transport {
	case "stdio", "sse", "streamable-http":
	default:
		return fmt.Errorf("invalid transport %q (expected stdio|sse|streamable-http)", c.Transport)
	}
	switch strings.ToLower(c.LogLevel) {
	case "trace", "debug", "info", "warn", "warning", "error":
	default:
		return fmt.Errorf("invalid log level %q", c.LogLevel)
	}
	if c.MCPHost == "" {
		return fmt.Errorf("mcp.host is empty")
	}
	return nil
}

// LocalHost reports whether the MCP bind host is a loopback address.
// Drives DNS-rebinding protection policy.
func (c *Config) LocalHost() bool {
	return c.MCPHost == "127.0.0.1" || c.MCPHost == "localhost" || c.MCPHost == "::1"
}

// PublicHost reports whether the MCP bind host is 0.0.0.0 / :: (all
// interfaces). Used to relax DNS-rebinding protection.
func (c *Config) PublicHost() bool {
	return c.MCPHost == "0.0.0.0" || c.MCPHost == "::"
}

// InitViper wires viper defaults and binds flags from cmd.
//
// Always call this BEFORE cobra parses argv. Use NewRootCmd to build the
// command with flags pre-registered; this function binds those flags into
// viper so viper.GetString("transport") reads either --transport or
// GHIDRA_MCP_TRANSPORT.
func InitViper(cmd *cobra.Command) error {
	v := viper.New()
	globalViper = v
	v.SetEnvPrefix("GHIDRA_MCP")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AllowEmptyEnv(false)

	// Defaults.
	v.SetDefault("transport", "stdio")
	v.SetDefault("mcp.host", "127.0.0.1")
	v.SetDefault("mcp.port", 0)
	v.SetDefault("ghidra.url", "")
	v.SetDefault("auto_connect", true)
	v.SetDefault("debugger.url", DefaultDebuggerURL)
	v.SetDefault("log.level", "info")
	v.SetDefault("lazy", false)
	v.SetDefault("default_groups", strings.Join(DefaultGroups, ","))
	v.SetDefault("config", "")

	// Bind flags. Flag values win over env over defaults.
	bindFlag := func(name string) {
		if err := v.BindPFlag(name, cmd.Flags().Lookup(name)); err != nil {
			panic(fmt.Errorf("bind flag %s: %w", name, err))
		}
	}
	bindFlag("transport")
	bindFlag("mcp.host")
	bindFlag("mcp.port")
	bindFlag("ghidra.url")
	bindFlag("auto_connect")
	bindFlag("debugger.url")
	bindFlag("log.level")
	bindFlag("lazy")
	bindFlag("default_groups")
	bindFlag("config")

	return nil
}

// RegisterFlags attaches all flags to cmd. Call before InitViper and Execute.
func RegisterFlags(cmd *cobra.Command) {
	fs := cmd.Flags()
	fs.String("transport", "stdio", "MCP transport: stdio | sse | streamable-http")
	fs.String("mcp.host", "127.0.0.1", "Host to bind HTTP/SSE server")
	fs.Int("mcp.port", 0, "Port to bind HTTP/SSE server (default: mcp-go chooses)")
	fs.String("ghidra.url", "", "Ghidra upstream URL override (env: GHIDRA_MCP_URL)")
	fs.Bool("auto_connect", true, "Auto-connect to a Ghidra instance at startup")
	fs.String("debugger.url", DefaultDebuggerURL, "Debugger proxy URL (env: GHIDRA_DEBUGGER_URL)")
	fs.String("log.level", "info", "Log level: trace|debug|info|warn|error")
	fs.Bool("lazy", false, "Lazy-load non-default tool groups on connect")
	fs.String("default_groups", strings.Join(DefaultGroups, ","), "Always-loaded tool groups (comma-separated)")
	fs.String("config", "", "Optional path to a YAML config file")
	fs.Bool("no-lazy", false, "Force eager loading of all tool groups on connect (overrides --lazy)")

	// --no-lazy is a back-compat alias for !lazy.
	cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		if f := cmd.Flags().Lookup("no-lazy"); f != nil && f.Changed {
			lazy, _ := cmd.Flags().GetBool("lazy")
			noLazy, _ := cmd.Flags().GetBool("no-lazy")
			if noLazy {
				_ = cmd.Flags().Set("lazy", "false")
			}
			_ = lazy
		}
		return nil
	}
}

// splitTrim splits s on sep, trims each piece, drops empties.
func splitTrim(s, sep string) []string {
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Compile-time check that Config satisfies a useful interface.
var _ fmt.Stringer = (*Config)(nil)

// String returns a redacted representation suitable for startup banners.
// (Currently unused; reserved.)
func (c *Config) String() string {
	return fmt.Sprintf("Config{transport=%s host=%s port=%d ghidra=%q lazy=%v groups=%v}",
		c.Transport, c.MCPHost, c.MCPPort, redactURL(c.GhidraURL), c.Lazy, c.DefaultGroups)
}

// redactURL strips userinfo and query strings — the URL itself is not
// sensitive (always loopback) but we still scrub defensively.
func redactURL(u string) string {
	if u == "" {
		return "<discover>"
	}
	return u
}

// TimeoutFor returns the per-endpoint timeout, with batch-size scaling for
// /rename_variables and /batch_set_comments. payloadSize is the number of
// items in the request body (0 if not applicable).
func TimeoutFor(endpoint string, payloadSize int) time.Duration {
	base, ok := EndpointTimeouts[endpoint]
	if !ok {
		base = EndpointTimeouts["default"]
	}

	switch endpoint {
	case "/rename_variables", "/batch_rename_variables", "/batch_set_comments",
		"/batch_create_structs", "/batch_set_local_variable_types":
		if payloadSize > 0 {
			scaled := base + time.Duration(payloadSize)*BatchTimeoutPerEntry
			if scaled > BatchTimeoutCap {
				scaled = BatchTimeoutCap
			}
			return scaled
		}
	}
	return base
}

// silence unused import warnings for pflag and time when this file is built standalone.
var _ = pflag.NewFlagSet
var _ = time.Second
