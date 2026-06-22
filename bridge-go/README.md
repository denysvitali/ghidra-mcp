# ghidra-mcp-bridge

A Go CLI that bridges MCP-compatible AI clients (Claude Code, Claude Desktop, Codex, etc.)
to a running Ghidra instance. Static tools for instance management plus dynamic tools
sourced from the Ghidra plugin's `/mcp/schema` endpoint.

Drop-in replacement for `bridge_mcp_ghidra.py`.

## Build

```bash
make build                # current platform
make cross-compile        # linux/darwin/windows × amd64/arm64
```

Output lands in `dist/ghidra-mcp-bridge[-<os>-<arch>][.exe]`.

## Run

```bash
./dist/ghidra-mcp-bridge --transport stdio   # default; for AI tool integration
./dist/ghidra-mcp-bridge --transport sse --mcp-port 8081
./dist/ghidra-mcp-bridge --transport streamable-http --mcp-port 8081
```

## Configuration

All knobs read via `viper` with prefix `GHIDRA_MCP_`:

| Flag | Env | Default | Notes |
|---|---|---|---|
| `--transport` | `GHIDRA_MCP_TRANSPORT` | `stdio` | `stdio` / `sse` / `streamable-http` |
| `--mcp-host` | `GHIDRA_MCP_MCP_HOST` | `127.0.0.1` | HTTP/SSE bind host |
| `--mcp-port` | `GHIDRA_MCP_MCP_PORT` | _none_ | HTTP/SSE bind port |
| `--lazy` | `GHIDRA_MCP_LAZY` | `false` | Load only default groups on connect |
| `--default-groups` | `GHIDRA_MCP_DEFAULT_GROUPS` | `listing,function,program` | Always loaded |
| `--log-level` | `GHIDRA_MCP_LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error` |
| `--auto-connect` | `GHIDRA_MCP_AUTO_CONNECT` | `true` | Connect to Ghidra at startup |
| `--config` | `GHIDRA_MCP_CONFIG` | _none_ | Optional YAML config file |

Ghidra upstream:
- `GHIDRA_MCP_URL` — explicit TCP override (default `http://127.0.0.1:8089`)
- `GHIDRA_DEBUGGER_URL` — debugger proxy (default `http://127.0.0.1:8099`)

Socket-dir discovery uses `XDG_RUNTIME_DIR`, `TMPDIR`, `USER`/`USERNAME`, `TEMP`/`TMP`.

## Test

```bash
make test         # full suite
make test-unit    # internal/ only
make vet fmt lint
```

## Layout

See the plan file (`~/.claude/plans/rewrite-the-bridge-in-crispy-starlight.md`) for the
full module map. Short version:

- `cmd/ghidra-mcp-bridge/` — cobra entrypoint
- `internal/config` — viper, defaults, per-endpoint timeouts
- `internal/logx` + `internal/logging` — Logger interface + logrus impl
- `internal/style` — lipgloss stderr renderers
- `internal/addr` — address sanitization
- `internal/schema` — `/mcp/schema` fetch + parse + tool-name sanitization
- `internal/discovery` — socket-dir, PID liveness, port scan, connect logic
- `internal/transport` — UDS + TCP HTTP client + envelope/payload helpers
- `internal/dispatcher` — mutex-serialized GET/POST + retry/reconnect/timeout
- `internal/mcp` — mcp-go server, 30 static tools, dynamic per-session registration
- `internal/poll` — `import_file` background polling