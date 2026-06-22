// Command ghidra-mcp-bridge is the Go MCP bridge for Ghidra.
//
// It serves MCP over stdio (default), SSE, or streamable HTTP and exposes
// tools sourced from a running Ghidra instance. See the package plan at
// ~/.claude/plans/rewrite-the-bridge-in-crispy-starlight.md for the full
// design.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"

	"github.com/xebyte/ghidra-mcp-bridge/internal/config"
	"github.com/xebyte/ghidra-mcp-bridge/internal/discovery"
	"github.com/xebyte/ghidra-mcp-bridge/internal/dispatcher"
	"github.com/xebyte/ghidra-mcp-bridge/internal/logging"
	bridgeMCP "github.com/xebyte/ghidra-mcp-bridge/internal/mcp"
	"github.com/xebyte/ghidra-mcp-bridge/internal/style"
	"github.com/xebyte/ghidra-mcp-bridge/internal/transport"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "ghidra-mcp-bridge",
		Short:        "MCP bridge to a running Ghidra instance.",
		Long:         "ghidra-mcp-bridge connects any MCP-compatible AI client to Ghidra over stdio, SSE, or streamable HTTP.",
		SilenceUsage: true,
	}
	config.RegisterFlags(cmd)
	cmd.RunE = run
	return cmd
}

func run(cmd *cobra.Command, _ []string) error {
	if err := config.InitViper(cmd); err != nil {
		return err
	}
	cfg, err := config.Load(cmd)
	if err != nil {
		return err
	}

	log := logging.Init(cfg.LogLevel, os.Stderr)
	style.Init(style.IsTTY())

	log.Infof("ghidra-mcp-bridge %s starting (transport=%s)", config.ServerVersion, cfg.Transport)
	style.Banner(fmt.Sprintf(" ghidra-mcp-bridge %s ", config.ServerVersion))
	style.OK(fmt.Sprintf("transport: %s", cfg.Transport))

	// Build the upstream transport client.
	client := transport.New(log)

	// Build the dispatcher (mutex-serialized HTTP).
	d := dispatcher.New(client, log)
	d.SetReconnectFunc(func(ctx context.Context) error {
		return autoReconnect(ctx, cfg, d, log)
	})

	// Build the MCP server with static + dynamic tools.
	srv := bridgeMCP.NewServer(bridgeMCP.Options{Dispatcher: d, Logger: log})
	srv.SetLazyMode(cfg.Lazy)
	srv.SetDefaultGroups(cfg.DefaultGroups)

	// Auto-connect at startup if requested.
	if cfg.AutoConnect {
		if err := autoConnect(context.Background(), cfg, client, srv, log); err != nil {
			log.Warnf("auto-connect: %v", err)
			style.Warn(fmt.Sprintf("auto-connect failed: %v", err))
		} else {
			style.OK("auto-connect succeeded")
		}
	}

	// Wire transport security + serve.
	mcpSrv := srv.MCPServer()
	switch cfg.Transport {
	case "stdio":
		style.OK("serving on stdio")
		return serveStdio(mcpSrv)
	case "sse":
		return serveSSE(mcpSrv, cfg)
	case "streamable-http":
		return serveStreamableHTTP(mcpSrv, cfg)
	}
	return fmt.Errorf("unknown transport %q", cfg.Transport)
}

// autoConnect runs the discovery algorithm and wires the dispatcher to
// the first matching Ghidra instance, then fetches /mcp/schema and
// registers the default tool groups.
func autoConnect(ctx context.Context, cfg *config.Config, client *transport.Client, srv *bridgeMCP.Server, log interface {
	Infof(string, ...any)
	Warnf(string, ...any)
}) error {
	target, err := discovery.Resolve(ctx, "", cfg.GhidraURL, nil)
	if err != nil {
		return err
	}
	switch target.Mode {
	case "uds":
		client.SetUDS(target.Socket, 0)
	case "tcp":
		if err := client.SetTCP(target.URL, 0); err != nil {
			return err
		}
	}
	return nil
}

// autoReconnect re-runs connect for the previously connected project.
// Used by the dispatcher's retry path.
func autoReconnect(ctx context.Context, cfg *config.Config, d *dispatcher.Dispatcher, log interface{ Infof(string, ...any) }) error {
	target, err := discovery.Resolve(ctx, d.ConnectedProject(), cfg.GhidraURL, nil)
	if err != nil {
		return err
	}
	client := d.Client()
	switch target.Mode {
	case "uds":
		client.SetUDS(target.Socket, 0)
	case "tcp":
		return client.SetTCP(target.URL, 0)
	}
	return nil
}

func serveStdio(srv *server.MCPServer) error {
	_, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := server.ServeStdio(srv); err != nil && err != context.Canceled {
		return err
	}
	return nil
}

func serveSSE(srv *server.MCPServer, cfg *config.Config) error {
	addr := fmt.Sprintf("%s:%d", cfg.MCPHost, cfg.MCPPort)
	if cfg.MCPPort == 0 {
		addr = fmt.Sprintf("%s:8081", cfg.MCPHost)
	}
	style.OK(fmt.Sprintf("serving SSE on http://%s/sse", addr))
	sse := server.NewSSEServer(srv, server.WithSSEEndpoint("/sse"))
	httpSrv := &http.Server{Addr: addr, Handler: sse}
	return runHTTPServer(httpSrv)
}

func serveStreamableHTTP(srv *server.MCPServer, cfg *config.Config) error {
	addr := fmt.Sprintf("%s:%d", cfg.MCPHost, cfg.MCPPort)
	if cfg.MCPPort == 0 {
		addr = fmt.Sprintf("%s:8081", cfg.MCPHost)
	}
	style.OK(fmt.Sprintf("serving streamable-http on http://%s/mcp", addr))
	httpSrv := server.NewStreamableHTTPServer(srv, server.WithEndpointPath("/mcp"))
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		if err := httpSrv.Start(addr); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()
	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		return err
	}
}

func runHTTPServer(srv *http.Server) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()
	select {
	case <-ctx.Done():
		return srv.Shutdown(context.Background())
	case err := <-errCh:
		return err
	}
}

// keep strings import alive for future use
var _ = strings.TrimSpace
