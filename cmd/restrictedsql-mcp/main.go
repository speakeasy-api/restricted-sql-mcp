// Command restrictedsql-mcp serves allowlisted SQL access to a Postgres or
// ClickHouse database over MCP.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ThomasRooney/gram-restrictedsql-tunnel-mcp/internal/config"
	"github.com/ThomasRooney/gram-restrictedsql-tunnel-mcp/internal/db"
	chbackend "github.com/ThomasRooney/gram-restrictedsql-tunnel-mcp/internal/db/clickhouse"
	pgbackend "github.com/ThomasRooney/gram-restrictedsql-tunnel-mcp/internal/db/postgres"
	"github.com/ThomasRooney/gram-restrictedsql-tunnel-mcp/internal/health"
	"github.com/ThomasRooney/gram-restrictedsql-tunnel-mcp/internal/mcpserver"
	"github.com/ThomasRooney/gram-restrictedsql-tunnel-mcp/internal/policy"
	"github.com/ThomasRooney/gram-restrictedsql-tunnel-mcp/internal/sqlguard"
	chguard "github.com/ThomasRooney/gram-restrictedsql-tunnel-mcp/internal/sqlguard/clickhouse"
	pgguard "github.com/ThomasRooney/gram-restrictedsql-tunnel-mcp/internal/sqlguard/postgres"
	"github.com/ThomasRooney/gram-restrictedsql-tunnel-mcp/internal/tunnel"
	"github.com/ThomasRooney/gram-restrictedsql-tunnel-mcp/internal/txn"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

// shutdownGrace bounds draining HTTP after SIGINT/SIGTERM.
const shutdownGrace = 10 * time.Second

// backendCloseTimeout bounds closing the pool at shutdown; connections stuck
// on an unresponsive database are abandoned to the exiting process.
const backendCloseTimeout = 2 * time.Second

func main() {
	cfg, err := config.ParseFlags(os.Args[1:], os.Getenv, version)
	if err != nil {
		if errors.Is(err, config.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "restrictedsql-mcp:", err)
		os.Exit(2)
	}
	pol, err := cfg.BuildPolicy()
	if err != nil {
		fmt.Fprintln(os.Stderr, "restrictedsql-mcp:", err)
		os.Exit(2)
	}
	// Logs go to stdout except in stdio mode, where stdout is the protocol.
	var logOut io.Writer = os.Stdout
	if cfg.Transport == "stdio" {
		logOut = os.Stderr
	}
	logger := slog.New(slog.NewJSONHandler(logOut, &slog.HandlerOptions{Level: logLevel(cfg.LogLevel)}))
	if err := run(cfg, pol, logger); err != nil {
		logger.Error("fatal", "error", err.Error())
		os.Exit(1)
	}
}

func run(cfg *config.Config, pol *policy.Policy, logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	backend, guard, err := selectDialect(ctx, cfg, pol, logger)
	if err != nil {
		return err
	}
	defer closeBackend(backend, logger)

	var registry *txn.Registry
	if pol.WritesEnabled {
		if txb, ok := backend.(db.TxBackend); ok {
			registry = txn.New(txb, cfg.TxnIdleTimeout, cfg.MaxOpenTxns, logger)
			go registry.RunReaper(ctx)
			defer registry.Close()
		} else {
			logger.Warn("writes enabled but the backend has no transaction support; write tools will fail", "dialect", pol.Dialect)
		}
	}

	server := mcpserver.New(mcpserver.Deps{
		Policy:  pol,
		Guard:   guard,
		Backend: backend,
		Txns:    registry,
		Logger:  logger,
		Version: cfg.Version,
	})

	logger.Info("restrictedsql-mcp starting",
		"version", cfg.Version,
		"dialect", pol.Dialect,
		"default_schema", pol.DefaultSchema,
		"transport", cfg.Transport,
		"listen", cfg.Listen,
		"read_tables", refStrings(pol.ReadTables),
		"write_tables", refStrings(pol.WriteTables),
		"writes_enabled", pol.WritesEnabled,
		"max_rows", pol.MaxRows,
		"statement_timeout", pol.StatementTimeout.String(),
		"txn_idle_timeout", cfg.TxnIdleTimeout.String(),
		"max_open_txns", cfg.MaxOpenTxns,
		"tunnel", cfg.Tunnel,
	)

	if cfg.Transport == "stdio" {
		logger.Info("stdio transport selected; /healthz and /readyz are not available")
		if cfg.Tunnel {
			logger.Warn("--tunnel is ignored with the stdio transport; the tunnel proxies to the http listener")
		}
		return server.Run(ctx, &mcp.StdioTransport{})
	}

	var runner *tunnel.Runner
	if cfg.Tunnel {
		runner, err = tunnel.New(tunnel.Config{
			GatewayURL:     cfg.TunnelGatewayURL,
			APIKey:         cfg.TunnelKey,
			LocalMCPURL:    localMCPURL(cfg.Listen),
			ServiceVersion: cfg.TunnelServiceVersion,
			Metadata: map[string]string{
				"dialect":     string(pol.Dialect),
				"read_tables": strings.Join(refStrings(pol.ReadTables), ","),
				"write_tools": fmt.Sprint(pol.WritesEnabled),
			},
		}, logger)
		if err != nil {
			return fmt.Errorf("tunnel: %w", err)
		}
	}

	checker := health.New(backend, pol.AllTables(), runner.State, logger)
	mux := http.NewServeMux()
	mux.Handle("/mcp", mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{
		Logger: logger,
	}))
	mux.HandleFunc("/healthz", checker.Healthz)
	mux.HandleFunc("/readyz", checker.Readyz)

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.Listen, err)
	}
	httpSrv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	errCh := make(chan error, 2)
	go func() {
		logger.Info("http listener ready", "addr", ln.Addr().String(), "mcp", "/mcp", "healthz", "/healthz", "readyz", "/readyz")
		if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("http serve: %w", err)
		}
	}()
	if runner != nil {
		go func() {
			if err := runner.Run(ctx); err != nil && ctx.Err() == nil {
				errCh <- fmt.Errorf("tunnel: %w", err)
			}
		}()
	}

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received", "grace", shutdownGrace.String())
	case err := <-errCh:
		logger.Error("component failed; shutting down", "error", err.Error())
	}
	// A second signal must end the process even if shutdown stalls.
	stop()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		logger.Warn("http shutdown incomplete", "error", err.Error())
	}
	logger.Info("http listener stopped")
	return nil
}

// closeBackend closes the pool, giving up after backendCloseTimeout.
func closeBackend(backend db.Backend, logger *slog.Logger) {
	done := make(chan error, 1)
	go func() { done <- backend.Close() }()
	select {
	case err := <-done:
		if err != nil {
			logger.Warn("backend close failed", "error", err.Error())
		}
	case <-time.After(backendCloseTimeout):
		logger.Warn("backend close did not finish in time; exiting anyway", "waited", backendCloseTimeout.String())
	}
}

// localMCPURL is the URL the tunnel agent proxies to. A listener bound to
// an unspecified address (0.0.0.0, ::, or no host) is reached on loopback.
func localMCPURL(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "http://" + listen + "/mcp"
	}
	if host == "" {
		host = "127.0.0.1"
	} else if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/mcp"
}

// selectDialect picks the guard and backend for the configured dialect.
func selectDialect(ctx context.Context, cfg *config.Config, pol *policy.Policy, logger *slog.Logger) (db.Backend, sqlguard.Guard, error) {
	switch pol.Dialect {
	case policy.Postgres:
		backend, err := pgbackend.New(ctx, cfg.DSN, pol, logger, pgbackend.WithMaxOpenTxns(cfg.MaxOpenTxns))
		if err != nil {
			return nil, nil, err
		}
		return backend, pgguard.NewWithLogger(logger), nil
	case policy.ClickHouse:
		backend, err := chbackend.New(ctx, cfg.DSN, pol, logger)
		if err != nil {
			return nil, nil, err
		}
		return backend, chguard.New(), nil
	default:
		return nil, nil, fmt.Errorf("unsupported dialect %q", pol.Dialect)
	}
}

func logLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func refStrings(m map[policy.TableRef]struct{}) []string {
	out := make([]string, 0, len(m))
	for r := range m {
		out = append(out, r.String())
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
