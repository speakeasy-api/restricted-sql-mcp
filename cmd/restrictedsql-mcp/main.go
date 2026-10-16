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

	"github.com/speakeasy-api/restricted-sql-mcp/internal/config"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/db"
	chbackend "github.com/speakeasy-api/restricted-sql-mcp/internal/db/clickhouse"
	pgbackend "github.com/speakeasy-api/restricted-sql-mcp/internal/db/postgres"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/dbsec"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/health"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/mcpserver"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/multidb"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/policy"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/sqlguard"
	chguard "github.com/speakeasy-api/restricted-sql-mcp/internal/sqlguard/clickhouse"
	pgguard "github.com/speakeasy-api/restricted-sql-mcp/internal/sqlguard/postgres"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/tunnel"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/txn"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

// shutdownGrace bounds draining HTTP after SIGINT/SIGTERM.
const shutdownGrace = 10 * time.Second

// bootProvisionTimeout bounds the boot-time provisioning attempt; a failure
// is retried by /readyz and by tool calls, never fatal.
const bootProvisionTimeout = 10 * time.Second

// columnRefreshInterval is how often the catalog column snapshots of the
// additional databases of a --databases server are reloaded; the default
// database's snapshot is reloaded by /readyz.
const columnRefreshInterval = 30 * time.Second

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

	if len(cfg.ReadSchemas) > 0 || len(cfg.WriteSchemas) > 0 {
		expandCtx, cancel := context.WithTimeout(ctx, bootProvisionTimeout)
		err := dbsec.ExpandSchemas(expandCtx, cfg.DSN, pol, cfg.ReadSchemas, cfg.WriteSchemas)
		cancel()
		if err != nil {
			return err
		}
		logger.Info("schema wildcards expanded", "read_schemas", cfg.ReadSchemas, "write_schemas", cfg.WriteSchemas,
			"read_tables", len(pol.ReadTables), "write_tables", len(pol.WriteTables))
	}
	backend, guard, err := selectDialect(ctx, cfg, pol, logger)
	if err != nil {
		return err
	}
	defer closeBackend(backend, logger)

	var registry *txn.Registry
	if pol.WritesEnabled {
		if txb, ok := backend.(db.TxBackend); ok {
			registry = txn.New(txb, cfg.TxnIdleTimeout, cfg.TxnMaxLifetime, cfg.MaxOpenTxns, logger)
			go registry.RunReaper(ctx)
			defer registry.Close()
		} else {
			logger.Warn("writes enabled but the backend has no transaction support; write tools will fail", "dialect", pol.Dialect)
		}
	}

	defaultDatabase := ""
	if pol.Dialect == policy.Postgres {
		defaultDatabase = cfg.DefaultDatabase()
	}
	var databases *multidb.Manager
	if cfg.DatabasesRE != nil {
		databases = multidb.New(multidb.Options{
			BootstrapDSN: cfg.DSN,
			Default:      &multidb.Instance{Name: defaultDatabase, Policy: pol, Backend: backend},
			Pattern:      cfg.DatabasesRE,
			Open: func(ctx context.Context, name string) (*multidb.Instance, error) {
				return openDatabase(ctx, cfg, name, logger)
			},
			Txns:   registry,
			Logger: logger,
		})
		defer databases.Close()
		go databases.RunColumnRefresh(ctx, columnRefreshInterval)
		listCtx, cancel := context.WithTimeout(ctx, bootProvisionTimeout)
		served, err := databases.Refresh(listCtx)
		cancel()
		if err != nil {
			logger.Warn("could not list databases at boot; list_databases and tool calls will retry", "error", err.Error())
		} else {
			logger.Info("multi-database mode", "default_database", defaultDatabase, "databases_pattern", cfg.Databases, "served_databases", served)
		}
	}

	server := mcpserver.New(mcpserver.Deps{
		Policy:          pol,
		Guard:           guard,
		Backend:         backend,
		Txns:            registry,
		Logger:          logger,
		Version:         cfg.Version,
		DefaultDatabase: defaultDatabase,
		Databases:       databases,
	})

	logger.Info("restrictedsql-mcp starting",
		"version", cfg.Version,
		"dialect", pol.Dialect,
		"default_schema", pol.DefaultSchema,
		"transport", cfg.Transport,
		"listen", cfg.Listen,
		"tunnel_only", cfg.TunnelOnly,
		"read_tables", refStrings(pol.ReadTables),
		"write_tables", refStrings(pol.WriteTables),
		"writes_enabled", pol.WritesEnabled,
		"max_rows", pol.MaxRows,
		"statement_timeout", pol.StatementTimeout.String(),
		"txn_idle_timeout", cfg.TxnIdleTimeout.String(),
		"txn_max_lifetime", cfg.TxnMaxLifetime.String(),
		"max_open_txns", cfg.MaxOpenTxns,
		"tunnel", cfg.Tunnel,
		"connection_level_security", cfg.ConnectionLevelSecurity,
	)
	if gate, ok := backend.(*dbsec.Gate); ok {
		provCtx, cancel := context.WithTimeout(ctx, bootProvisionTimeout)
		if err := gate.EnsureProvisioned(provCtx); err != nil {
			logger.Warn("connection-level security not provisioned at boot; /readyz and tool calls will retry", "error", err.Error())
		}
		cancel()
	}

	if annotation, ok := backend.(*dbsec.AnnotationGate); ok {
		if err := annotation.Refresh(ctx); err != nil {
			logger.Warn("annotation mode unavailable at boot", "error", err)
		}
		go annotation.Run(ctx, cfg.AnnotationRefreshInterval)
	}

	if cfg.Transport == "stdio" {
		logger.Info("stdio transport selected; /healthz and /readyz are not available")
		if cfg.Tunnel {
			logger.Warn("--tunnel is ignored with the stdio transport; the tunnel proxies to the http listener")
		}
		return server.Run(ctx, &mcp.StdioTransport{})
	}

	var runner *tunnel.Runner
	var gate *tunnel.Gate
	localURL := localMCPURL(cfg.Listen)
	if cfg.TunnelOnly {
		if gate, err = tunnel.NewGate(); err != nil {
			return err
		}
		if localURL, err = gate.LocalMCPURL(localURL); err != nil {
			return err
		}
		logger.Info("tunnel-only mode: /mcp refuses requests that did not come through the in-process tunnel agent")
	}
	if cfg.Tunnel {
		runner, err = tunnel.New(tunnel.Config{
			GatewayURL:     cfg.TunnelGatewayURL,
			APIKey:         cfg.TunnelKey,
			LocalMCPURL:    localURL,
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
	// Stateless (MCP 2026-07-28): no Mcp-Session-Id, nothing held per client
	// between requests. The only cross-request state is an open write
	// transaction, addressed by its transaction_id and bounded by
	// --txn-idle-timeout and --txn-max-lifetime.
	var mcpHandler http.Handler = mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{
		Logger:                       logger,
		Stateless:                    true,
		PropagateRequestCancellation: true,
	})
	if gate != nil {
		mcpHandler = gate.Wrap(mcpHandler)
	}
	mux.Handle("/mcp", mcpHandler)
	mux.HandleFunc("/healthz", checker.Healthz)
	mux.HandleFunc("/readyz", checker.Readyz)

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.Listen, err)
	}
	// --health-listen exposes only the probes, so /mcp can stay on loopback
	// where only the in-process tunnel agent reaches it.
	var healthLn net.Listener
	if cfg.HealthListen != "" {
		if healthLn, err = net.Listen("tcp", cfg.HealthListen); err != nil {
			_ = ln.Close()
			return fmt.Errorf("listen %s: %w", cfg.HealthListen, err)
		}
	}
	newServer := func(h http.Handler) *http.Server {
		return &http.Server{
			Handler:           h,
			ReadHeaderTimeout: 10 * time.Second,
			BaseContext:       func(net.Listener) context.Context { return ctx },
		}
	}
	httpSrv := newServer(mux)
	errCh := make(chan error, 3)
	go func() {
		logger.Info("http listener ready", "addr", ln.Addr().String(), "mcp", "/mcp", "healthz", "/healthz", "readyz", "/readyz")
		if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("http serve: %w", err)
		}
	}()
	var healthSrv *http.Server
	if healthLn != nil {
		healthMux := http.NewServeMux()
		healthMux.HandleFunc("/healthz", checker.Healthz)
		healthMux.HandleFunc("/readyz", checker.Readyz)
		healthSrv = newServer(healthMux)
		go func() {
			logger.Info("health listener ready", "addr", healthLn.Addr().String(), "healthz", "/healthz", "readyz", "/readyz")
			if err := healthSrv.Serve(healthLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("health serve: %w", err)
			}
		}()
	}
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
	if healthSrv != nil {
		if err := healthSrv.Shutdown(shutdownCtx); err != nil {
			logger.Warn("health shutdown incomplete", "error", err.Error())
		}
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

// pgOptions sizes a Postgres backend: maxConns read connections, write
// transactions on top when writes are enabled, and for the default database
// a probe pool of its own.
func pgOptions(cfg *config.Config, maxConns int, probePool bool) []pgbackend.Option {
	opts := []pgbackend.Option{pgbackend.WithMaxConns(maxConns)}
	if cfg.WritesEnabled {
		opts = append(opts, pgbackend.WithMaxOpenTxns(cfg.MaxOpenTxns), pgbackend.WithTxnIdleTimeout(cfg.TxnIdleTimeout))
	}
	if probePool {
		opts = append(opts, pgbackend.WithProbePool())
	}
	return opts
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

// openDatabase opens one additional database of a --databases server: a
// fresh policy with schema wildcards expanded against that database (schemas
// differ between databases), and, with connection-level security, its own
// login roles named from a per-database prefix since roles are cluster-wide.
// Readiness is not gated on it; an error is returned to the tool call that
// asked and the next call retries.
func openDatabase(ctx context.Context, cfg *config.Config, name string, logger *slog.Logger) (*multidb.Instance, error) {
	dsn, err := dbsec.WithDatabase(cfg.DSN, name)
	if err != nil {
		return nil, err
	}
	pol, err := cfg.BuildPolicy()
	if err != nil {
		return nil, err
	}
	if err := dbsec.ExpandSchemas(ctx, dsn, pol, cfg.ReadSchemas, cfg.WriteSchemas); err != nil {
		return nil, err
	}
	logger = logger.With("database", name)
	inst := &multidb.Instance{Name: name, Policy: pol}
	if cfg.ConnectionLevelSecurity {
		prefix := dbsec.DatabaseRolePrefix(cfg.SecurityRolePrefix, name)
		prov := &dbsec.PostgresProvisioner{DSN: dsn, Policy: pol, Prefix: prefix, Logger: logger}
		build := func(ctx context.Context, creds dbsec.Creds) (db.Backend, error) {
			return pgbackend.NewWithWriteDSN(ctx, creds.ReadDSN, creds.WriteDSN, pol, logger, pgOptions(cfg, cfg.DatabasePoolMaxConns, false)...)
		}
		gate := dbsec.NewGate(policy.Postgres, prov, build, logger)
		if err := gate.EnsureProvisioned(ctx); err != nil {
			closeBackend(gate, logger)
			return nil, err
		}
		inst.Backend, inst.Roles = gate, prov.Roles()
	} else {
		backend, err := pgbackend.New(ctx, dsn, pol, logger, pgOptions(cfg, cfg.DatabasePoolMaxConns, false)...)
		if err != nil {
			return nil, err
		}
		inst.Backend = backend
	}
	// The guard resolves column references from the catalog snapshot; an
	// instance without one would fail closed, so a failed load fails the open.
	err = inst.Backend.Ping(ctx)
	if loader, ok := inst.Backend.(db.ColumnLoader); ok && err == nil {
		err = loader.RefreshColumns(ctx)
	}
	if err != nil {
		closeBackend(inst.Backend, logger)
		if len(inst.Roles) > 0 {
			if _, dropErr := dbsec.DropRoles(context.WithoutCancel(ctx), cfg.DSN, inst.Roles); dropErr != nil {
				logger.Warn("dropping roles after a failed open failed", "roles", inst.Roles, "error", dropErr.Error())
			}
		}
		return nil, err
	}
	return inst, nil
}

// selectDialect picks the guard and backend for the configured dialect. With
// connection-level security the backend is a dbsec.Gate that provisions the
// restricted roles first and then opens pools as those roles.
func selectDialect(ctx context.Context, cfg *config.Config, pol *policy.Policy, logger *slog.Logger) (db.Backend, sqlguard.Guard, error) {
	if pol.AnnotationMode() {
		prefix, err := dbsec.AnnotationRolePrefix(cfg.SecurityRolePrefix)
		if err != nil {
			return nil, nil, err
		}
		var source dbsec.AnnotationSource
		var guard sqlguard.Guard
		var build dbsec.AnnotationBuilder
		switch pol.Dialect {
		case policy.Postgres:
			source = &dbsec.PostgresAnnotations{DSN: cfg.DSN, Prefix: prefix, Logger: logger}
			guard = pgguard.NewWithLogger(logger)
			build = func(ctx context.Context, creds dbsec.Creds, p *policy.Policy) (db.Backend, error) {
				return pgbackend.New(ctx, creds.ReadDSN, p, logger, pgOptions(cfg, cfg.PoolMaxConns, true)...)
			}
		case policy.ClickHouse:
			source = &dbsec.ClickHouseAnnotations{DSN: cfg.DSN, Prefix: prefix, Logger: logger}
			guard = chguard.New()
			build = func(ctx context.Context, creds dbsec.Creds, p *policy.Policy) (db.Backend, error) {
				return chbackend.New(ctx, creds.ReadDSN, p, logger)
			}
		default:
			return nil, nil, fmt.Errorf("unsupported annotation dialect")
		}
		return dbsec.NewAnnotationGate(pol, source, build, cfg.AnnotationRefreshTimeout, logger), guard, nil
	}
	switch pol.Dialect {
	case policy.Postgres:
		guard := pgguard.NewWithLogger(logger)
		if cfg.ConnectionLevelSecurity {
			prov := &dbsec.PostgresProvisioner{DSN: cfg.DSN, Policy: pol, Prefix: cfg.SecurityRolePrefix, Logger: logger}
			build := func(ctx context.Context, creds dbsec.Creds) (db.Backend, error) {
				return pgbackend.NewWithWriteDSN(ctx, creds.ReadDSN, creds.WriteDSN, pol, logger, pgOptions(cfg, cfg.PoolMaxConns, true)...)
			}
			return dbsec.NewGate(policy.Postgres, prov, build, logger), guard, nil
		}
		backend, err := pgbackend.New(ctx, cfg.DSN, pol, logger, pgOptions(cfg, cfg.PoolMaxConns, true)...)
		if err != nil {
			return nil, nil, err
		}
		return backend, guard, nil
	case policy.ClickHouse:
		if cfg.ConnectionLevelSecurity {
			prov := &dbsec.ClickHouseProvisioner{DSN: cfg.DSN, Policy: pol, Prefix: cfg.SecurityRolePrefix, Logger: logger}
			build := func(ctx context.Context, creds dbsec.Creds) (db.Backend, error) {
				return chbackend.New(ctx, creds.ReadDSN, pol, logger)
			}
			return dbsec.NewGate(policy.ClickHouse, prov, build, logger), chguard.New(), nil
		}
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
