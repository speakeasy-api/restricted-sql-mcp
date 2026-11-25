package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/speakeasy-api/restricted-sql-mcp/internal/config"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/db"
	pgbackend "github.com/speakeasy-api/restricted-sql-mcp/internal/db/postgres"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/dbsec"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/mcpserver"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/policy"
	pgguard "github.com/speakeasy-api/restricted-sql-mcp/internal/sqlguard/postgres"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/tunnelidentity"
)

type identityContextKey struct{}

func replicaPasswords(raw string, principals []config.ReplicaPrincipal) (map[string]string, error) {
	var passwords map[string]string
	if err := json.Unmarshal([]byte(raw), &passwords); err != nil {
		return nil, errors.New("RESTRICTED_SQL_PASSWORDS must map database logins to passwords")
	}
	for _, principal := range principals {
		if passwords[principal.DatabaseLogin] == "" {
			return nil, errors.New("replica caller is missing a database password")
		}
	}
	return passwords, nil
}

func runReplica(ctx context.Context, stop context.CancelFunc, cfg *config.Config, pol *policy.Policy, logger *slog.Logger) error {
	if cfg.ReplicaMode == "reconcile" {
		logins := make([]string, 0, len(cfg.ReplicaPrincipals))
		for _, principal := range cfg.ReplicaPrincipals {
			logins = append(logins, principal.DatabaseLogin)
		}
		lsn, err := dbsec.ReconcileReplicaGrants(ctx, cfg.DSN, logins, pol)
		if err == nil {
			logger.Info("replica grants committed", "replay_lsn", lsn)
		}
		return err
	}
	passwords, err := replicaPasswords(cfg.ReplicaPasswords, cfg.ReplicaPrincipals)
	if err != nil {
		return err
	}

	verifyDSN, err := dbsec.RewriteDSN(cfg.DSN, cfg.ReplicaVerifierLogin, cfg.ReplicaVerifierPassword)
	if err != nil {
		return err
	}

	servers := make(map[string]*mcp.Server, len(cfg.ReplicaPrincipals))
	refreshers := make([]*dbsec.AnnotationGate, 0, len(cfg.ReplicaPrincipals))
	dataSlots := make(chan struct{}, cfg.ReplicaMaxConcurrentQueries)
	probeSlots := make(chan struct{}, 1)
	for _, principal := range cfg.ReplicaPrincipals {
		dsn, err := dbsec.RewriteDSN(cfg.DSN, principal.DatabaseLogin, passwords[principal.DatabaseLogin])
		if err != nil {
			return err
		}
		callerLogger := logger.With("subject", principal.Subject(), "database_login", principal.DatabaseLogin)
		source := &dbsec.ReplicaAnnotations{ReadDSN: dsn, Role: principal.DatabaseLogin, ExpectedLSN: cfg.ReplicaReplayLSN, Slots: probeSlots,
			VerifierDSN: verifyDSN, VerifierRole: cfg.ReplicaVerifierLogin}
		build := func(ctx context.Context, creds dbsec.Creds, p *policy.Policy) (db.Backend, error) {
			return pgbackend.New(ctx, creds.ReadDSN, p, callerLogger, pgbackend.WithMaxConns(1),
				pgbackend.WithReplicaCheck(func(ctx context.Context, conn *pgx.Conn) error {
					return source.CheckReplica(ctx, conn)
				}, dataSlots))
		}
		gate := dbsec.NewAnnotationGate(pol, source, build, cfg.AnnotationRefreshTimeout, callerLogger)
		refreshers = append(refreshers, gate)
		defer closeBackend(gate, callerLogger)
		go gate.Run(ctx, cfg.AnnotationRefreshInterval)
		go func() {
			if err := gate.Refresh(ctx); err != nil && ctx.Err() == nil {
				callerLogger.Warn("replica database unavailable at boot", "error", err)
			}
		}()
		server := mcpserver.New(mcpserver.Deps{
			Policy: pol, Guard: pgguard.NewWithLogger(callerLogger), Backend: gate,
			Logger: callerLogger, Version: cfg.Version, DefaultDatabase: cfg.DefaultDatabase(),
			DisableExplain: true,
		})
		server.AddReceivingMiddleware(authorizeTunnelMethods(callerLogger))
		servers[principal.Subject()] = server
	}
	ready := func(context.Context) error {
		for _, gate := range refreshers {
			if !gate.Ready() {
				return errors.New("replica grants are not ready")
			}
		}
		return nil
	}
	verifier := tunnelidentity.New(cfg.ReplicaAudience, cfg.ReplicaOrganization)
	authenticate := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := verifier.Verify(r)
			if err != nil || servers[claims.Subject] == nil {
				http.Error(w, "configured caller identity required", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityContextKey{}, claims)))
		})
	}
	selectServer := func(r *http.Request) *mcp.Server {
		claims, _ := r.Context().Value(identityContextKey{}).(*tunnelidentity.Claims)
		if claims == nil {
			return nil
		}
		return servers[claims.Subject]
	}
	return serveHTTP(ctx, stop, cfg, pol, logger, ready, selectServer, authenticate, nil)
}

func authorizeTunnelMethods(logger *slog.Logger) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			claims, _ := ctx.Value(identityContextKey{}).(*tunnelidentity.Claims)
			if claims == nil || !claims.AllowsMethod(method) {
				return nil, errors.New("caller identity does not allow this method")
			}
			result, err := next(ctx, method, req)
			if method == "tools/call" {
				tool, _ := result.(*mcp.CallToolResult)
				logger.InfoContext(ctx, "restricted SQL tool call", "method", method, "assertion_id", claims.ID,
					"ok", err == nil && tool != nil && !tool.IsError)
			}
			return result, err
		}
	}
}
