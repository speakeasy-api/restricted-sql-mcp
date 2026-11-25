package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

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
	logins := make([]string, 0, len(cfg.ReplicaPrincipals))
	for _, principal := range cfg.ReplicaPrincipals {
		logins = append(logins, principal.DatabaseLogin)
	}
	if cfg.ReplicaMode == "reconcile" {
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
	probe := &dbsec.ReplicaProbe{
		VerifierDSN: verifyDSN, VerifierRole: cfg.ReplicaVerifierLogin,
		ExpectedLSN: cfg.ReplicaReplayLSN, Roles: logins,
	}
	for _, principal := range cfg.ReplicaPrincipals {
		dsn, err := dbsec.RewriteDSN(cfg.DSN, principal.DatabaseLogin, passwords[principal.DatabaseLogin])
		if err != nil {
			return err
		}
		callerLogger := logger.With("database_login", principal.DatabaseLogin)
		source := &dbsec.ReplicaAnnotations{ReadDSN: dsn, Role: principal.DatabaseLogin, Probe: probe}
		build := func(ctx context.Context, creds dbsec.Creds, p *policy.Policy) (db.Backend, error) {
			return pgbackend.New(ctx, creds.ReadDSN, p, callerLogger, pgbackend.WithMaxConns(1),
				pgbackend.WithReplicaCheck(source.CheckReplica, dataSlots))
		}
		gate := dbsec.NewAnnotationGate(pol, source, build, cfg.AnnotationRefreshTimeout, callerLogger)
		refreshers = append(refreshers, gate)
		defer closeBackend(gate, callerLogger)
		server := mcpserver.New(mcpserver.Deps{
			Policy: pol, Guard: pgguard.NewWithLogger(callerLogger), Backend: gate,
			Logger: callerLogger, Version: cfg.Version, DefaultDatabase: cfg.DefaultDatabase(),
			DisableExplain: true,
		})
		server.AddReceivingMiddleware(authorizeTunnelMethods(callerLogger))
		servers[principal.RoutingKey()] = server
	}
	go refreshReplica(ctx, cfg, pol, probe, refreshers, logger)
	ready := func(context.Context) error {
		for _, gate := range refreshers {
			if !gate.Ready() {
				return errors.New("replica grants are not ready")
			}
		}
		return nil
	}
	verifier := tunnelidentity.New(cfg.ReplicaIssuer, cfg.ReplicaAudience, cfg.ReplicaOrganization, nil)
	selectServer, authenticate := replicaCallerRouting(verifier.Verify, servers)
	return serveHTTP(ctx, stop, cfg, pol, logger, ready, selectServer, authenticate, nil)
}

func refreshReplica(ctx context.Context, cfg *config.Config, pol *policy.Policy, probe *dbsec.ReplicaProbe, gates []*dbsec.AnnotationGate, logger *slog.Logger) {
	ticker := time.NewTicker(cfg.AnnotationRefreshInterval)
	defer ticker.Stop()
	for ctx.Err() == nil {
		probeCtx, cancel := context.WithTimeout(ctx, cfg.AnnotationRefreshTimeout)
		err := probe.Refresh(probeCtx, pol)
		cancel()
		if err != nil && ctx.Err() == nil {
			logger.Warn("replica grant verification failed", "error", err)
		}
		var refreshes sync.WaitGroup
		for _, gate := range gates {
			refreshes.Go(func() {
				if err := gate.Refresh(ctx); err != nil && ctx.Err() == nil {
					logger.Warn("replica caller is unavailable", "error", err)
				}
			})
		}
		refreshes.Wait()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func replicaCallerRouting(verify func(*http.Request) (*tunnelidentity.Claims, error), servers map[string]*mcp.Server) (func(*http.Request) *mcp.Server, func(http.Handler) http.Handler) {
	findServer := func(claims *tunnelidentity.Claims) *mcp.Server {
		if claims == nil || !strings.HasPrefix(claims.Subject, "user:") || claims.Subject == "user:" {
			return nil
		}
		if server := servers[claims.Subject]; server != nil {
			return server
		}
		if email := config.NormalizeReplicaEmail(claims.Email); email != "" {
			return servers["email:"+email]
		}
		return nil
	}
	authenticate := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := verify(r)
			if err != nil || findServer(claims) == nil {
				http.Error(w, "configured caller identity required", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityContextKey{}, claims)))
		})
	}
	selectServer := func(r *http.Request) *mcp.Server {
		claims, _ := r.Context().Value(identityContextKey{}).(*tunnelidentity.Claims)
		return findServer(claims)
	}
	return selectServer, authenticate
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
				logger.InfoContext(ctx, "restricted SQL tool call", "method", method, "subject", claims.Subject, "assertion_id", claims.ID,
					"ok", err == nil && tool != nil && !tool.IsError)
			}
			return result, err
		}
	}
}
