package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"

	"github.com/jackc/pgx/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/speakeasy-api/restricted-sql-mcp/internal/config"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/db"
	pgbackend "github.com/speakeasy-api/restricted-sql-mcp/internal/db/postgres"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/dbsec"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/mcpserver"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/policy"
	pgguard "github.com/speakeasy-api/restricted-sql-mcp/internal/sqlguard/postgres"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/staffidentity"
)

type staffContextKey struct{}

type staffAccount struct {
	Subject  string `json:"subject"`
	Login    string `json:"login"`
	Password string `json:"password"`
}

var staffSubject = regexp.MustCompile(`^user:[a-zA-Z0-9_-]{1,128}$`)

func parseStaffAccounts(raw string) ([]staffAccount, error) {
	var accounts []staffAccount
	if err := json.Unmarshal([]byte(raw), &accounts); err != nil || len(accounts) == 0 || len(accounts) > 5 {
		return nil, errors.New("staff credentials must contain one to five accounts")
	}
	subjects, logins := map[string]bool{}, map[string]bool{}
	for _, account := range accounts {
		if !staffSubject.MatchString(account.Subject) || !config.ValidStaffLogin(account.Login) ||
			account.Password == "" || subjects[account.Subject] || logins[account.Login] {
			return nil, errors.New("invalid or duplicate staff account")
		}
		subjects[account.Subject], logins[account.Login] = true, true
	}
	return accounts, nil
}

func runStaff(ctx context.Context, stop context.CancelFunc, cfg *config.Config, pol *policy.Policy, logger *slog.Logger) error {
	if cfg.StaffMode == "reconcile" {
		lsn, err := dbsec.ReconcileStaffGrants(ctx, cfg.DSN, cfg.StaffLogins, pol)
		if err == nil {
			logger.Info("staff grants committed", "replay_lsn", lsn)
		}
		return err
	}
	accounts, err := parseStaffAccounts(cfg.StaffAccounts)
	if err != nil {
		return err
	}

	verifyDSN, err := dbsec.RewriteDSN(cfg.DSN, config.StaffVerifierRole, cfg.StaffVerifierPassword)
	if err != nil {
		return err
	}

	servers := make(map[string]*mcp.Server, len(accounts))
	refreshers := make([]*dbsec.AnnotationGate, 0, len(accounts))
	dataSlots := make(chan struct{}, 2)
	probeSlots := make(chan struct{}, 1)
	for _, account := range accounts {
		dsn, err := dbsec.RewriteDSN(cfg.DSN, account.Login, account.Password)
		if err != nil {
			return err
		}
		accountLogger := logger.With("subject", account.Subject, "database_login", account.Login)
		source := &dbsec.ReplicaAnnotations{ReadDSN: dsn, Role: account.Login, ExpectedLSN: cfg.StaffReplayLSN, Slots: probeSlots,
			VerifierDSN: verifyDSN, VerifierRole: config.StaffVerifierRole}
		build := func(ctx context.Context, creds dbsec.Creds, p *policy.Policy) (db.Backend, error) {
			return pgbackend.New(ctx, creds.ReadDSN, p, accountLogger, pgbackend.WithMaxConns(1),
				pgbackend.WithStaffReplica(func(ctx context.Context, conn *pgx.Conn) error {
					return source.CheckReplica(ctx, conn)
				}, dataSlots))
		}
		gate := dbsec.NewAnnotationGate(pol, source, build, cfg.AnnotationRefreshTimeout, accountLogger)
		refreshers = append(refreshers, gate)
		defer closeBackend(gate, accountLogger)
		go gate.Run(ctx, cfg.AnnotationRefreshInterval)
		go func() {
			if err := gate.Refresh(ctx); err != nil && ctx.Err() == nil {
				accountLogger.Warn("staff database unavailable at boot", "error", err)
			}
		}()
		server := mcpserver.New(mcpserver.Deps{
			Policy: pol, Guard: pgguard.NewWithLogger(accountLogger), Backend: gate,
			Logger: accountLogger, Version: cfg.Version, DefaultDatabase: cfg.DefaultDatabase(),
			DisableExplain: true,
		})
		server.AddReceivingMiddleware(staffMethods(accountLogger))
		servers[account.Subject] = server
	}
	ready := func(context.Context) error {
		for _, gate := range refreshers {
			if !gate.Ready() {
				return errors.New("staff replica grants are not ready")
			}
		}
		return nil
	}
	verifier := staffidentity.New(cfg.StaffAudience, cfg.StaffOrganization)
	authenticate := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := verifier.Verify(r)
			if err != nil || servers[claims.Subject] == nil {
				http.Error(w, "staff identity required", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), staffContextKey{}, claims)))
		})
	}
	selectServer := func(r *http.Request) *mcp.Server {
		claims, _ := r.Context().Value(staffContextKey{}).(*staffidentity.Claims)
		if claims == nil {
			return nil
		}
		return servers[claims.Subject]
	}
	return serveHTTP(ctx, stop, cfg, pol, logger, ready, selectServer, authenticate, nil)
}

func staffMethods(logger *slog.Logger) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			claims, _ := ctx.Value(staffContextKey{}).(*staffidentity.Claims)
			if claims == nil || !claims.AllowsMethod(method) {
				return nil, errors.New("staff identity does not allow this method")
			}
			result, err := next(ctx, method, req)
			if method == "tools/call" {
				tool, _ := result.(*mcp.CallToolResult)
				logger.InfoContext(ctx, "staff SQL tool call", "method", method, "assertion_id", claims.ID,
					"ok", err == nil && tool != nil && !tool.IsError)
			}
			return result, err
		}
	}
}
