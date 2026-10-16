package dbsec

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/speakeasy-api/restricted-sql-mcp/internal/db"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/policy"
)

// Builder opens the real backend on the derived DSNs.
type Builder func(ctx context.Context, creds Creds) (db.Backend, error)

// Gate is a db.Backend (and db.TxBackend) that comes into existence only
// after provisioning succeeds. Every call first ensures provisioning, so a
// failed boot-time attempt is retried by /readyz probes and by tool calls.
type Gate struct {
	dialect policy.Dialect
	prov    Provisioner
	build   Builder
	log     *slog.Logger

	inner  atomic.Pointer[db.Backend]
	sem    chan struct{} // serialises provisioning attempts
	mu     sync.Mutex
	closed bool
}

// NewGate wraps a provisioner and a backend builder.
func NewGate(dialect policy.Dialect, prov Provisioner, build Builder, logger *slog.Logger) *Gate {
	if logger == nil {
		logger = slog.Default()
	}
	return &Gate{
		dialect: dialect,
		prov:    prov,
		build:   build,
		log:     logger.With("component", "dbsec"),
		sem:     make(chan struct{}, 1),
	}
}

// EnsureProvisioned provisions the roles and opens the backend if that has
// not happened yet. Concurrent callers wait for the in-flight attempt; the
// error is a *NotProvisionedError until an attempt succeeds. The health
// checker calls this on every probe.
func (g *Gate) EnsureProvisioned(ctx context.Context) error {
	if g.inner.Load() != nil {
		return nil
	}
	select {
	case g.sem <- struct{}{}:
	case <-ctx.Done():
		return &NotProvisionedError{Err: ctx.Err()}
	}
	defer func() { <-g.sem }()
	if g.inner.Load() != nil {
		return nil
	}
	g.mu.Lock()
	closed := g.closed
	g.mu.Unlock()
	if closed {
		return &NotProvisionedError{Err: errors.New("backend is closed")}
	}

	creds, err := g.prov.Provision(ctx)
	if err != nil {
		g.log.Warn("connection-level security provisioning failed; will retry", "error", err.Error())
		return &NotProvisionedError{Err: err}
	}
	backend, err := g.build(ctx, creds)
	if err != nil {
		g.log.Warn("connection-level security: opening pools on the provisioned roles failed; will retry", "error", err.Error())
		return &NotProvisionedError{Err: err}
	}
	g.inner.Store(&backend)
	g.log.Info("connection-level security active; tool traffic now runs as the provisioned roles")
	return nil
}

func (g *Gate) backend(ctx context.Context) (db.Backend, error) {
	if err := g.EnsureProvisioned(ctx); err != nil {
		return nil, err
	}
	return *g.inner.Load(), nil
}

func (g *Gate) Dialect() policy.Dialect { return g.dialect }

// RefreshColumns forwards to the provisioned backend so /readyz keeps the
// policy's catalog column snapshot fresh when the gate is in front of it.
func (g *Gate) RefreshColumns(ctx context.Context) error {
	b, err := g.backend(ctx)
	if err != nil {
		return err
	}
	if loader, ok := b.(db.ColumnLoader); ok {
		return loader.RefreshColumns(ctx)
	}
	return nil
}

func (g *Gate) Ping(ctx context.Context) error {
	b, err := g.backend(ctx)
	if err != nil {
		return err
	}
	return b.Ping(ctx)
}

func (g *Gate) TablesExist(ctx context.Context, refs []policy.TableRef) ([]policy.TableRef, error) {
	b, err := g.backend(ctx)
	if err != nil {
		return nil, err
	}
	return b.TablesExist(ctx, refs)
}

func (g *Gate) Query(ctx context.Context, canonicalSQL string, maxRows int) (*db.Result, error) {
	b, err := g.backend(ctx)
	if err != nil {
		return nil, err
	}
	return b.Query(ctx, canonicalSQL, maxRows)
}

func (g *Gate) Explain(ctx context.Context, canonicalSQL string, opts db.ExplainOptions) (json.RawMessage, string, error) {
	b, err := g.backend(ctx)
	if err != nil {
		return nil, "", err
	}
	return b.Explain(ctx, canonicalSQL, opts)
}

func (g *Gate) ListSchemas(ctx context.Context) ([]db.Schema, error) {
	b, err := g.backend(ctx)
	if err != nil {
		return nil, err
	}
	return b.ListSchemas(ctx)
}

func (g *Gate) ListObjects(ctx context.Context, schema, objectType string) ([]db.Object, error) {
	b, err := g.backend(ctx)
	if err != nil {
		return nil, err
	}
	return b.ListObjects(ctx, schema, objectType)
}

func (g *Gate) ObjectDetails(ctx context.Context, ref policy.TableRef) (*db.ObjectDetails, error) {
	b, err := g.backend(ctx)
	if err != nil {
		return nil, err
	}
	return b.ObjectDetails(ctx, ref)
}

// Begin delegates to the provisioned backend's write pool.
func (g *Gate) Begin(ctx context.Context) (db.Tx, error) {
	b, err := g.backend(ctx)
	if err != nil {
		return nil, err
	}
	txb, ok := b.(db.TxBackend)
	if !ok {
		return nil, errors.New("backend has no transaction support")
	}
	return txb.Begin(ctx)
}

// Close closes the provisioned backend, if any, and stops further attempts.
func (g *Gate) Close() error {
	g.mu.Lock()
	g.closed = true
	g.mu.Unlock()
	g.sem <- struct{}{}
	defer func() { <-g.sem }()
	if b := g.inner.Load(); b != nil {
		return (*b).Close()
	}
	return nil
}
