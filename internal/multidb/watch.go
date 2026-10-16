package multidb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/speakeasy-api/restricted-sql-mcp/internal/db"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/policy"
)

// watched reports backend errors to the manager so a dropped database is
// noticed by the call that hits it.
type watched struct {
	m     *Manager
	inst  *Instance
	inner db.Backend
}

func (m *Manager) watch(inst *Instance) db.Backend {
	return &watched{m: m, inst: inst, inner: inst.Backend}
}

// check turns an error that evicted the instance into a clear tool error.
func (w *watched) check(ctx context.Context, err error) error {
	if err != nil && w.m.observe(ctx, w.inst, err) {
		return fmt.Errorf("database %q no longer exists: %w", w.inst.Name, err)
	}
	return err
}

func (w *watched) Dialect() policy.Dialect { return w.inner.Dialect() }

func (w *watched) Ping(ctx context.Context) error { return w.check(ctx, w.inner.Ping(ctx)) }

func (w *watched) TablesExist(ctx context.Context, refs []policy.TableRef) ([]policy.TableRef, error) {
	missing, err := w.inner.TablesExist(ctx, refs)
	return missing, w.check(ctx, err)
}

func (w *watched) Query(ctx context.Context, canonicalSQL string, maxRows int) (*db.Result, error) {
	res, err := w.inner.Query(ctx, canonicalSQL, maxRows)
	return res, w.check(ctx, err)
}

func (w *watched) Explain(ctx context.Context, canonicalSQL string, opts db.ExplainOptions) (json.RawMessage, string, error) {
	planJSON, planText, err := w.inner.Explain(ctx, canonicalSQL, opts)
	return planJSON, planText, w.check(ctx, err)
}

func (w *watched) ListSchemas(ctx context.Context) ([]db.Schema, error) {
	schemas, err := w.inner.ListSchemas(ctx)
	return schemas, w.check(ctx, err)
}

func (w *watched) ListObjects(ctx context.Context, schema, objectType string) ([]db.Object, error) {
	objects, err := w.inner.ListObjects(ctx, schema, objectType)
	return objects, w.check(ctx, err)
}

func (w *watched) ObjectDetails(ctx context.Context, ref policy.TableRef) (*db.ObjectDetails, error) {
	details, err := w.inner.ObjectDetails(ctx, ref)
	return details, w.check(ctx, err)
}

func (w *watched) Close() error { return w.inner.Close() }

// RefreshColumns forwards to the inner backend's column loader, if any.
func (w *watched) RefreshColumns(ctx context.Context) error {
	loader, ok := w.inner.(db.ColumnLoader)
	if !ok {
		return nil
	}
	return w.check(ctx, loader.RefreshColumns(ctx))
}

// Begin opens a transaction on the instance's write pool.
func (w *watched) Begin(ctx context.Context) (db.Tx, error) {
	txb, ok := w.inner.(db.TxBackend)
	if !ok {
		return nil, errors.New("backend has no transaction support")
	}
	tx, err := txb.Begin(ctx)
	if err != nil {
		return nil, w.check(ctx, err)
	}
	return &watchedTx{w: w, inner: tx}, nil
}

// watchedTx reports errors asynchronously: the transaction registry calls it
// while holding the transaction's lock, which eviction also takes.
type watchedTx struct {
	w     *watched
	inner db.Tx
}

func (t *watchedTx) report(err error) {
	if err != nil {
		go t.w.m.observe(context.Background(), t.w.inst, err)
	}
}

func (t *watchedTx) Exec(ctx context.Context, canonicalSQL string, maxRows int) (*db.Result, error) {
	res, err := t.inner.Exec(ctx, canonicalSQL, maxRows)
	t.report(err)
	return res, err
}

func (t *watchedTx) Commit(ctx context.Context) error {
	err := t.inner.Commit(ctx)
	t.report(err)
	return err
}

func (t *watchedTx) Rollback(ctx context.Context) error {
	err := t.inner.Rollback(ctx)
	t.report(err)
	return err
}
