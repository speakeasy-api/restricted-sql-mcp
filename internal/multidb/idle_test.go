package multidb

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/speakeasy-api/restricted-sql-mcp/internal/db"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/policy"
)

type countingBackend struct{ refreshes, queries int }

func (c *countingBackend) Dialect() policy.Dialect                          { return policy.Postgres }
func (c *countingBackend) Ping(context.Context) error                       { return nil }
func (c *countingBackend) RefreshColumns(context.Context) error             { c.refreshes++; return nil }
func (c *countingBackend) Close() error                                     { return nil }
func (c *countingBackend) ListSchemas(context.Context) ([]db.Schema, error) { return nil, nil }
func (c *countingBackend) TablesExist(context.Context, []policy.TableRef) ([]policy.TableRef, error) {
	return nil, nil
}
func (c *countingBackend) Query(context.Context, string, int) (*db.Result, error) {
	c.queries++
	return &db.Result{}, nil
}
func (c *countingBackend) Explain(context.Context, string, db.ExplainOptions) (json.RawMessage, string, error) {
	return nil, "", nil
}
func (c *countingBackend) ListObjects(context.Context, string, string) ([]db.Object, error) {
	return nil, nil
}
func (c *countingBackend) ObjectDetails(context.Context, policy.TableRef) (*db.ObjectDetails, error) {
	return nil, nil
}

// An idle database is not kept warm by the periodic column refresh (so its
// pool can shed connections), and is refreshed on its next use instead.
func TestIdleDatabaseNotKeptWarm(t *testing.T) {
	ctx := context.Background()
	m := New(Options{Default: &Instance{Name: "app"}})
	now := time.Unix(1_000_000, 0)
	m.now = func() time.Time { return now }
	inner := &countingBackend{}
	inst := &Instance{Name: "app_preview_pr_1", Backend: inner}
	inst.inner = inner
	inst.Backend = m.watch(inst)
	m.instances[inst.Name] = inst

	m.RefreshColumns(ctx)
	if inner.refreshes != 1 {
		t.Fatalf("fresh database not refreshed: %d", inner.refreshes)
	}
	now = now.Add(idleAfter + time.Second)
	m.RefreshColumns(ctx)
	if inner.refreshes != 1 {
		t.Fatalf("idle database kept warm: %d refreshes", inner.refreshes)
	}
	if _, err := inst.Backend.Query(ctx, "SELECT 1", 1); err != nil {
		t.Fatal(err)
	}
	if inner.refreshes != 2 || inner.queries != 1 {
		t.Fatalf("first use after idle: refreshes=%d queries=%d, want 2 and 1", inner.refreshes, inner.queries)
	}
	if _, err := inst.Backend.Query(ctx, "SELECT 1", 1); err != nil || inner.refreshes != 2 {
		t.Fatalf("busy database refreshed per call: %d (%v)", inner.refreshes, err)
	}
	m.RefreshColumns(ctx)
	if inner.refreshes != 3 {
		t.Fatalf("database in use again not refreshed: %d", inner.refreshes)
	}
}
