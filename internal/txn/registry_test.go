package txn

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/speakeasy-api/restricted-sql-mcp/internal/db"
)

type fakeTx struct{ rolledBack bool }

func (f *fakeTx) Exec(context.Context, string, int) (*db.Result, error) { return &db.Result{}, nil }
func (f *fakeTx) Commit(context.Context) error                          { return nil }
func (f *fakeTx) Rollback(context.Context) error                        { f.rolledBack = true; return nil }

type fakeBackend struct{ txs []*fakeTx }

func (f *fakeBackend) Begin(context.Context) (db.Tx, error) {
	tx := &fakeTx{}
	f.txs = append(f.txs, tx)
	return tx, nil
}

func TestRegistryDatabases(t *testing.T) {
	ctx := context.Background()
	a, b := &fakeBackend{}, &fakeBackend{}
	r := New(a, time.Minute, 3, nil)
	idA, _, err := r.BeginOn(ctx, a, "a")
	if err != nil {
		t.Fatal(err)
	}
	idB, _, err := r.BeginOn(ctx, b, "b")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Begin(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.BeginOn(ctx, b, "b"); !errors.Is(err, ErrTooMany) {
		t.Fatalf("cap is not shared across databases: %v", err)
	}
	if got, err := r.Database(idA); err != nil || got != "a" {
		t.Fatalf("Database(a) = %q, %v", got, err)
	}
	if n := r.CloseDatabase("b"); n != 1 || !b.txs[0].rolledBack || a.txs[0].rolledBack {
		t.Fatalf("CloseDatabase(b) closed %d", n)
	}
	if _, err := r.Database(idB); !errors.Is(err, ErrUnknown) {
		t.Fatalf("closed transaction still known: %v", err)
	}
	if _, err := r.Exec(ctx, idB, "SELECT 1", 1); !errors.Is(err, ErrUnknown) {
		t.Fatalf("closed transaction still usable: %v", err)
	}
	if r.Open() != 2 {
		t.Fatalf("open = %d", r.Open())
	}
}
