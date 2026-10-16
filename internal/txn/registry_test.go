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
	r := New(a, time.Minute, time.Hour, 3, nil)
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

func TestRegistryMaxLifetime(t *testing.T) {
	ctx := context.Background()
	b := &fakeBackend{}
	r := New(b, 2*time.Minute, 5*time.Minute, 3, nil)
	now := time.Unix(1_000_000, 0)
	r.now = func() time.Time { return now }

	id, expires, err := r.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if want := now.Add(2 * time.Minute); !expires.Equal(want) {
		t.Fatalf("expires = %v, want idle deadline %v", expires, want)
	}
	// Keep the transaction busy: each call is inside the idle window, but the
	// absolute lifetime still ends it.
	for i := 0; i < 4; i++ {
		now = now.Add(time.Minute)
		if _, err := r.Exec(ctx, id, "SELECT 1", 1); err != nil {
			t.Fatalf("exec at +%dm: %v", i+1, err)
		}
	}
	now = now.Add(90 * time.Second) // 5m30s after begin, 90s idle
	if _, err := r.Exec(ctx, id, "SELECT 1", 1); !errors.Is(err, ErrUnknown) {
		t.Fatalf("exec past max lifetime: %v", err)
	}
	if !b.txs[0].rolledBack || r.Open() != 0 {
		t.Fatalf("expired transaction not rolled back (open %d)", r.Open())
	}

	// The reaper enforces the lifetime too, even for a recently used one.
	id, _, err = r.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range []time.Duration{time.Minute, time.Minute, time.Minute, time.Minute, 50 * time.Second} {
		now = now.Add(step)
		if _, err := r.Exec(ctx, id, "SELECT 1", 1); err != nil {
			t.Fatal(err)
		}
	}
	now = now.Add(20 * time.Second)
	r.reap()
	if !b.txs[1].rolledBack || r.Open() != 0 {
		t.Fatalf("reaper kept a transaction past its max lifetime (open %d)", r.Open())
	}

	// Near the end of its life, the deadline reported is the absolute one.
	if _, _, err = r.Begin(ctx); err != nil {
		t.Fatal(err)
	}
	r2 := New(b, 2*time.Minute, time.Minute, 3, nil)
	r2.now = func() time.Time { return now }
	if _, expires, err = r2.Begin(ctx); err != nil || !expires.Equal(now.Add(time.Minute)) {
		t.Fatalf("expires = %v (%v), want max lifetime %v", expires, err, now.Add(time.Minute))
	}
}
