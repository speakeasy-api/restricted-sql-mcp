package pgbackend

import (
	"context"
	"testing"
	"time"

	"github.com/speakeasy-api/restricted-sql-mcp/internal/policy"
)

// Pools connect lazily, so sizing is checked without a database; the boot
// ping to an unused port fails fast and is only logged.
func TestPoolSizing(t *testing.T) {
	ctx := context.Background()
	const dsn = "postgres://u:p@127.0.0.1:1/app?connect_timeout=1"
	pol := &policy.Policy{}
	for name, tc := range map[string]struct {
		writeDSN              string
		opts                  []Option
		read, write, probe    int32
		sharedWrite, ownProbe bool
	}{
		"default":        {opts: nil, read: 16, sharedWrite: true},
		"own write pool": {opts: []Option{WithMaxConns(4), WithMaxOpenTxns(8)}, read: 4, write: 8},
		"separate write": {writeDSN: dsn, opts: []Option{WithMaxConns(4), WithMaxOpenTxns(8)}, read: 4, write: 8},
		"probe pool":     {opts: []Option{WithMaxConns(2), WithProbePool()}, read: 2, sharedWrite: true, probe: 1, ownProbe: true},
	} {
		b, err := NewWithWriteDSN(ctx, dsn, tc.writeDSN, pol, nil, tc.opts...)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := b.read.Config().MaxConns; got != tc.read {
			t.Errorf("%s: read MaxConns = %d, want %d", name, got, tc.read)
		}
		if (b.write == b.read) != tc.sharedWrite {
			t.Errorf("%s: shared write pool = %v, want %v", name, b.write == b.read, tc.sharedWrite)
		}
		if !tc.sharedWrite && b.write.Config().MaxConns != tc.write {
			t.Errorf("%s: write MaxConns = %d, want %d", name, b.write.Config().MaxConns, tc.write)
		}
		if (b.probe != b.read) != tc.ownProbe || (tc.ownProbe && b.probe.Config().MaxConns != tc.probe) {
			t.Errorf("%s: probe pool own=%v want %v", name, b.probe != b.read, tc.ownProbe)
		}
		if got := b.read.Config().MaxConnIdleTime; got != maxConnIdleTime {
			t.Errorf("%s: MaxConnIdleTime = %v, want %v", name, got, maxConnIdleTime)
		}
		_ = b.Close()
	}
	if maxConnIdleTime > time.Minute {
		t.Fatalf("idle connections should be shed within a minute, got %v", maxConnIdleTime)
	}
}
