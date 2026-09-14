package pgbackend

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ThomasRooney/gram-restrictedsql-tunnel-mcp/internal/db"
)

// tx is one write transaction pinned to a dedicated pooled connection.
type tx struct {
	b    *Backend
	conn *pgxpool.Conn
	log  *slog.Logger

	mu   sync.Mutex
	done bool
}

// Begin acquires a dedicated connection, opens a transaction and applies the
// session protections. The connection is released by Commit or Rollback.
func (b *Backend) Begin(ctx context.Context) (db.Tx, error) {
	conn, err := b.pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire connection: %w", err)
	}
	if _, err := conn.Exec(ctx, "BEGIN"); err != nil {
		conn.Release()
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	t := &tx{b: b, conn: conn, log: b.log.With("tx_conn", fmt.Sprintf("%p", conn))}
	if err := applySessionSettings(ctx, conn, b.pol); err != nil {
		t.finish(ctx, "ROLLBACK")
		return nil, err
	}
	t.log.Debug("tx.begin")
	return t, nil
}

// Exec runs canonical SQL inside the transaction. Errors leave the
// transaction in Postgres's aborted state; the caller must roll back.
func (t *tx) Exec(ctx context.Context, canonicalSQL string, maxRows int) (*db.Result, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.done {
		return nil, errors.New("transaction is already closed")
	}
	start := time.Now()
	maxRows = t.b.capRows(maxRows)
	log := t.log.With("sql", truncate(canonicalSQL), "max_rows", maxRows)
	log.Debug("tx.exec.start")
	rows, err := t.conn.Query(ctx, canonicalSQL)
	if err != nil {
		log.Debug("tx.exec.failed", "error", err.Error(), "duration", time.Since(start))
		return nil, err
	}
	res, err := collectRows(rows, t.conn.Conn().TypeMap(), maxRows)
	if err != nil {
		log.Debug("tx.exec.failed", "error", err.Error(), "duration", time.Since(start))
		return nil, err
	}
	res.Duration = time.Since(start)
	log.Debug("tx.exec.done", "rows", len(res.Rows), "rows_affected", res.RowsAffected, "truncated", res.Truncated, "duration", res.Duration)
	return res, nil
}

func (t *tx) Commit(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.done {
		return errors.New("transaction is already closed")
	}
	err := t.finish(ctx, "COMMIT")
	t.log.Debug("tx.commit", "error", errString(err))
	return err
}

func (t *tx) Rollback(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.done {
		return errors.New("transaction is already closed")
	}
	err := t.finish(ctx, "ROLLBACK")
	t.log.Debug("tx.rollback", "error", errString(err))
	return err
}

// finish ends the transaction with COMMIT or ROLLBACK and always releases
// the connection. A failed COMMIT is followed by a ROLLBACK so the connection
// goes back to the pool clean.
func (t *tx) finish(ctx context.Context, verb string) error {
	t.done = true
	defer t.conn.Release()
	if ctx.Err() != nil {
		ctx = context.WithoutCancel(ctx)
	}
	ctx, cancel := context.WithTimeout(ctx, resetTimeout)
	defer cancel()
	tag, err := t.conn.Exec(ctx, verb)
	if err != nil && verb == "COMMIT" {
		_, _ = t.conn.Exec(ctx, "ROLLBACK")
		return fmt.Errorf("commit: %w", err)
	}
	if err != nil {
		return fmt.Errorf("%s: %w", verb, err)
	}
	// Postgres answers COMMIT on an aborted transaction with a ROLLBACK tag
	// and no error; report that as a failure instead of a silent no-op.
	if verb == "COMMIT" && tag.String() == "ROLLBACK" {
		return errors.New("commit: transaction was aborted by an earlier error and has been rolled back")
	}
	return nil
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
