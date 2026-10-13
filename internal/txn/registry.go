// Package txn tracks open write transactions by id and rolls back the ones
// that go idle.
package txn

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/speakeasy-api/gram-restricted-sql-mcp/internal/db"
)

var (
	// ErrUnknown is returned for ids that were never issued, already
	// finished, or reaped after going idle.
	ErrUnknown = errors.New("unknown or expired transaction_id")
	// ErrTooMany is returned by Begin when the open-transaction cap is hit.
	ErrTooMany = errors.New("too many open transactions")
)

// closeTimeout bounds the rollback issued by the reaper and by Close.
const closeTimeout = 5 * time.Second

type entry struct {
	// mu serializes calls on one transaction; different ids never block
	// each other.
	mu       sync.Mutex
	tx       db.Tx
	database string // fixed at Begin; empty in single-database use
	lastUsed time.Time
	closed   bool
}

// Registry owns every open transaction of the process.
type Registry struct {
	mu      sync.Mutex
	entries map[string]*entry
	pending int
	backend db.TxBackend
	idle    time.Duration
	max     int
	logger  *slog.Logger
}

// New builds a registry. idle is the inactivity window after which a
// transaction is rolled back; max caps concurrently open transactions.
func New(backend db.TxBackend, idle time.Duration, max int, logger *slog.Logger) *Registry {
	if logger == nil {
		logger = slog.Default()
	}
	return &Registry{
		entries: map[string]*entry{},
		backend: backend,
		idle:    idle,
		max:     max,
		logger:  logger,
	}
}

// Begin opens a transaction on a dedicated connection of the registry's
// backend and returns its id and the time it expires if left idle.
func (r *Registry) Begin(ctx context.Context) (string, time.Time, error) {
	return r.BeginOn(ctx, r.backend, "")
}

// BeginOn opens a transaction on backend and records database as the
// database it belongs to. The open-transaction cap is shared by every
// database. The recorded database never changes; see Database.
func (r *Registry) BeginOn(ctx context.Context, backend db.TxBackend, database string) (string, time.Time, error) {
	r.mu.Lock()
	if len(r.entries)+r.pending >= r.max {
		open := len(r.entries)
		r.mu.Unlock()
		r.logger.DebugContext(ctx, "txn.begin rejected", "database", database, "open", open, "max", r.max)
		return "", time.Time{}, fmt.Errorf("%w (max %d)", ErrTooMany, r.max)
	}
	r.pending++
	r.mu.Unlock()

	tx, err := backend.Begin(ctx)
	r.mu.Lock()
	r.pending--
	if err != nil {
		r.mu.Unlock()
		r.logger.DebugContext(ctx, "txn.begin failed", "database", database, "error", err.Error())
		return "", time.Time{}, err
	}
	id, err := newID()
	if err != nil {
		r.mu.Unlock()
		_ = tx.Rollback(ctx)
		return "", time.Time{}, err
	}
	now := time.Now()
	r.entries[id] = &entry{tx: tx, database: database, lastUsed: now}
	open := len(r.entries)
	r.mu.Unlock()

	expires := now.Add(r.idle)
	r.logger.DebugContext(ctx, "txn.begin", "transaction_id", id, "database", database, "expires_at", expires, "open", open)
	return id, expires, nil
}

// Database returns the database the transaction was begun in.
func (r *Registry) Database(id string) (string, error) {
	e := r.lookup(id)
	if e == nil {
		return "", ErrUnknown
	}
	return e.database, nil
}

// CloseDatabase rolls back and forgets every open transaction of database,
// in parallel, waiting for calls in flight. It returns how many it closed.
func (r *Registry) CloseDatabase(database string) int {
	return r.closeWhere(func(e *entry) bool { return e.database == database }, "txn.closed_database")
}

// Exec runs canonical SQL inside the transaction and extends its idle
// deadline.
func (r *Registry) Exec(ctx context.Context, id, canonicalSQL string, maxRows int) (*db.Result, error) {
	e := r.lookup(id)
	if e == nil {
		return nil, ErrUnknown
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil, ErrUnknown
	}
	if time.Since(e.lastUsed) > r.idle {
		r.logger.DebugContext(ctx, "txn.expired", "transaction_id", id, "idle", time.Since(e.lastUsed).String())
		r.finish(ctx, id, e, "rollback")
		return nil, ErrUnknown
	}
	e.lastUsed = time.Now()
	start := time.Now()
	res, err := e.tx.Exec(ctx, canonicalSQL, maxRows)
	e.lastUsed = time.Now()
	if err != nil {
		r.logger.DebugContext(ctx, "txn.exec failed", "transaction_id", id, "database", e.database, "duration", time.Since(start).String(), "error", err.Error())
		return nil, err
	}
	r.logger.DebugContext(ctx, "txn.exec", "transaction_id", id, "database", e.database, "duration", time.Since(start).String(),
		"rows_affected", res.RowsAffected, "rows", len(res.Rows), "truncated", res.Truncated)
	return res, nil
}

// Commit commits and releases the transaction. The id is invalid afterwards
// even if the commit failed.
func (r *Registry) Commit(ctx context.Context, id string) error {
	e := r.lookup(id)
	if e == nil {
		return ErrUnknown
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return ErrUnknown
	}
	return r.finish(ctx, id, e, "commit")
}

// Rollback rolls back and releases the transaction.
func (r *Registry) Rollback(ctx context.Context, id string) error {
	e := r.lookup(id)
	if e == nil {
		return ErrUnknown
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return ErrUnknown
	}
	return r.finish(ctx, id, e, "rollback")
}

// finish closes the entry (caller holds e.mu), removes it from the map, and
// runs the terminal operation.
func (r *Registry) finish(ctx context.Context, id string, e *entry, op string) error {
	e.closed = true
	r.mu.Lock()
	delete(r.entries, id)
	open := len(r.entries)
	r.mu.Unlock()

	var err error
	if op == "commit" {
		err = e.tx.Commit(ctx)
	} else {
		err = e.tx.Rollback(ctx)
	}
	if err != nil {
		r.logger.DebugContext(ctx, "txn."+op+" failed", "transaction_id", id, "database", e.database, "open", open, "error", err.Error())
		return err
	}
	r.logger.DebugContext(ctx, "txn."+op, "transaction_id", id, "database", e.database, "open", open)
	return nil
}

func (r *Registry) lookup(id string) *entry {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.entries[id]
}

// RunReaper rolls back idle transactions until ctx is cancelled.
func (r *Registry) RunReaper(ctx context.Context) {
	interval := r.idle / 4
	if interval < time.Second {
		interval = time.Second
	}
	r.logger.Debug("txn.reaper started", "interval", interval.String(), "idle", r.idle.String())
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.reap()
		}
	}
}

func (r *Registry) reap() {
	r.mu.Lock()
	snapshot := make(map[string]*entry, len(r.entries))
	for id, e := range r.entries {
		snapshot[id] = e
	}
	r.mu.Unlock()

	for id, e := range snapshot {
		// A transaction with a call in flight is not idle; skip it this round.
		if !e.mu.TryLock() {
			continue
		}
		if !e.closed && time.Since(e.lastUsed) > r.idle {
			idle := time.Since(e.lastUsed)
			ctx, cancel := context.WithTimeout(context.Background(), closeTimeout)
			err := r.finish(ctx, id, e, "rollback")
			cancel()
			r.logger.Info("txn.reaped", "transaction_id", id, "database", e.database, "idle", idle.String(), "error", errString(err))
		}
		e.mu.Unlock()
	}
}

// Close rolls back every open transaction, in parallel so an unresponsive
// database costs closeTimeout once rather than per transaction. Calls in
// flight are waited for.
func (r *Registry) Close() {
	r.closeWhere(func(*entry) bool { return true }, "txn.closed")
}

func (r *Registry) closeWhere(match func(*entry) bool, event string) int {
	r.mu.Lock()
	snapshot := make(map[string]*entry, len(r.entries))
	for id, e := range r.entries {
		if match(e) {
			snapshot[id] = e
		}
	}
	r.mu.Unlock()
	var wg sync.WaitGroup
	for id, e := range snapshot {
		wg.Add(1)
		go func(id string, e *entry) {
			defer wg.Done()
			e.mu.Lock()
			defer e.mu.Unlock()
			if e.closed {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), closeTimeout)
			defer cancel()
			err := r.finish(ctx, id, e, "rollback")
			r.logger.Info(event, "transaction_id", id, "database", e.database, "error", errString(err))
		}(id, e)
	}
	wg.Wait()
	return len(snapshot)
}

// Open reports the number of open transactions.
func (r *Registry) Open() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}

func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate transaction id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
