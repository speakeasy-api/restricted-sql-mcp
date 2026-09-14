// Package pgbackend implements db.Backend and db.TxBackend for Postgres on top
// of pgx. It owns the session-level protections: read-only transactions,
// statement_timeout and a pinned search_path.
package pgbackend

import (
	"context"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ThomasRooney/gram-restrictedsql-tunnel-mcp/internal/db"
	"github.com/ThomasRooney/gram-restrictedsql-tunnel-mcp/internal/policy"
	"github.com/ThomasRooney/gram-restrictedsql-tunnel-mcp/internal/sqlguard"
)

const (
	minPoolConns     = 16
	defaultMaxRows   = 1000
	bootPingTimeout  = 3 * time.Second
	resetTimeout     = 5 * time.Second
	logSQLLimit      = 2000
	undefinedFuncSQL = "42883"
)

// execer is the subset of pgx.Tx and *pgxpool.Conn used for session settings.
type execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Backend is a Postgres db.Backend backed by lazily connecting pgx pools.
// read serves queries, explain, metadata and readiness; write serves Begin.
// They are the same pool unless the backend was built with a separate write
// DSN (connection-level security).
type Backend struct {
	read  *pgxpool.Pool
	write *pgxpool.Pool
	pol   *policy.Policy
	log   *slog.Logger
}

// New parses the DSN and creates the pool without requiring the database to
// be reachable; connectivity is reported by Ping (and therefore /readyz).
func New(ctx context.Context, dsn string, pol *policy.Policy, logger *slog.Logger) (*Backend, error) {
	return NewWithWriteDSN(ctx, dsn, "", pol, logger)
}

// NewWithWriteDSN is New with a second pool for write transactions. An empty
// writeDSN reuses the read pool.
func NewWithWriteDSN(ctx context.Context, readDSN, writeDSN string, pol *policy.Policy, logger *slog.Logger) (*Backend, error) {
	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With("backend", "postgres")
	read, err := newPool(ctx, readDSN)
	if err != nil {
		return nil, err
	}
	write := read
	if writeDSN != "" {
		if write, err = newPool(ctx, writeDSN); err != nil {
			read.Close()
			return nil, err
		}
	}
	b := &Backend{read: read, write: write, pol: pol, log: logger}
	pingCtx, cancel := context.WithTimeout(ctx, bootPingTimeout)
	defer cancel()
	if err := read.Ping(pingCtx); err != nil {
		logger.Warn("postgres unreachable at boot; readiness will retry", "error", err.Error())
	} else {
		logger.Debug("postgres reachable at boot", "max_conns", read.Config().MaxConns, "separate_write_pool", write != read)
	}
	return b, nil
}

func newPool(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("invalid postgres DSN: %w", err)
	}
	if cfg.MaxConns < minPoolConns {
		cfg.MaxConns = minPoolConns
	}
	cfg.MinConns = 0
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create postgres pool: %w", err)
	}
	return pool, nil
}

func (b *Backend) Dialect() policy.Dialect { return policy.Postgres }

func (b *Backend) Ping(ctx context.Context) error {
	err := b.read.Ping(ctx)
	if err != nil {
		b.log.Debug("ping failed", "error", err.Error())
	}
	return err
}

func (b *Backend) Close() error {
	b.read.Close()
	if b.write != b.read {
		b.write.Close()
	}
	return nil
}

// TablesExist returns the refs that are not a table, view, materialized view,
// partitioned table or foreign table.
func (b *Backend) TablesExist(ctx context.Context, refs []policy.TableRef) ([]policy.TableRef, error) {
	if len(refs) == 0 {
		return nil, nil
	}
	schemas := make([]string, len(refs))
	names := make([]string, len(refs))
	for i, r := range refs {
		schemas[i], names[i] = r.Schema, r.Name
	}
	const q = `
SELECT n.nspname, c.relname
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN unnest($1::text[], $2::text[]) AS want(s, t) ON want.s = n.nspname AND want.t = c.relname
WHERE c.relkind IN ('r', 'v', 'm', 'p', 'f')`
	rows, err := b.read.Query(ctx, q, schemas, names)
	if err != nil {
		return nil, fmt.Errorf("check tables: %w", err)
	}
	defer rows.Close()
	found := map[policy.TableRef]struct{}{}
	for rows.Next() {
		var s, t string
		if err := rows.Scan(&s, &t); err != nil {
			return nil, err
		}
		found[policy.TableRef{Schema: s, Name: t}] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("check tables: %w", err)
	}
	var missing []policy.TableRef
	for _, r := range refs {
		if _, ok := found[r]; !ok {
			missing = append(missing, r)
		}
	}
	b.log.Debug("tables checked", "wanted", len(refs), "missing", missing)
	return missing, nil
}

// beginReadOnly opens a READ ONLY transaction with the session protections
// applied. The caller must Rollback it.
func (b *Backend) beginReadOnly(ctx context.Context) (*pgxpool.Conn, pgx.Tx, error) {
	conn, err := b.read.Acquire(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("acquire connection: %w", err)
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		conn.Release()
		return nil, nil, fmt.Errorf("begin read-only transaction: %w", err)
	}
	if err := applySessionSettings(ctx, tx, b.pol); err != nil {
		_ = tx.Rollback(ctx)
		conn.Release()
		return nil, nil, err
	}
	return conn, tx, nil
}

// applySessionSettings pins statement_timeout and search_path for the
// current transaction. Both values come from boot configuration, never from
// the caller.
func applySessionSettings(ctx context.Context, tx execer, pol *policy.Policy) error {
	if pol.StatementTimeout > 0 {
		stmt := fmt.Sprintf("SET LOCAL statement_timeout = %d", pol.StatementTimeout.Milliseconds())
		if _, err := tx.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("set statement_timeout: %w", err)
		}
	}
	stmt := "SET LOCAL search_path = " + pgx.Identifier{pol.DefaultSchema}.Sanitize()
	if _, err := tx.Exec(ctx, stmt); err != nil {
		return fmt.Errorf("set search_path: %w", err)
	}
	return nil
}

// Query runs canonical read-only SQL inside a READ ONLY transaction that is
// always rolled back.
func (b *Backend) Query(ctx context.Context, canonicalSQL string, maxRows int) (*db.Result, error) {
	start := time.Now()
	maxRows = b.capRows(maxRows)
	log := b.log.With("sql", truncate(canonicalSQL), "max_rows", maxRows)
	log.Debug("query.start")
	conn, tx, err := b.beginReadOnly(ctx)
	if err != nil {
		log.Debug("query.begin_failed", "error", err.Error())
		return nil, err
	}
	defer conn.Release()
	defer rollbackQuietly(tx)

	rows, err := tx.Query(ctx, canonicalSQL)
	if err != nil {
		log.Debug("query.failed", "error", err.Error(), "duration", time.Since(start))
		return nil, err
	}
	res, err := collectRows(rows, conn.Conn().TypeMap(), maxRows)
	if err != nil {
		log.Debug("query.failed", "error", err.Error(), "duration", time.Since(start))
		return nil, err
	}
	res.Duration = time.Since(start)
	log.Debug("query.done", "rows", len(res.Rows), "truncated", res.Truncated, "duration", res.Duration)
	return res, nil
}

// Explain returns the JSON plan. Hypothetical indexes are created with hypopg
// inside the same read-only session and reset afterwards.
func (b *Backend) Explain(ctx context.Context, canonicalSQL string, opts db.ExplainOptions) (json.RawMessage, string, error) {
	start := time.Now()
	log := b.log.With("sql", truncate(canonicalSQL), "analyze", opts.Analyze, "hypothetical_indexes", len(opts.HypotheticalIndexes))
	log.Debug("explain.start")
	if opts.Analyze && len(opts.HypotheticalIndexes) > 0 {
		return nil, "", errors.New("analyze and hypothetical_indexes are mutually exclusive")
	}
	ddls := make([]string, 0, len(opts.HypotheticalIndexes))
	for _, h := range opts.HypotheticalIndexes {
		ddl, err := sqlguard.BuildIndexDDL(h)
		if err != nil {
			return nil, "", err
		}
		ddls = append(ddls, ddl)
	}

	conn, tx, err := b.beginReadOnly(ctx)
	if err != nil {
		return nil, "", err
	}
	defer conn.Release()
	if len(ddls) > 0 {
		// hypopg indexes are session-scoped, not transaction-scoped, so they
		// are reset on the bare connection after the transaction has been
		// rolled back (defers run last-in first-out), even when the caller's
		// context is done, so nothing leaks into the pool.
		defer func() {
			resetCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), resetTimeout)
			defer cancel()
			if _, err := conn.Exec(resetCtx, "SELECT hypopg_reset()"); err != nil {
				log.Warn("hypopg_reset failed", "error", err.Error())
			}
		}()
	}
	defer rollbackQuietly(tx)

	if len(ddls) > 0 {
		for _, ddl := range ddls {
			log.Debug("explain.hypopg_create", "ddl", ddl)
			if _, err := tx.Exec(ctx, "SELECT * FROM hypopg_create_index($1)", ddl); err != nil {
				if isUndefinedFunction(err, "hypopg_create_index") {
					return nil, "", errors.New("hypopg extension is not installed")
				}
				return nil, "", fmt.Errorf("create hypothetical index: %w", err)
			}
		}
	}

	explain := "EXPLAIN (FORMAT JSON, VERBOSE, COSTS"
	if opts.Analyze {
		explain += ", ANALYZE, BUFFERS"
	}
	explain += ") " + canonicalSQL
	var plan []byte
	if err := tx.QueryRow(ctx, explain).Scan(&plan); err != nil {
		log.Debug("explain.failed", "error", err.Error(), "duration", time.Since(start))
		return nil, "", err
	}
	if !json.Valid(plan) {
		return nil, "", errors.New("explain returned invalid JSON")
	}
	log.Debug("explain.done", "bytes", len(plan), "duration", time.Since(start))
	return json.RawMessage(plan), "", nil
}

func (b *Backend) capRows(maxRows int) int {
	if maxRows <= 0 {
		maxRows = b.pol.MaxRows
	}
	if maxRows <= 0 {
		maxRows = defaultMaxRows
	}
	return maxRows
}

func rollbackQuietly(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), resetTimeout)
	defer cancel()
	_ = tx.Rollback(ctx)
}

func isUndefinedFunction(err error, name string) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == undefinedFuncSQL {
		return strings.Contains(pgErr.Message, name)
	}
	return false
}

// collectRows drains rows into a Result, keeping at most maxRows and marking
// Truncated when more were available. It always closes rows so the command
// tag is complete.
func collectRows(rows pgx.Rows, tm *pgtype.Map, maxRows int) (*db.Result, error) {
	defer rows.Close()
	res := &db.Result{Rows: [][]any{}}
	for _, fd := range rows.FieldDescriptions() {
		res.Columns = append(res.Columns, db.Column{Name: fd.Name, Type: typeName(tm, fd.DataTypeOID)})
	}
	if res.Columns == nil {
		res.Columns = []db.Column{}
	}
	for rows.Next() {
		if len(res.Rows) >= maxRows {
			res.Truncated = true
			break
		}
		vals, err := rows.Values()
		if err != nil {
			return nil, err
		}
		row := make([]any, len(vals))
		for i, v := range vals {
			row[i] = convertValue(v)
		}
		res.Rows = append(res.Rows, row)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	res.RowsAffected = rows.CommandTag().RowsAffected()
	return res, nil
}

func typeName(tm *pgtype.Map, oid uint32) string {
	if tm != nil {
		if t, ok := tm.TypeForOID(oid); ok {
			return t.Name
		}
	}
	return fmt.Sprintf("oid:%d", oid)
}

// convertValue turns pgx's default decoded values into JSON-friendly ones.
func convertValue(v any) any {
	switch x := v.(type) {
	case nil:
		return nil
	case bool, string, int16, int32, int64, float32, float64, json.RawMessage:
		return x
	case time.Time:
		return x.Format(time.RFC3339Nano)
	case [16]byte:
		return formatUUID(x)
	case []byte:
		return `\x` + hex.EncodeToString(x)
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = convertValue(e)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = convertValue(e)
		}
		return out
	case driver.Valuer:
		dv, err := x.Value()
		if err != nil {
			return fmt.Sprint(v)
		}
		if _, again := dv.(driver.Valuer); again {
			return fmt.Sprint(dv)
		}
		return convertValue(dv)
	}
	return v
}

func formatUUID(u [16]byte) string {
	var buf [36]byte
	hex.Encode(buf[0:8], u[0:4])
	buf[8] = '-'
	hex.Encode(buf[9:13], u[4:6])
	buf[13] = '-'
	hex.Encode(buf[14:18], u[6:8])
	buf[18] = '-'
	hex.Encode(buf[19:23], u[8:10])
	buf[23] = '-'
	hex.Encode(buf[24:], u[10:])
	return string(buf[:])
}

func truncate(s string) string {
	if len(s) > logSQLLimit {
		return s[:logSQLLimit] + "…"
	}
	return s
}
