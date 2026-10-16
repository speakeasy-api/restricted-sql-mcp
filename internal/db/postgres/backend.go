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

	"github.com/speakeasy-api/restricted-sql-mcp/internal/db"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/policy"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/sqlguard"
)

const (
	// defaultMaxConns sizes the read pool when WithMaxConns is not given.
	defaultMaxConns = 16
	// maxConnIdleTime closes pooled connections unused this long (pgx checks
	// every minute), so a database nobody is querying holds no connections.
	maxConnIdleTime = time.Minute
	// txnIdleGrace is added to the transaction idle timeout for Postgres's
	// own idle_in_transaction_session_timeout, the backstop should this
	// process stop reaping.
	txnIdleGrace     = 30 * time.Second
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
// read serves queries, explain and metadata; write serves Begin; probe serves
// readiness (Ping, TablesExist) and the column snapshot. write is a pool of
// its own whenever writes are possible (it uses the write DSN under
// connection-level security, else the read DSN); probe is the read pool
// unless WithProbePool.
type Backend struct {
	read    *pgxpool.Pool
	write   *pgxpool.Pool
	probe   *pgxpool.Pool
	pol     *policy.Policy
	log     *slog.Logger
	txnIdle time.Duration
}

// Option tunes the backend at construction.
type Option func(*options)

type options struct {
	maxConns    int
	maxOpenTxns int
	txnIdle     time.Duration
	probePool   bool
}

// WithMaxConns caps the connections used for reads (queries, explain,
// metadata). The default is 16.
func WithMaxConns(n int) Option {
	return func(o *options) { o.maxConns = n }
}

// WithMaxOpenTxns is the process-wide cap on write transactions, each of
// which pins a connection from a separate write pool sized to it, so writes
// never starve reads.
func WithMaxOpenTxns(n int) Option {
	return func(o *options) { o.maxOpenTxns = n }
}

// WithTxnIdleTimeout sets idle_in_transaction_session_timeout on write
// transactions to d plus a grace period.
func WithTxnIdleTimeout(d time.Duration) Option {
	return func(o *options) { o.txnIdle = d }
}

// WithProbePool gives readiness and the column snapshot a one-connection
// pool of their own, so a saturated read pool cannot fail the probe.
func WithProbePool() Option {
	return func(o *options) { o.probePool = true }
}

// New parses the DSN and creates the pool without requiring the database to
// be reachable; connectivity is reported by Ping (and therefore /readyz).
func New(ctx context.Context, dsn string, pol *policy.Policy, logger *slog.Logger, opts ...Option) (*Backend, error) {
	return NewWithWriteDSN(ctx, dsn, "", pol, logger, opts...)
}

// NewWithWriteDSN is New with a second pool for write transactions. An empty
// writeDSN reuses the read pool.
func NewWithWriteDSN(ctx context.Context, readDSN, writeDSN string, pol *policy.Policy, logger *slog.Logger, opts ...Option) (*Backend, error) {
	if logger == nil {
		logger = slog.Default()
	}
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	logger = logger.With("backend", "postgres")
	reads := o.maxConns
	if reads <= 0 {
		reads = defaultMaxConns
	}
	b := &Backend{pol: pol, log: logger, txnIdle: o.txnIdle}
	var err error
	if b.read, err = newPool(ctx, readDSN, reads); err != nil {
		return nil, err
	}
	// Transactions get a pool of their own whose connections are closed when
	// the transaction ends (see tx.finish): pooled idle write connections
	// would otherwise pile up in every database's pool, past the
	// process-wide --max-open-txns cap.
	b.write = b.read
	if o.maxOpenTxns > 0 || writeDSN != "" {
		if writeDSN == "" {
			writeDSN = readDSN
		}
		if b.write, err = newPool(ctx, writeDSN, max(o.maxOpenTxns, 1)); err != nil {
			b.read.Close()
			return nil, err
		}
	}
	b.probe = b.read
	if o.probePool {
		if b.probe, err = newPool(ctx, readDSN, 1); err != nil {
			_ = b.Close()
			return nil, err
		}
	}
	pingCtx, cancel := context.WithTimeout(ctx, bootPingTimeout)
	defer cancel()
	if err := b.probe.Ping(pingCtx); err != nil {
		logger.Warn("postgres unreachable at boot; readiness will retry", "error", err.Error())
	} else {
		logger.Debug("postgres reachable at boot", "read_max_conns", b.read.Config().MaxConns, "write_max_conns", b.write.Config().MaxConns,
			"separate_write_pool", b.write != b.read, "probe_pool", b.probe != b.read)
		if err := b.RefreshColumns(pingCtx); err != nil {
			logger.Warn("could not load catalog columns at boot; readiness will retry", "error", err.Error())
		}
	}
	return b, nil
}

// newPool creates a lazily connecting pool of at most maxConns connections
// that sheds connections idle for maxConnIdleTime.
func newPool(ctx context.Context, dsn string, maxConns int) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("invalid postgres DSN: %w", err)
	}
	cfg.MaxConns = int32(max(maxConns, 1))
	cfg.MinConns = 0
	cfg.MaxConnIdleTime = maxConnIdleTime
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create postgres pool: %w", err)
	}
	return pool, nil
}

// RefreshColumns loads the ordered column names of every allowlisted relation
// into the policy. Relations that do not exist are simply absent from the
// snapshot, so qualified references to them fail closed in the guard.
func (b *Backend) RefreshColumns(ctx context.Context) error {
	if b.pol.AnnotationMode() {
		return nil
	}
	refs := b.pol.AllTables()
	schemas := make([]string, len(refs))
	names := make([]string, len(refs))
	for i, r := range refs {
		schemas[i], names[i] = r.Schema, r.Name
	}
	const q = `
SELECT n.nspname, c.relname, a.attname
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN unnest($1::text[], $2::text[]) AS want(s, t) ON want.s = n.nspname AND want.t = c.relname
JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
WHERE c.relkind IN ('r', 'v', 'm', 'p', 'f')
ORDER BY n.nspname, c.relname, a.attnum`
	rows, err := b.probe.Query(ctx, q, schemas, names)
	if err != nil {
		return fmt.Errorf("load columns: %w", err)
	}
	defer rows.Close()
	cols := map[policy.TableRef][]string{}
	for rows.Next() {
		var s, t, col string
		if err := rows.Scan(&s, &t, &col); err != nil {
			return fmt.Errorf("load columns: %w", err)
		}
		ref := policy.TableRef{Schema: s, Name: t}
		cols[ref] = append(cols[ref], col)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("load columns: %w", err)
	}
	b.pol.SetColumns(cols)
	b.log.Debug("catalog columns loaded", "relations", len(cols), "wanted", len(refs))
	return nil
}

func (b *Backend) Dialect() policy.Dialect { return policy.Postgres }

func (b *Backend) Ping(ctx context.Context) error {
	err := b.probe.Ping(ctx)
	if err != nil {
		b.log.Debug("ping failed", "error", err.Error())
	}
	return err
}

func (b *Backend) Close() error {
	b.read.Close()
	if b.probe != nil && b.probe != b.read {
		b.probe.Close()
	}
	if b.write != nil && b.write != b.read {
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
	rows, err := b.probe.Query(ctx, q, schemas, names)
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
	schema := pol.DefaultSchema
	if pol.AnnotationMode() {
		schema = "pg_catalog"
	}
	stmt := "SET LOCAL search_path = " + pgx.Identifier{schema}.Sanitize()
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
	fds := rows.FieldDescriptions()
	arrayCols := make([]bool, len(fds))
	for i, fd := range fds {
		res.Columns = append(res.Columns, db.Column{Name: fd.Name, Type: typeName(tm, fd.DataTypeOID)})
		arrayCols[i] = isArrayType(tm, fd.DataTypeOID)
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
		raw := rows.RawValues()
		row := make([]any, len(vals))
		for i, v := range vals {
			if arrayCols[i] && raw[i] != nil {
				// pgx decodes every array into a flat []any; rebuild the
				// dimensions so a 2-D array arrives as nested arrays.
				if nested, err := decodeArray(tm, fds[i], raw[i]); err == nil {
					v = nested
				}
			}
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

func isArrayType(tm *pgtype.Map, oid uint32) bool {
	if tm == nil {
		return false
	}
	t, ok := tm.TypeForOID(oid)
	if !ok {
		return false
	}
	_, isArray := t.Codec.(*pgtype.ArrayCodec)
	return isArray
}

// decodeArray scans an array column keeping its dimensions.
func decodeArray(tm *pgtype.Map, fd pgconn.FieldDescription, src []byte) (any, error) {
	var arr pgtype.Array[any]
	if err := tm.Scan(fd.DataTypeOID, fd.Format, src, &arr); err != nil {
		return nil, err
	}
	if !arr.Valid {
		return nil, nil
	}
	if len(arr.Dims) <= 1 {
		if arr.Elements == nil {
			return []any{}, nil
		}
		return arr.Elements, nil
	}
	rest := arr.Elements
	return nestArray(arr.Dims, &rest), nil
}

func nestArray(dims []pgtype.ArrayDimension, rest *[]any) []any {
	n := int(dims[0].Length)
	out := make([]any, 0, n)
	if len(dims) == 1 {
		out = append(out, (*rest)[:n]...)
		*rest = (*rest)[n:]
		return out
	}
	for i := 0; i < n; i++ {
		out = append(out, nestArray(dims[1:], rest))
	}
	return out
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
