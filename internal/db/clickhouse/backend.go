// Package chbackend implements db.Backend for ClickHouse over the native
// protocol. Read queries run with readonly=1, max_execution_time and
// max_result_rows as the session-level second layer behind the guard.
package chbackend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"reflect"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/speakeasy-api/restricted-sql-mcp/internal/db"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/policy"
)

const contextGrace = 5 * time.Second

// Backend is the ClickHouse implementation of db.Backend. It does not
// implement db.TxBackend: ClickHouse writes are out of scope.
type Backend struct {
	conn    driver.Conn
	pol     *policy.Policy
	timeout time.Duration
	log     *slog.Logger
}

// New parses the DSN and opens a lazily-dialing connection pool. It never
// fails because the server is unreachable; /readyz surfaces that instead.
func New(ctx context.Context, dsn string, pol *policy.Policy, logger *slog.Logger) (*Backend, error) {
	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With("backend", "clickhouse")
	opts, err := clickhouse.ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse clickhouse dsn: %w", err)
	}
	if opts.DialTimeout == 0 {
		opts.DialTimeout = 10 * time.Second
	}
	opts.MaxOpenConns = 8
	opts.MaxIdleConns = 2
	opts.ConnMaxLifetime = time.Hour
	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("open clickhouse connection: %w", err)
	}
	b := &Backend{conn: conn, pol: pol, timeout: pol.StatementTimeout, log: logger}
	if b.timeout <= 0 {
		b.timeout = 30 * time.Second
	}
	if err := conn.Ping(ctx); err != nil {
		logger.Warn("clickhouse not reachable at boot; readiness will retry", "error", err.Error())
	} else {
		logger.Debug("clickhouse reachable", "database", opts.Auth.Database, "addr", opts.Addr)
	}
	return b, nil
}

func (b *Backend) Dialect() policy.Dialect { return policy.ClickHouse }

func (b *Backend) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return b.conn.Ping(ctx)
}

func (b *Backend) Close() error { return b.conn.Close() }

// readCtx attaches the read-only session settings and a hard client-side
// cutoff. The driver replaces max_execution_time with any context deadline it
// sees, so the deadline is implemented with a timer on a cancel-only context
// instead, keeping the server-side limit authoritative.
func (b *Backend) readCtx(ctx context.Context, maxRows int) (context.Context, context.CancelFunc) {
	settings := clickhouse.Settings{
		"readonly":             1,
		"max_execution_time":   math.Ceil(b.timeout.Seconds()*1000) / 1000,
		"result_overflow_mode": "break",
	}
	if maxRows > 0 {
		settings["max_result_rows"] = maxRows + 1
	}
	b.log.Debug("query settings", "settings", fmt.Sprint(settings))
	qctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	timer := time.NewTimer(b.timeout + contextGrace)
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			cancel()
		case <-timer.C:
			cancel()
		case <-done:
		}
	}()
	stop := func() {
		timer.Stop()
		close(done)
		cancel()
	}
	return clickhouse.Context(qctx, clickhouse.WithSettings(settings)), stop
}

func (b *Backend) Query(ctx context.Context, canonicalSQL string, maxRows int) (*db.Result, error) {
	if maxRows <= 0 {
		maxRows = b.pol.MaxRows
	}
	if maxRows <= 0 {
		maxRows = 1000
	}
	qctx, cancel := b.readCtx(ctx, maxRows)
	defer cancel()
	start := time.Now()
	rows, err := b.conn.Query(qctx, canonicalSQL)
	if err != nil {
		b.log.Debug("query failed", "sql", canonicalSQL, "error", err.Error())
		return nil, err
	}
	defer rows.Close()
	res, err := collect(rows, maxRows)
	if err != nil {
		b.log.Debug("query read failed", "sql", canonicalSQL, "error", err.Error())
		return nil, err
	}
	res.Duration = time.Since(start)
	b.log.Debug("query ok", "sql", canonicalSQL, "rows", len(res.Rows), "truncated", res.Truncated,
		"duration_ms", res.Duration.Milliseconds())
	return res, nil
}

// collect reads up to maxRows rows, scanning each column into the driver's
// natural Go type and normalising it for JSON.
func collect(rows driver.Rows, maxRows int) (*db.Result, error) {
	types := rows.ColumnTypes()
	res := &db.Result{Columns: make([]db.Column, len(types)), Rows: [][]any{}}
	for i, ct := range types {
		res.Columns[i] = db.Column{Name: ct.Name(), Type: ct.DatabaseTypeName()}
	}
	for rows.Next() {
		if len(res.Rows) >= maxRows {
			res.Truncated = true
			break
		}
		dest := make([]any, len(types))
		for i, ct := range types {
			dest[i] = reflect.New(ct.ScanType()).Interface()
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		row := make([]any, len(types))
		for i, d := range dest {
			row[i] = normalize(reflect.ValueOf(d).Elem().Interface())
		}
		res.Rows = append(res.Rows, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return res, nil
}

// normalize converts driver values into JSON-friendly ones: nil pointers to
// null, times to RFC3339, Stringer types (decimals, UUIDs, IPs, big ints) to
// strings, and containers recursively.
func normalize(v any) any {
	if v == nil {
		return nil
	}
	switch x := v.(type) {
	case time.Time:
		return x.Format(time.RFC3339Nano)
	case *time.Time:
		if x == nil {
			return nil
		}
		return x.Format(time.RFC3339Nano)
	case string, bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return x
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Ptr, reflect.Interface:
		if rv.IsNil() {
			return nil
		}
		if s, ok := v.(fmt.Stringer); ok {
			return s.String()
		}
		return normalize(rv.Elem().Interface())
	case reflect.Slice, reflect.Array:
		if s, ok := v.(fmt.Stringer); ok {
			return s.String()
		}
		out := make([]any, rv.Len())
		for i := range out {
			out[i] = normalize(rv.Index(i).Interface())
		}
		return out
	case reflect.Map:
		out := make(map[string]any, rv.Len())
		iter := rv.MapRange()
		for iter.Next() {
			out[fmt.Sprint(normalize(iter.Key().Interface()))] = normalize(iter.Value().Interface())
		}
		return out
	case reflect.Struct:
		if s, ok := v.(fmt.Stringer); ok {
			return s.String()
		}
		return fmt.Sprint(v)
	}
	if s, ok := v.(fmt.Stringer); ok {
		return s.String()
	}
	return v
}

// Explain returns the text plan. Hypothetical indexes are a Postgres feature.
func (b *Backend) Explain(ctx context.Context, canonicalSQL string, opts db.ExplainOptions) (json.RawMessage, string, error) {
	if len(opts.HypotheticalIndexes) > 0 {
		return nil, "", errors.New("hypothetical indexes are not supported on clickhouse")
	}
	stmt := "EXPLAIN PLAN indexes = 1 " + canonicalSQL
	if opts.Analyze {
		stmt = "EXPLAIN PIPELINE " + canonicalSQL
	}
	qctx, cancel := b.readCtx(ctx, 0)
	defer cancel()
	start := time.Now()
	rows, err := b.conn.Query(qctx, stmt)
	if err != nil {
		b.log.Debug("explain failed", "sql", stmt, "error", err.Error())
		return nil, "", err
	}
	defer rows.Close()
	var lines []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return nil, "", err
		}
		lines = append(lines, line)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	b.log.Debug("explain ok", "sql", stmt, "lines", len(lines), "duration_ms", time.Since(start).Milliseconds())
	return nil, strings.Join(lines, "\n"), nil
}

// TablesExist reports which of refs are absent from system.tables.
func (b *Backend) TablesExist(ctx context.Context, refs []policy.TableRef) ([]policy.TableRef, error) {
	if len(refs) == 0 {
		return nil, nil
	}
	dbs := make([]string, 0, len(refs))
	names := make([]string, 0, len(refs))
	for _, r := range refs {
		dbs = append(dbs, r.Schema)
		names = append(names, r.Name)
	}
	qctx, cancel := b.readCtx(ctx, 0)
	defer cancel()
	rows, err := b.conn.Query(qctx,
		"SELECT database, name FROM system.tables WHERE database IN (?) AND name IN (?)", dbs, names)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	found := map[policy.TableRef]struct{}{}
	for rows.Next() {
		var r policy.TableRef
		if err := rows.Scan(&r.Schema, &r.Name); err != nil {
			return nil, err
		}
		found[r] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var missing []policy.TableRef
	for _, r := range refs {
		if _, ok := found[r]; !ok {
			missing = append(missing, r)
		}
	}
	b.log.Debug("tables checked", "requested", len(refs), "missing", len(missing))
	return missing, nil
}
