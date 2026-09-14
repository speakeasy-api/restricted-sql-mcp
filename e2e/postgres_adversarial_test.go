package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestPostgresReadInputLimits covers inputs the guard must refuse before
// parsing: NUL bytes (the C parser would silently truncate at the first one)
// and oversized statements (the deparser is superlinear in size).
func TestPostgresReadInputLimits(t *testing.T) {
	s := bootServer(t, ServerOpts{})
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT 1\x00; SELECT * FROM forbidden_secrets"}, "NUL")
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT * FROM allowed_orders\x00, forbidden_secrets"}, "NUL")
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT '\x00'"}, "NUL")

	long := "SELECT " + strings.Repeat("1,", 40000) + "1"
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": long}, "too long")
	ok := "SELECT id FROM allowed_orders WHERE id IN (" + strings.Repeat("1,", 3000) + "1)"
	s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": ok})
}

// ensureLeakFunction installs the fixture from init.sql on a stack that was
// created before it existed, and proves it is reachable outside the guard.
func ensureLeakFunction(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, pgDSN())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close(ctx)
	_, err = conn.Exec(ctx, `CREATE OR REPLACE FUNCTION public.leak_via_row(public.allowed_orders) RETURNS text LANGUAGE sql STABLE
AS $$ SELECT secret FROM public.forbidden_secrets LIMIT 1 $$`)
	if err != nil {
		t.Fatalf("create fixture function: %v", err)
	}
	var leaked string
	if err := conn.QueryRow(ctx, "SELECT o.leak_via_row FROM public.allowed_orders o LIMIT 1").Scan(&leaked); err != nil {
		t.Fatalf("fixture function not reachable via column notation: %v", err)
	}
	if leaked != "hunter2" {
		t.Fatalf("fixture leaked %q, want hunter2", leaked)
	}
}

// TestPostgresColumnNotation covers Postgres's functional column notation:
// rel.name falls back to name(rel) when name is not a column, which would call
// any function taking the row type, record or anyelement. The guard must
// resolve every qualified reference to a real column.
func TestPostgresColumnNotation(t *testing.T) {
	ensureLeakFunction(t)
	s := bootServer(t, ServerOpts{})
	rejected := map[string]string{
		"SELECT o.leak_via_row FROM allowed_orders o":                                       "functional column notation",
		"SELECT (o).leak_via_row FROM allowed_orders o":                                     "functional column notation",
		"SELECT allowed_orders.leak_via_row FROM allowed_orders":                            "functional column notation",
		"SELECT public.allowed_orders.leak_via_row FROM public.allowed_orders":              "functional column notation",
		"SELECT * FROM allowed_orders o ORDER BY o.leak_via_row":                            "functional column notation",
		"SELECT * FROM allowed_orders o WHERE o.leak_via_row IS NOT NULL":                   "functional column notation",
		"SELECT o.id FROM allowed_orders o, LATERAL (SELECT o.leak_via_row AS s) l":         "functional column notation",
		"SELECT o.pg_typeof, o.pg_column_size, o.to_json, o.json_agg FROM allowed_orders o": "functional column notation",
		"SELECT j.to_json FROM (allowed_orders o JOIN allowed_customers c ON true) j":       "functional column notation",
		"SELECT x.pg_typeof FROM (SELECT 1 AS a) x":                                         "functional column notation",
		"SELECT x.to_json FROM (VALUES (1)) x":                                              "functional column notation",
		"WITH paid AS (SELECT id FROM allowed_orders) SELECT paid.to_json FROM paid":        "functional column notation",
		"SELECT x.leak_via_row FROM (SELECT o.* FROM allowed_orders o) x":                   "functional column notation",
		"SELECT (o.customer_id).pg_typeof FROM allowed_orders o":                            "field access on an expression",
		"SELECT (ROW(1, 2)).pg_typeof":                                                      "field access on an expression",
		"SELECT ((SELECT o FROM allowed_orders o LIMIT 1)).pg_typeof":                       "field access on an expression",
		"SELECT (id).pg_typeof FROM allowed_orders":                                         "field access on a column",
		"SELECT o.customer_id.pg_typeof FROM allowed_orders o":                              "does not name a relation",
		"SELECT allowed_orders.id FROM allowed_orders o":                                    "does not name a relation",
		"SELECT app.public.allowed_orders.id FROM allowed_orders":                           "catalog-qualified",
		"SELECT o.nope FROM allowed_orders o":                                               "o.nope",
		"SELECT o.ctid FROM allowed_orders o":                                               "o.ctid",
		"SELECT j.id FROM (allowed_orders o JOIN allowed_customers c USING (id)) AS j(x)":   "j.id",
		"WITH RECURSIVE a AS (SELECT * FROM b), b AS (SELECT 1 AS x) SELECT a.x FROM a":     "not known",
	}
	for sql, want := range rejected {
		t.Run(sql, func(t *testing.T) {
			s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": sql}, want)
		})
	}
	accepted := []string{
		"SELECT allowed_orders.id, public.allowed_orders.amount FROM public.allowed_orders",
		"SELECT sub.amount FROM (SELECT id, amount FROM allowed_orders) sub WHERE sub.amount > 10",
		"SELECT sub.amount, sub.name FROM (SELECT * FROM allowed_orders o JOIN allowed_customers c ON c.id = o.customer_id) sub",
		"SELECT sub.customer_id FROM (SELECT o.* FROM allowed_orders o) sub",
		"SELECT v.id, v.name, w.column1 FROM (VALUES (1, 'a')) AS v(id, name), (VALUES (2)) w",
		"SELECT paid.status FROM (SELECT status FROM allowed_orders WHERE status = 'paid' UNION SELECT status FROM allowed_orders) paid",
		"WITH paid(a, b) AS (SELECT id, amount FROM allowed_orders) SELECT paid.a, p.b FROM paid, paid p",
		"WITH RECURSIVE t(n) AS (SELECT 1 UNION ALL SELECT t.n + 1 FROM t WHERE t.n < 5) SELECT t.n FROM t",
		"WITH RECURSIVE b AS (SELECT 1 AS x), a AS (SELECT * FROM b) SELECT a.x FROM a",
		"SELECT j.id, j.name, j.email FROM (allowed_orders o JOIN allowed_customers c USING (id)) AS j(id, cid, amount, status, created_at, name, email)",
		"SELECT n.customer_id FROM (allowed_orders NATURAL JOIN allowed_customers) n",
		"SELECT o.id, (SELECT c.name FROM allowed_customers c WHERE c.id = o.customer_id) FROM allowed_orders o",
		"SELECT o.id, l.dbl FROM allowed_orders o CROSS JOIN LATERAL (SELECT o.amount * 2 AS dbl) l",
		"SELECT j.id, j.name FROM (allowed_orders o JOIN allowed_customers c USING (id)) j",
		"SELECT u.id FROM allowed_orders o JOIN allowed_customers c USING (id) AS u",
		"SELECT (o).id, (o).amount, (o).* FROM allowed_orders o",
		`SELECT x."coalesce", x.lower, x.text, x."?column?", x."case", x."exists", x."array", x."row", x.count, x."current_date", x."nullif", x."greatest", x.amount FROM (SELECT coalesce(id, 1), lower(status), 'a'::text, 1 + 1, CASE WHEN true THEN 1 END, EXISTS (SELECT 1), ARRAY[1], ROW(1), count(*), current_date, nullif(1, 2), greatest(1, 2), amount::int FROM allowed_orders GROUP BY 1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13) x`,
		"SELECT o.id, o.cid, o.amount FROM allowed_orders AS o(id, cid)",
		"SELECT customer_id, count(o.id) FROM allowed_orders o GROUP BY o.customer_id HAVING max(o.amount) > 1 ORDER BY o.customer_id",
		"SELECT sum(o.amount) OVER (PARTITION BY o.customer_id ORDER BY o.id) FROM allowed_orders o",
		"SELECT x.leak_via_row FROM (SELECT * FROM allowed_orders o JOIN (SELECT 1 AS leak_via_row) y ON true) x",
	}
	for _, sql := range accepted {
		t.Run(sql, func(t *testing.T) {
			s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": sql})
		})
	}
}

func TestPostgresColumnNotationWrite(t *testing.T) {
	ensureLeakFunction(t)
	s := writeServer(t)
	id := beginTx(t, s)
	rejected := map[string]string{
		"INSERT INTO allowed_audit (note) SELECT o.leak_via_row FROM allowed_orders o":                                      "functional column notation",
		"INSERT INTO allowed_audit (note) VALUES ('x') RETURNING allowed_audit.to_json":                                     "functional column notation",
		"INSERT INTO allowed_audit AS a (note) VALUES ('x') RETURNING a.pg_typeof":                                          "functional column notation",
		"INSERT INTO allowed_audit (id, note) VALUES (1, 'x') ON CONFLICT (id) DO UPDATE SET note = excluded.to_json::text": "functional column notation",
		"UPDATE allowed_audit a SET note = a.to_json::text":                                                                 "functional column notation",
		"UPDATE allowed_audit SET note = o.leak_via_row FROM allowed_orders o":                                              "functional column notation",
		"DELETE FROM allowed_audit a USING allowed_orders o WHERE o.leak_via_row IS NOT NULL":                               "functional column notation",
		"DELETE FROM allowed_audit RETURNING allowed_audit.record_out":                                                      "functional column notation",
		"WITH d AS (DELETE FROM allowed_audit RETURNING *) SELECT d.to_json FROM d":                                         "functional column notation",
	}
	for sql, want := range rejected {
		t.Run(sql, func(t *testing.T) {
			s.mustReject(t, "execute_sql_write", map[string]any{"transaction_id": id, "sql": sql}, want)
		})
	}
	accepted := []string{
		"INSERT INTO allowed_audit (note) VALUES ('x') RETURNING allowed_audit.id, allowed_audit.note",
		"INSERT INTO allowed_audit AS a (note) VALUES ('x') RETURNING a.id",
		"INSERT INTO allowed_audit (id, note) VALUES (1000, 'x') ON CONFLICT (id) DO UPDATE SET note = excluded.note || allowed_audit.note WHERE allowed_audit.id = excluded.id RETURNING allowed_audit.*",
		"UPDATE allowed_audit a SET note = c.name FROM allowed_customers c WHERE c.id = a.id RETURNING a.id, c.name",
		"UPDATE allowed_audit SET note = allowed_audit.note || 'x' WHERE allowed_audit.id = 1000",
		"DELETE FROM allowed_audit a USING allowed_orders o WHERE a.id = o.id RETURNING a.note, o.status",
		"WITH d AS (DELETE FROM allowed_audit a USING allowed_orders o WHERE a.id = o.id RETURNING a.*, o.status) SELECT d.note, d.status FROM d",
		"WITH i AS (INSERT INTO allowed_audit (note) VALUES ('x') RETURNING *) SELECT i.id FROM i",
		"WITH u AS (UPDATE allowed_audit SET note = 'y' RETURNING id AS uid) SELECT u.uid FROM u",
	}
	for _, sql := range accepted {
		t.Run(sql, func(t *testing.T) {
			s.mustCall(t, "execute_sql_write", map[string]any{"transaction_id": id, "sql": sql})
		})
	}
	s.mustCall(t, "rollback_transaction", map[string]any{"transaction_id": id})
}
