package e2e

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestPostgresReadBasic(t *testing.T) {
	s := bootServer(t, ServerOpts{})
	out := s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT id, amount FROM allowed_orders ORDER BY id"})
	if got := columnNames(t, out); !reflect.DeepEqual(got, []string{"id", "amount"}) {
		t.Fatalf("columns = %v", got)
	}
	rs := rows(t, out)
	if len(rs) != 5 {
		t.Fatalf("rows = %d, want 5: %v", len(rs), rs)
	}
	if rs[0][0] != float64(1) || rs[0][1] != "10.00" {
		t.Fatalf("first row = %v, want [1 10.00]", rs[0])
	}
	if num(t, out, "row_count") != 5 || out["truncated"] != false {
		t.Fatalf("row_count/truncated = %v/%v", out["row_count"], out["truncated"])
	}
	if _, ok := out["duration_ms"].(float64); !ok {
		t.Fatalf("duration_ms missing: %v", out)
	}
	if !strings.Contains(s.Logs.String(), "public.allowed_orders") {
		t.Fatalf("debug logs do not mention the canonical table name")
	}
}

func TestPostgresReadTruncation(t *testing.T) {
	s := bootServer(t, ServerOpts{})
	out := s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT id FROM allowed_orders ORDER BY id", "max_rows": 2})
	if rs := rows(t, out); len(rs) != 2 {
		t.Fatalf("rows = %d, want 2", len(rs))
	}
	if out["truncated"] != true || num(t, out, "row_count") != 2 {
		t.Fatalf("truncated/row_count = %v/%v", out["truncated"], out["row_count"])
	}
}

func TestPostgresReadServerRowCap(t *testing.T) {
	s := bootServer(t, ServerOpts{ExtraArgs: []string{"--max-rows", "3"}})
	out := s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT id FROM allowed_orders ORDER BY id", "max_rows": 100})
	if rs := rows(t, out); len(rs) != 3 || out["truncated"] != true {
		t.Fatalf("rows = %d truncated = %v, want 3/true", len(rs), out["truncated"])
	}
}

func TestPostgresReadJoinAndAggregate(t *testing.T) {
	s := bootServer(t, ServerOpts{})
	out := s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": `
		SELECT c.name, count(*) AS n, sum(o.amount) AS total
		FROM allowed_orders o JOIN allowed_customers c ON c.id = o.customer_id
		WHERE o.status = 'paid'
		GROUP BY c.name HAVING count(*) >= 1 ORDER BY c.name`})
	rs := rows(t, out)
	if len(rs) != 2 {
		t.Fatalf("rows = %v, want Ada and Linus", rs)
	}
	if rs[0][0] != "Ada" || rs[0][1] != float64(2) || rs[0][2] != "35.50" {
		t.Fatalf("Ada row = %v", rs[0])
	}
	if rs[1][0] != "Linus" || rs[1][1] != float64(1) || rs[1][2] != "42.00" {
		t.Fatalf("Linus row = %v", rs[1])
	}
}

func TestPostgresReadWindowAndCTE(t *testing.T) {
	s := bootServer(t, ServerOpts{})
	out := s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": `
		WITH ranked AS (
			SELECT id, customer_id, amount,
			       row_number() OVER (PARTITION BY customer_id ORDER BY amount DESC) AS rn
			FROM allowed_orders
		)
		SELECT id, customer_id FROM ranked WHERE rn = 1 ORDER BY customer_id`})
	rs := rows(t, out)
	if len(rs) != 3 || rs[0][0] != float64(2) || rs[1][0] != float64(3) || rs[2][0] != float64(4) {
		t.Fatalf("rows = %v, want top order per customer [2 3 4]", rs)
	}
}

func TestPostgresReadValueTypes(t *testing.T) {
	s := bootServer(t, ServerOpts{})
	out := s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": `
		SELECT id, amount, created_at, status, amount::float8 AS f, NULL::text AS n,
		       ARRAY[1, 2] AS arr, '{"a":1}'::jsonb AS j, created_at::date AS d, true AS b
		FROM allowed_orders WHERE id = 1`})
	rs := rows(t, out)
	if len(rs) != 1 {
		t.Fatalf("rows = %v", rs)
	}
	r := rs[0]
	checks := []struct {
		i    int
		want any
	}{
		{0, float64(1)}, {1, "10.00"}, {2, "2026-01-01T10:00:00Z"}, {3, "paid"}, {4, float64(10)}, {5, nil},
		{6, []any{float64(1), float64(2)}}, {7, map[string]any{"a": float64(1)}}, {8, "2026-01-01T00:00:00Z"}, {9, true},
	}
	for _, c := range checks {
		if !reflect.DeepEqual(r[c.i], c.want) {
			t.Errorf("column %d = %#v (%T), want %#v", c.i, r[c.i], r[c.i], c.want)
		}
	}
	types := map[string]string{}
	for _, c := range out["columns"].([]any) {
		m := c.(map[string]any)
		types[fmt.Sprint(m["name"])] = fmt.Sprint(m["type"])
	}
	if types["amount"] != "numeric" || types["created_at"] != "timestamptz" || types["j"] != "jsonb" {
		t.Fatalf("column types = %v", types)
	}
}

func TestPostgresReadPositiveCorpus(t *testing.T) {
	s := bootServer(t, ServerOpts{})
	for _, sql := range positiveCorpusCommon {
		t.Run(sql, func(t *testing.T) {
			out := s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": sql})
			if _, ok := out["rows"]; !ok {
				t.Fatalf("no rows in result: %v", out)
			}
		})
	}
}

func TestPostgresBypassCorpus(t *testing.T) {
	s := bootServer(t, ServerOpts{})
	corpus := append(append([]string{}, bypassCorpusCommon...), bypassCorpusPostgres...)
	for _, sql := range corpus {
		t.Run(sql, func(t *testing.T) {
			s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": sql}, "rejected")
		})
	}
	if row := s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT count(*) FROM allowed_orders"}); rows(t, row)[0][0] != float64(5) {
		t.Fatalf("allowed_orders changed during the bypass corpus: %v", row)
	}
}

func TestPostgresReadRejectsWriteVerbs(t *testing.T) {
	s := bootServer(t, ServerOpts{WriteTables: []string{"allowed_audit"}, Writes: true})
	cases := map[string]string{
		"INSERT INTO allowed_audit (note) VALUES ('x')":                      "read mode",
		"UPDATE allowed_audit SET note = 'x'":                                "read mode",
		"DELETE FROM allowed_audit":                                          "read mode",
		"WITH d AS (DELETE FROM allowed_audit RETURNING id) SELECT * FROM d": "read mode",
		"SELECT * FROM allowed_audit":                                        "public.allowed_audit",
	}
	for sql, want := range cases {
		t.Run(sql, func(t *testing.T) {
			s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": sql}, want)
		})
	}
}

func TestPostgresReadAdversarial(t *testing.T) {
	s := bootServer(t, ServerOpts{})
	rejected := map[string]string{
		"TABLE forbidden_secrets": "forbidden_secrets",
		"SELECT * FROM allowed_orders, forbidden_secrets AS allowed_customers":           "forbidden_secrets",
		`SELECT * FROM "Public"."allowed_orders"`:                                        "Public.allowed_orders",
		"SELECT CAST('x' AS regclass)":                                                   "regclass",
		`SELECT pg_catalog."pg_sleep"(1)`:                                                "pg_sleep",
		`SELECT "PG_SLEEP"(1)`:                                                           "PG_SLEEP",
		"SELECT public.lower('x')":                                                       "schema-qualified",
		"SELECT 1 OPERATOR(pg_catalog.+) 1":                                              "operator",
		"SELECT 'a' COLLATE \"C\"":                                                       "COLLATE",
		"SELECT xmlelement(name x)":                                                      "XML",
		"SELECT * FROM allowed_orders WHERE id = ANY (SELECT id FROM forbidden_secrets)": "forbidden_secrets",
		"SELECT * FROM allowed_orders o, LATERAL (SELECT * FROM forbidden_secrets) f":    "forbidden_secrets",
		"WITH RECURSIVE t AS (SELECT * FROM forbidden_secrets UNION ALL SELECT * FROM t) SELECT * FROM t": "forbidden_secrets",
		"SELECT * FROM ROWS FROM (generate_series(1, 2))":                                                 "table functions",
		"SELECT current_user":                                 "introspection",
		"SELECT session_user, current_schema":                 "introspection",
		"SELECT * FROM allowed_orders WHERE id = 1; SELECT 1": "one statement",
		"SELECT 1;;":                     "trailing",
		"SELECT nextval('allowed_seq')":  "nextval",
		"SELECT * FROM allowed_orders_v": "allowed_orders_v",
		"BEGIN":                          "transaction control",
		"SELECT * FROM json_table('[]', '$' COLUMNS (x int PATH '$'))":                                  "JSON",
		"SELECT * FROM allowed_orders WHERE amount > (SELECT count(*) FROM information_schema.columns)": "information_schema.columns",
		"SELECT 1 FROM (VALUES (1)) v, forbidden_secrets":                                               "forbidden_secrets",
	}
	for sql, want := range rejected {
		t.Run(sql, func(t *testing.T) {
			s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": sql}, want)
		})
	}
	accepted := []string{
		"WITH allowed_orders AS (SELECT 1 AS id) SELECT * FROM allowed_orders",
		"WITH forbidden_secrets AS (SELECT 1 AS id) SELECT * FROM forbidden_secrets",
		"SELECT * FROM allowed_orders /* comment */ ;",
		"-- leading comment\nSELECT 1",
		"SELECT * FROM ONLY allowed_orders",
		"SELECT DISTINCT ON (customer_id) id FROM allowed_orders ORDER BY customer_id, id",
		"SELECT id FROM allowed_orders ORDER BY id FETCH FIRST 2 ROWS WITH TIES",
		"SELECT status, count(*) FROM allowed_orders GROUP BY ROLLUP (status) ORDER BY 1",
		"SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY amount) FROM allowed_orders",
		"SELECT array_agg(id ORDER BY id) FILTER (WHERE id > 1) FROM allowed_orders",
		"SELECT * FROM allowed_orders WHERE status SIMILAR TO 'p%' OR status ILIKE 'C%' OR status LIKE 'p!%' ESCAPE '!'",
		"SELECT id FROM allowed_orders WHERE amount BETWEEN 5 AND 50 AND id IS NOT NULL AND (id, 1) IN (SELECT id, 1 FROM allowed_customers)",
		"SELECT date_trunc('day', created_at), extract(year FROM created_at), created_at AT TIME ZONE 'UTC', now() - interval '1 day' FROM allowed_orders",
		"SELECT sum(amount) OVER w FROM allowed_orders WINDOW w AS (PARTITION BY customer_id ORDER BY id ROWS BETWEEN 1 PRECEDING AND CURRENT ROW)",
		`SELECT "id" FROM "public"."allowed_orders" AS "O"`,
		"SELECT (row_to_json(o)).id, json_build_object('id', id)->>'id' FROM allowed_orders o",
		"SELECT * FROM (VALUES (1, 'a'), (2, 'b')) AS v(id, name)",
		"SELECT 1 WHERE 1 IS DISTINCT FROM 2 AND true IS TRUE",
	}
	for _, sql := range accepted {
		t.Run(sql, func(t *testing.T) {
			s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": sql})
		})
	}
}

func TestPostgresReadStatementTimeout(t *testing.T) {
	s := bootServer(t, ServerOpts{ExtraArgs: []string{"--statement-timeout", "500ms"}})
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": `
		WITH RECURSIVE t(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM t WHERE n < 10000000)
		SELECT count(*) FROM t`}, "canceling statement")
	s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT 1"})
}

func TestPostgresReadOnlyWhenTableNotReadable(t *testing.T) {
	s := bootServer(t, ServerOpts{ReadTables: []string{"allowed_customers"}})
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT * FROM allowed_orders"}, "public.allowed_orders")
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT * FROM public.allowed_orders"}, "public.allowed_orders")
	s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT * FROM allowed_customers"})
}

func TestPostgresReadSchemaQualifiedAllowlist(t *testing.T) {
	s := bootServer(t, ServerOpts{ReadTables: []string{"public.allowed_orders"}, ExtraArgs: []string{"--default-schema", "pg_catalog"}})
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT * FROM allowed_orders"}, "pg_catalog.allowed_orders")
	s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT * FROM public.allowed_orders"})
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT * FROM pg_tables"}, "pg_catalog.pg_tables")
}
