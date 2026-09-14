package e2e

import (
	"fmt"
	"strings"
	"testing"
)

func chServer(t *testing.T, o ServerOpts) *Server {
	t.Helper()
	o.Dialect = "clickhouse"
	return bootServer(t, o)
}

func TestClickHouseReadBasic(t *testing.T) {
	s := chServer(t, ServerOpts{})
	out := s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT id, amount FROM allowed_orders ORDER BY id"})
	if got := columnNames(t, out); strings.Join(got, ",") != "id,amount" {
		t.Fatalf("columns = %v", got)
	}
	rs := rows(t, out)
	if len(rs) != 5 || num(t, out, "row_count") != 5 || out["truncated"] != false {
		t.Fatalf("rows=%d row_count=%v truncated=%v", len(rs), out["row_count"], out["truncated"])
	}
	if fmt.Sprint(rs[0][0]) != "1" || fmt.Sprint(rs[4][0]) != "5" {
		t.Fatalf("unexpected ordering: %v", rs)
	}
	if _, ok := out["duration_ms"].(float64); !ok {
		t.Fatalf("duration_ms missing: %v", out)
	}
}

func TestClickHouseReadTruncation(t *testing.T) {
	s := chServer(t, ServerOpts{})
	out := s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT id FROM allowed_orders ORDER BY id", "max_rows": 2})
	if rs := rows(t, out); len(rs) != 2 || out["truncated"] != true || num(t, out, "row_count") != 2 {
		t.Fatalf("rows=%d truncated=%v row_count=%v", len(rs), out["truncated"], out["row_count"])
	}
}

func TestClickHouseReadJoinAndAggregate(t *testing.T) {
	s := chServer(t, ServerOpts{})
	out := s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": `
		SELECT c.name, uniq(o.id) AS orders, sum(o.amount) AS total, toStartOfDay(min(o.created_at)) AS first_day
		FROM allowed_orders AS o
		JOIN allowed_customers AS c ON c.id = o.customer_id
		GROUP BY c.name
		ORDER BY c.name`})
	rs := rows(t, out)
	if len(rs) != 3 {
		t.Fatalf("rows = %v", rs)
	}
	if fmt.Sprint(rs[0][0]) != "Ada" || fmt.Sprint(rs[0][1]) != "2" || fmt.Sprint(rs[0][2]) != "35.5" {
		t.Fatalf("first row = %v", rs[0])
	}
	if !strings.HasPrefix(fmt.Sprint(rs[0][3]), "2026-01-01T00:00:00") {
		t.Fatalf("first_day = %v", rs[0][3])
	}
}

func TestClickHouseReadPositiveCorpus(t *testing.T) {
	s := chServer(t, ServerOpts{})
	for _, sql := range positiveCorpusCommon {
		s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": sql})
	}
}

func TestClickHouseBypassCorpus(t *testing.T) {
	s := chServer(t, ServerOpts{})
	corpus := append(append([]string{}, bypassCorpusCommon...), bypassCorpusClickHouse...)
	for _, sql := range corpus {
		s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": sql}, "rejected")
	}
}

func TestClickHouseReadRejectsWriteVerbs(t *testing.T) {
	s := chServer(t, ServerOpts{})
	for _, sql := range []string{
		"INSERT INTO allowed_orders (id) VALUES (99)",
		"INSERT INTO allowed_orders SELECT * FROM allowed_orders",
		"ALTER TABLE allowed_orders DELETE WHERE id = 1",
		"DROP TABLE allowed_orders",
		"OPTIMIZE TABLE allowed_orders",
	} {
		s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": sql}, "rejected")
	}
	out := s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT count() FROM allowed_orders"})
	if rs := rows(t, out); fmt.Sprint(rs[0][0]) != "5" {
		t.Fatalf("table changed: %v", rs)
	}
}

func TestClickHouseInTableBypass(t *testing.T) {
	s := chServer(t, ServerOpts{})
	// Each of these reaches app.forbidden_secrets through the set position of
	// IN and would otherwise act as an exfiltration oracle for the secret.
	for _, sql := range []string{
		"SELECT (1, 'hunter2') IN (app.forbidden_secrets)",
		"SELECT (1, 'hunter2') IN ((app.forbidden_secrets))",
		"SELECT (1, 'hunter2') IN (forbidden_secrets)",
		"SELECT id GLOBAL IN (app.forbidden_secrets) FROM allowed_orders",
		"SELECT in((1, 'hunter2'), app.forbidden_secrets)",
		"SELECT globalIn((1, 'hunter2'), forbidden_secrets)",
		"SELECT arrayFilter(x -> (x, 'hunter2') IN (app.forbidden_secrets), [1])",
	} {
		s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": sql}, "rejected")
	}
	// Legitimate set-position operands must keep working: constant lists,
	// subqueries, scalar WITH aliases, and relation CTEs.
	for _, sql := range []string{
		"SELECT id IN (1, 2, 3) FROM allowed_orders",
		"SELECT id IN (SELECT customer_id FROM allowed_orders) FROM allowed_orders",
		"WITH 5 AS s SELECT id IN (s) FROM allowed_orders",
		"WITH t AS (SELECT id FROM allowed_orders) SELECT id IN (t) FROM allowed_orders",
		"SELECT in(id, (1, 2, 3)) FROM allowed_orders",
	} {
		s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": sql})
	}
}

func TestClickHouseReadStatementTimeout(t *testing.T) {
	s := chServer(t, ServerOpts{ExtraArgs: []string{"--statement-timeout", "1s"}})
	sql := "SELECT count() FROM allowed_orders AS t0"
	for i := 1; i < 13; i++ {
		sql += fmt.Sprintf(", allowed_orders AS t%d", i)
	}
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": sql}, "Timeout exceeded")
}

func TestClickHouseReadOnlyWhenTableNotReadable(t *testing.T) {
	s := chServer(t, ServerOpts{ReadTables: []string{"allowed_customers"}})
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT * FROM allowed_orders"}, "app.allowed_orders")
	s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT * FROM allowed_customers"})
}

func TestClickHouseReadQualifiedNamesAndCTEs(t *testing.T) {
	s := chServer(t, ServerOpts{})
	s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT count() FROM app.allowed_orders"})
	s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT count() FROM `app`.`allowed_orders`"})
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT count() FROM default.allowed_orders"}, "default.allowed_orders")
	out := s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "WITH forbidden_secrets AS (SELECT 1 AS id) SELECT id FROM forbidden_secrets"})
	if rs := rows(t, out); len(rs) != 1 || fmt.Sprint(rs[0][0]) != "1" {
		t.Fatalf("cte shadow rows = %v", rs)
	}
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "WITH x AS (SELECT * FROM allowed_orders) SELECT * FROM x UNION ALL SELECT * FROM x"}, "app.x")
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT * FROM allowed_orders WHERE id IN forbidden_secrets"}, "rejected")
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT arrayMap(x -> sleep(x), [1]) FROM allowed_orders"}, "sleep")
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT * FROM allowed_orders SAMPLE 0.5"}, "SAMPLE")
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT * FROM allowed_orders WHERE id = {id:Int32}"}, "bind parameters")
}
