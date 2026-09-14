package e2e

import (
	"strings"
	"testing"
	"time"
)

func writeServer(t *testing.T, extra ...string) *Server {
	t.Helper()
	return bootServer(t, ServerOpts{WriteTables: []string{"allowed_audit"}, Writes: true, ExtraArgs: extra})
}

func beginTx(t *testing.T, s *Server) string {
	t.Helper()
	out := s.mustCall(t, "begin_transaction", nil)
	id, _ := out["transaction_id"].(string)
	if id == "" {
		t.Fatalf("begin_transaction returned no transaction_id: %v", out)
	}
	if exp, _ := out["expires_at"].(string); exp == "" {
		t.Fatalf("begin_transaction returned no expires_at: %v", out)
	} else if _, err := time.Parse(time.RFC3339, exp); err != nil {
		t.Fatalf("expires_at %q is not RFC3339: %v", exp, err)
	}
	return id
}

func auditCount(t *testing.T, s *Server, txID string) float64 {
	t.Helper()
	out := s.mustCall(t, "execute_sql_write", map[string]any{"transaction_id": txID, "sql": "SELECT count(*) FROM allowed_audit"})
	v, ok := rows(t, out)[0][0].(float64)
	if !ok {
		t.Fatalf("count is not a number: %v", out)
	}
	return v
}

func TestPostgresWriteRollback(t *testing.T) {
	s := writeServer(t)
	id := beginTx(t, s)
	before := auditCount(t, s, id)

	out := s.mustCall(t, "execute_sql_write", map[string]any{"transaction_id": id, "sql": "INSERT INTO allowed_audit (note) VALUES ('rollback me') RETURNING id, note"})
	if num(t, out, "rows_affected") != 1 || num(t, out, "row_count") != 1 {
		t.Fatalf("insert result = %v", out)
	}
	if r := rows(t, out); r[0][1] != "rollback me" {
		t.Fatalf("returning row = %v", r)
	}
	if got := auditCount(t, s, id); got != before+1 {
		t.Fatalf("count inside txn = %v, want %v", got, before+1)
	}
	status := s.mustCall(t, "rollback_transaction", map[string]any{"transaction_id": id})
	if status["status"] != "rolled_back" {
		t.Fatalf("rollback status = %v", status)
	}

	id2 := beginTx(t, s)
	if got := auditCount(t, s, id2); got != before {
		t.Fatalf("count after rollback = %v, want %v", got, before)
	}
	s.mustCall(t, "rollback_transaction", map[string]any{"transaction_id": id2})
	s.mustReject(t, "execute_sql_write", map[string]any{"transaction_id": id, "sql": "SELECT 1"}, "unknown or expired")
}

func TestPostgresWriteCommit(t *testing.T) {
	s := writeServer(t)
	id := beginTx(t, s)
	before := auditCount(t, s, id)
	s.mustCall(t, "execute_sql_write", map[string]any{"transaction_id": id, "sql": "INSERT INTO allowed_audit (note) VALUES ('committed')"})
	upd := s.mustCall(t, "execute_sql_write", map[string]any{"transaction_id": id, "sql": "UPDATE allowed_audit SET note = note || '!' WHERE note = 'committed'"})
	if num(t, upd, "rows_affected") != 1 {
		t.Fatalf("update rows_affected = %v", upd["rows_affected"])
	}
	status := s.mustCall(t, "commit_transaction", map[string]any{"transaction_id": id})
	if status["status"] != "committed" {
		t.Fatalf("commit status = %v", status)
	}
	s.mustReject(t, "commit_transaction", map[string]any{"transaction_id": id}, "unknown or expired")

	id2 := beginTx(t, s)
	if got := auditCount(t, s, id2); got != before+1 {
		t.Fatalf("count after commit = %v, want %v", got, before+1)
	}
	del := s.mustCall(t, "execute_sql_write", map[string]any{"transaction_id": id2, "sql": "DELETE FROM allowed_audit WHERE note = 'committed!' RETURNING id"})
	if num(t, del, "rows_affected") != 1 {
		t.Fatalf("delete rows_affected = %v", del["rows_affected"])
	}
	s.mustCall(t, "commit_transaction", map[string]any{"transaction_id": id2})

	ro := bootServer(t, ServerOpts{ReadTables: []string{"allowed_audit"}})
	if r := rows(t, ro.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT count(*) FROM allowed_audit WHERE note LIKE 'committed%'"})); r[0][0] != float64(0) {
		t.Fatalf("cleanup delete not visible from a read-only server: %v", r)
	}
}

func TestPostgresWritePolicy(t *testing.T) {
	s := writeServer(t)
	id := beginTx(t, s)
	rejected := map[string]string{
		"UPDATE allowed_orders SET amount = 0":                                                                   "public.allowed_orders",
		"DELETE FROM allowed_customers":                                                                          "public.allowed_customers",
		"INSERT INTO allowed_audit (note) SELECT secret FROM forbidden_secrets":                                  "public.forbidden_secrets",
		"INSERT INTO forbidden_secrets VALUES (9, 'x')":                                                          "public.forbidden_secrets",
		"SELECT * FROM forbidden_secrets":                                                                        "public.forbidden_secrets",
		"WITH s AS (SELECT secret FROM forbidden_secrets) INSERT INTO allowed_audit (note) SELECT secret FROM s": "public.forbidden_secrets",
		"INSERT INTO allowed_audit (note) VALUES ('x'); DELETE FROM allowed_audit":                               "one statement",
		"TRUNCATE allowed_audit":                                                                                 "TRUNCATE",
		"INSERT INTO allowed_audit (note) VALUES (pg_read_file('/etc/passwd'))":                                  "pg_read_file",
		"INSERT INTO allowed_audit (note) VALUES ($1)":                                                           "bind parameters",
		"COMMIT": "transaction control",
		"WITH allowed_audit AS (SELECT 1) INSERT INTO allowed_orders (id) VALUES (1)": "public.allowed_orders",
	}
	for sql, want := range rejected {
		t.Run(sql, func(t *testing.T) {
			s.mustReject(t, "execute_sql_write", map[string]any{"transaction_id": id, "sql": sql}, want)
		})
	}
	for _, sql := range bypassCorpusWritePostgres {
		t.Run("corpus/"+sql, func(t *testing.T) {
			s.mustReject(t, "execute_sql_write", map[string]any{"transaction_id": id, "sql": sql}, "rejected")
		})
	}
	// Rejections happen before the database sees anything, so the
	// transaction is still usable.
	accepted := []string{
		"SELECT * FROM allowed_orders ORDER BY id",
		"SELECT o.id FROM allowed_orders o JOIN allowed_customers c ON c.id = o.customer_id",
		"INSERT INTO allowed_audit (note) SELECT status FROM allowed_orders WHERE id = 1",
		"INSERT INTO allowed_audit (note) SELECT c.name FROM allowed_customers c RETURNING id",
		"UPDATE allowed_audit SET note = 'x' WHERE id IN (SELECT id FROM allowed_orders)",
		"UPDATE allowed_audit a SET note = c.name FROM allowed_customers c WHERE c.id = a.id",
		"DELETE FROM allowed_audit USING allowed_orders o WHERE o.id = allowed_audit.id RETURNING allowed_audit.id",
		"INSERT INTO allowed_audit (id, note) VALUES (1000, 'x') ON CONFLICT (id) DO UPDATE SET note = excluded.note",
		"INSERT INTO allowed_audit (id, note) VALUES (1000, 'y') ON CONFLICT DO NOTHING",
		"WITH d AS (DELETE FROM allowed_audit WHERE id = 1000 RETURNING id) SELECT count(*) FROM d",
		"WITH allowed_orders AS (SELECT 1 AS id) INSERT INTO allowed_audit (note) SELECT 'cte' FROM allowed_orders",
	}
	for _, sql := range accepted {
		t.Run(sql, func(t *testing.T) {
			s.mustCall(t, "execute_sql_write", map[string]any{"transaction_id": id, "sql": sql})
		})
	}
	s.mustCall(t, "rollback_transaction", map[string]any{"transaction_id": id})

	id2 := beginTx(t, s)
	if got := auditCount(t, s, id2); got != 0 {
		t.Fatalf("allowed_audit not empty after rollback: %v", got)
	}
	s.mustCall(t, "rollback_transaction", map[string]any{"transaction_id": id2})
}

func TestPostgresWriteAbortedTransaction(t *testing.T) {
	s := writeServer(t)
	id := beginTx(t, s)
	s.mustReject(t, "execute_sql_write", map[string]any{"transaction_id": id, "sql": "INSERT INTO allowed_audit (id, note) VALUES (NULL, 'x')"}, "not-null")
	s.mustReject(t, "execute_sql_write", map[string]any{"transaction_id": id, "sql": "SELECT 1"}, "current transaction is aborted")
	s.mustReject(t, "commit_transaction", map[string]any{"transaction_id": id}, "")
	s.mustReject(t, "execute_sql_write", map[string]any{"transaction_id": id, "sql": "SELECT 1"}, "unknown or expired")

	id2 := beginTx(t, s)
	if got := auditCount(t, s, id2); got != 0 {
		t.Fatalf("aborted transaction left rows: %v", got)
	}
	s.mustCall(t, "rollback_transaction", map[string]any{"transaction_id": id2})
}

func TestPostgresWriteUnknownTransaction(t *testing.T) {
	s := writeServer(t)
	for _, tool := range []string{"execute_sql_write", "commit_transaction", "rollback_transaction"} {
		s.mustReject(t, tool, map[string]any{"transaction_id": "00000000000000000000000000000000", "sql": "SELECT 1"}, "unknown or expired")
	}
	s.mustReject(t, "execute_sql_write", map[string]any{"transaction_id": "", "sql": "SELECT 1"}, "transaction_id")
}

func TestPostgresWriteMaxOpenTransactions(t *testing.T) {
	s := writeServer(t, "--max-open-txns", "1")
	id := beginTx(t, s)
	s.mustReject(t, "begin_transaction", nil, "too many")
	s.mustCall(t, "rollback_transaction", map[string]any{"transaction_id": id})
	id2 := beginTx(t, s)
	s.mustCall(t, "commit_transaction", map[string]any{"transaction_id": id2})
}

func TestPostgresWriteIdleTimeout(t *testing.T) {
	s := writeServer(t, "--txn-idle-timeout", "2s")
	id := beginTx(t, s)
	s.mustCall(t, "execute_sql_write", map[string]any{"transaction_id": id, "sql": "INSERT INTO allowed_audit (note) VALUES ('idle')"})
	time.Sleep(3500 * time.Millisecond)
	s.mustReject(t, "execute_sql_write", map[string]any{"transaction_id": id, "sql": "SELECT 1"}, "unknown or expired")
	if !strings.Contains(s.Logs.String(), "reaped") {
		t.Fatalf("reaper did not log the rollback")
	}
	id2 := beginTx(t, s)
	if got := auditCount(t, s, id2); got != 0 {
		t.Fatalf("reaped transaction was not rolled back: %v", got)
	}
	s.mustCall(t, "rollback_transaction", map[string]any{"transaction_id": id2})
}

func TestPostgresWriteRowCap(t *testing.T) {
	s := writeServer(t)
	id := beginTx(t, s)
	out := s.mustCall(t, "execute_sql_write", map[string]any{"transaction_id": id, "sql": "INSERT INTO allowed_audit (note) SELECT status FROM allowed_orders RETURNING id", "max_rows": 2})
	if num(t, out, "rows_affected") != 5 || len(rows(t, out)) != 2 || out["truncated"] != true {
		t.Fatalf("insert with row cap = %v", out)
	}
	s.mustCall(t, "rollback_transaction", map[string]any{"transaction_id": id})
}

func TestPostgresWriteToolsAbsentWithoutFlag(t *testing.T) {
	s := bootServer(t, ServerOpts{WriteTables: []string{"allowed_audit"}})
	for _, name := range s.toolNames(t) {
		if contains(writeToolNames, name) {
			t.Fatalf("write tool %s registered without --dangerously-add-write-tools", name)
		}
	}
}
