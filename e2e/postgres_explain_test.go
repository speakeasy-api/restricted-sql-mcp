package e2e

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// planText re-encodes the plan without HTML escaping so hypopg's "<oid>"
// index names are searchable.
func planText(t *testing.T, out map[string]any) string {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out["plan"]); err != nil {
		t.Fatalf("encode plan: %v", err)
	}
	return buf.String()
}

func topPlan(t *testing.T, out map[string]any) map[string]any {
	t.Helper()
	arr, ok := out["plan"].([]any)
	if !ok || len(arr) == 0 {
		t.Fatalf("plan is not a non-empty JSON array: %v", out["plan"])
	}
	first, ok := arr[0].(map[string]any)
	if !ok {
		t.Fatalf("plan[0] is not an object: %v", arr[0])
	}
	plan, ok := first["Plan"].(map[string]any)
	if !ok {
		t.Fatalf("plan[0] has no Plan object: %v", first)
	}
	return plan
}

func TestPostgresExplainPlain(t *testing.T) {
	s := bootServer(t, ServerOpts{})
	out := s.mustCall(t, "explain_query", map[string]any{"sql": "SELECT * FROM allowed_orders WHERE status = 'paid'"})
	if out["dialect"] != "postgres" {
		t.Fatalf("dialect = %v", out["dialect"])
	}
	plan := topPlan(t, out)
	if plan["Node Type"] != "Seq Scan" || plan["Relation Name"] != "allowed_orders" || plan["Schema"] != "public" {
		t.Fatalf("plan = %v", plan)
	}
	if strings.Contains(planText(t, out), "Actual Rows") {
		t.Fatalf("plain explain should not execute the query")
	}
}

func TestPostgresExplainAnalyze(t *testing.T) {
	s := bootServer(t, ServerOpts{})
	out := s.mustCall(t, "explain_query", map[string]any{"sql": "SELECT count(*) FROM allowed_orders o JOIN allowed_customers c ON c.id = o.customer_id", "analyze": true})
	text := planText(t, out)
	if !strings.Contains(text, "Actual Rows") || !strings.Contains(text, "Shared Hit Blocks") {
		t.Fatalf("analyze plan lacks actual rows / buffers: %s", text)
	}
	topPlan(t, out)
}

func TestPostgresExplainHypotheticalIndex(t *testing.T) {
	s := bootServer(t, ServerOpts{})
	args := map[string]any{
		"sql":                  "SELECT * FROM allowed_orders WHERE status = 'paid'",
		"hypothetical_indexes": []map[string]any{{"table": "allowed_orders", "columns": []string{"status"}}},
	}
	out := s.mustCall(t, "explain_query", args)
	text := planText(t, out)
	if !strings.Contains(text, "<") || !strings.Contains(text, "btree_allowed_orders_status") {
		t.Fatalf("plan does not use the hypothetical index: %s", text)
	}

	// The hypothetical index must not leak into later sessions.
	after := s.mustCall(t, "explain_query", map[string]any{"sql": "SELECT * FROM allowed_orders WHERE status = 'paid'"})
	if strings.Contains(planText(t, after), "btree_allowed_orders_status") {
		t.Fatalf("hypothetical index leaked into a later explain: %s", planText(t, after))
	}

	qualified := s.mustCall(t, "explain_query", map[string]any{
		"sql":                  "SELECT * FROM allowed_orders WHERE customer_id = 1 AND status = 'paid'",
		"hypothetical_indexes": []map[string]any{{"schema": "public", "table": "allowed_orders", "columns": []string{"customer_id", "status"}, "method": "btree"}},
	})
	if !strings.Contains(planText(t, qualified), "btree_allowed_orders_customer_id_status") {
		t.Fatalf("plan does not use the composite hypothetical index: %s", planText(t, qualified))
	}
}

func TestPostgresExplainRejections(t *testing.T) {
	s := bootServer(t, ServerOpts{})
	hypo := []map[string]any{{"table": "allowed_orders", "columns": []string{"status"}}}
	s.mustReject(t, "explain_query", map[string]any{"sql": "SELECT 1", "analyze": true, "hypothetical_indexes": hypo}, "mutually exclusive")
	s.mustReject(t, "explain_query", map[string]any{
		"sql":                  "SELECT 1",
		"hypothetical_indexes": []map[string]any{{"table": "forbidden_secrets", "columns": []string{"secret"}}},
	}, "forbidden_secrets")
	s.mustReject(t, "explain_query", map[string]any{
		"sql":                  "SELECT 1",
		"hypothetical_indexes": []map[string]any{{"table": "allowed_orders", "columns": []string{"status); DROP TABLE allowed_orders; --"}}},
	}, "identifier")
	s.mustReject(t, "explain_query", map[string]any{
		"sql":                  "SELECT 1",
		"hypothetical_indexes": []map[string]any{{"table": "allowed_orders", "columns": []string{"status"}, "method": "spgist"}},
	}, "method")
	for _, sql := range []string{
		"SELECT * FROM forbidden_secrets",
		"SELECT pg_sleep(1)",
		"DELETE FROM allowed_orders",
		"EXPLAIN SELECT 1",
		"SELECT 1; SELECT 2",
	} {
		s.mustReject(t, "explain_query", map[string]any{"sql": sql}, "rejected")
	}
	if row := s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT count(*) FROM allowed_orders"}); rows(t, row)[0][0] != float64(5) {
		t.Fatalf("allowed_orders changed: %v", row)
	}
}
