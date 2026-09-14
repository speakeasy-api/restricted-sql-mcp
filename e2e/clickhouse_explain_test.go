package e2e

import (
	"fmt"
	"strings"
	"testing"
)

func chPlanText(t *testing.T, out map[string]any) string {
	t.Helper()
	if out["dialect"] != "clickhouse" {
		t.Fatalf("dialect = %v", out["dialect"])
	}
	plan, ok := out["plan"].(string)
	if !ok || plan == "" {
		t.Fatalf("plan is not a non-empty string: %v", out["plan"])
	}
	return plan
}

func TestClickHouseExplainPlan(t *testing.T) {
	s := chServer(t, ServerOpts{})
	out := s.mustCall(t, "explain_query", map[string]any{"sql": "SELECT * FROM allowed_orders WHERE id = 1"})
	plan := chPlanText(t, out)
	if !strings.Contains(plan, "ReadFromMergeTree") || !strings.Contains(plan, "app.allowed_orders") {
		t.Fatalf("plan = %q", plan)
	}
	if !strings.Contains(plan, "PrimaryKey") {
		t.Fatalf("plan lacks index details (indexes = 1): %q", plan)
	}
}

func TestClickHouseExplainAnalyze(t *testing.T) {
	s := chServer(t, ServerOpts{})
	out := s.mustCall(t, "explain_query", map[string]any{"sql": "SELECT * FROM allowed_orders WHERE id = 1", "analyze": true})
	plan := chPlanText(t, out)
	if !strings.Contains(plan, "Pipeline") && !strings.Contains(plan, "Source") && !strings.Contains(plan, "Transform") {
		t.Fatalf("pipeline plan = %q", plan)
	}
}

func TestClickHouseExplainHypotheticalIndexUnsupported(t *testing.T) {
	s := chServer(t, ServerOpts{})
	s.mustReject(t, "explain_query", map[string]any{
		"sql":                  "SELECT * FROM allowed_orders WHERE status = 'paid'",
		"hypothetical_indexes": []map[string]any{{"table": "allowed_orders", "columns": []string{"status"}}},
	}, "not supported on clickhouse")
}

func TestClickHouseExplainRejectsBypass(t *testing.T) {
	s := chServer(t, ServerOpts{})
	for _, sql := range append([]string{"SELECT * FROM forbidden_secrets", "SELECT sleep(3)"}, bypassCorpusClickHouse...) {
		s.mustReject(t, "explain_query", map[string]any{"sql": sql}, "rejected")
	}
	out := s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT count() FROM allowed_orders"})
	if rs := rows(t, out); fmt.Sprint(rs[0][0]) != "5" {
		t.Fatalf("rows = %v", rs)
	}
}
