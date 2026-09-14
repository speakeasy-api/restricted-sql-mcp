package e2e

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// superuserConn opens a direct pgx connection as the e2e superuser.
func superuserConn(t *testing.T) *pgx.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, pgDSN())
	if err != nil {
		t.Fatalf("superuser connect: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

func queryBool(t *testing.T, conn *pgx.Conn, sql string, args ...any) bool {
	t.Helper()
	var v bool
	if err := conn.QueryRow(context.Background(), sql, args...).Scan(&v); err != nil {
		t.Fatalf("%s %v: %v", sql, args, err)
	}
	return v
}

func queryStrings(t *testing.T, conn *pgx.Conn, sql string, args ...any) []string {
	t.Helper()
	rows, err := conn.Query(context.Background(), sql, args...)
	if err != nil {
		t.Fatalf("%s %v: %v", sql, args, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	sort.Strings(out)
	return out
}

// privilegeMatrix is the set of grant facts the tests assert on both roles.
var privilegeMatrix = []struct {
	sql  string
	want bool
}{
	{"SELECT has_table_privilege('restrictedsql_ro', 'public.forbidden_secrets', 'SELECT')", false},
	{"SELECT has_table_privilege('restrictedsql_ro', 'public.allowed_orders', 'SELECT')", true},
	{"SELECT has_table_privilege('restrictedsql_ro', 'public.allowed_customers', 'SELECT')", true},
	{"SELECT has_table_privilege('restrictedsql_ro', 'public.allowed_orders', 'INSERT')", false},
	{"SELECT has_table_privilege('restrictedsql_ro', 'public.allowed_audit', 'SELECT')", false},
	{"SELECT has_table_privilege('restrictedsql_rw', 'public.allowed_audit', 'INSERT')", true},
	{"SELECT has_table_privilege('restrictedsql_rw', 'public.allowed_audit', 'UPDATE')", true},
	{"SELECT has_table_privilege('restrictedsql_rw', 'public.allowed_audit', 'DELETE')", true},
	{"SELECT has_table_privilege('restrictedsql_rw', 'public.allowed_audit', 'SELECT')", true},
	{"SELECT has_table_privilege('restrictedsql_rw', 'public.allowed_orders', 'SELECT')", true},
	{"SELECT has_table_privilege('restrictedsql_rw', 'public.allowed_orders', 'UPDATE')", false},
	{"SELECT has_table_privilege('restrictedsql_rw', 'public.forbidden_secrets', 'SELECT')", false},
	{"SELECT has_sequence_privilege('restrictedsql_rw', 'public.allowed_audit_id_seq', 'USAGE')", true},
	{"SELECT has_sequence_privilege('restrictedsql_rw', 'public.allowed_audit_id_seq', 'SELECT')", true},
	{"SELECT has_sequence_privilege('restrictedsql_ro', 'public.allowed_audit_id_seq', 'USAGE')", false},
	{"SELECT has_sequence_privilege('restrictedsql_rw', 'public.allowed_seq', 'USAGE')", false},
	{"SELECT has_schema_privilege('restrictedsql_ro', 'public', 'USAGE')", true},
	{"SELECT has_schema_privilege('restrictedsql_rw', 'public', 'USAGE')", true},
	{"SELECT has_schema_privilege('restrictedsql_ro', 'public', 'CREATE')", false},
}

func assertRoles(t *testing.T, conn *pgx.Conn) {
	t.Helper()
	for _, role := range []string{"restrictedsql_ro", "restrictedsql_rw"} {
		var canLogin, super, createRole, createDB, inherit, replication bool
		var config []string
		err := conn.QueryRow(context.Background(),
			"SELECT rolcanlogin, rolsuper, rolcreaterole, rolcreatedb, rolinherit, rolreplication, coalesce(rolconfig, '{}') FROM pg_roles WHERE rolname = $1", role).
			Scan(&canLogin, &super, &createRole, &createDB, &inherit, &replication, &config)
		if err != nil {
			t.Fatalf("role %s: %v", role, err)
		}
		if !canLogin || super || createRole || createDB || inherit || replication {
			t.Fatalf("role %s attributes: login=%v super=%v createrole=%v createdb=%v inherit=%v replication=%v",
				role, canLogin, super, createRole, createDB, inherit, replication)
		}
		sort.Strings(config)
		if strings.Join(config, ",") != "search_path=public,statement_timeout=30000" {
			t.Fatalf("role %s config = %v", role, config)
		}
	}
	for _, p := range privilegeMatrix {
		if got := queryBool(t, conn, p.sql); got != p.want {
			t.Fatalf("%s = %v, want %v", p.sql, got, p.want)
		}
	}
}

func TestPostgresConnectionLevelSecurity(t *testing.T) {
	appName := fmt.Sprintf("e2e-cls-%d", time.Now().UnixNano())
	s := bootServer(t, ServerOpts{
		DSN:         pgDSN() + "&application_name=" + appName,
		WriteTables: []string{"allowed_audit"},
		Writes:      true,
		ExtraArgs:   []string{"--connection-level-security"},
	})
	conn := superuserConn(t)
	assertRoles(t, conn)

	out := s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT count(*) FROM allowed_orders"})
	if rows(t, out)[0][0] != float64(5) {
		t.Fatalf("count = %v", out)
	}
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT * FROM forbidden_secrets"}, "allowlist")

	schemas := s.mustCall(t, "list_schemas", nil)
	if !strings.Contains(fmt.Sprint(schemas["schemas"]), "public") {
		t.Fatalf("list_schemas = %v", schemas)
	}
	objects := s.mustCall(t, "list_objects", map[string]any{"schema": "public", "object_type": "table"})
	if !strings.Contains(fmt.Sprint(objects["objects"]), "allowed_orders") {
		t.Fatalf("list_objects = %v", objects)
	}
	details := s.mustCall(t, "get_object_details", map[string]any{"schema": "public", "name": "allowed_orders"})
	if len(details["columns"].([]any)) != 5 {
		t.Fatalf("get_object_details columns = %v", details["columns"])
	}
	plan := s.mustCall(t, "explain_query", map[string]any{"sql": "SELECT * FROM allowed_orders WHERE status = 'paid'"})
	if topPlan(t, plan)["Node Type"] == nil {
		t.Fatalf("explain plan = %v", plan)
	}
	hypo := s.mustCall(t, "explain_query", map[string]any{
		"sql":                  "SELECT * FROM allowed_orders WHERE status = 'paid'",
		"hypothetical_indexes": []map[string]any{{"table": "allowed_orders", "columns": []string{"status"}}},
	})
	if !strings.Contains(planText(t, hypo), "<") {
		t.Fatalf("plan does not use the hypothetical index: %s", planText(t, hypo))
	}

	id := beginTx(t, s)
	before := auditCount(t, s, id)
	ins := s.mustCall(t, "execute_sql_write", map[string]any{"transaction_id": id, "sql": "INSERT INTO allowed_audit (note) VALUES ('cls') RETURNING id"})
	if num(t, ins, "rows_affected") != 1 {
		t.Fatalf("insert = %v", ins)
	}
	s.mustReject(t, "execute_sql_write", map[string]any{"transaction_id": id, "sql": "INSERT INTO forbidden_secrets VALUES (2, 'x')"}, "allowlist")

	users := queryStrings(t, conn, "SELECT DISTINCT usename FROM pg_stat_activity WHERE application_name = $1", appName)
	if strings.Join(users, ",") != "restrictedsql_ro,restrictedsql_rw" {
		t.Fatalf("tool connections run as %v, want restrictedsql_ro and restrictedsql_rw only", users)
	}

	if auditCount(t, s, id) != before+1 {
		t.Fatalf("count inside txn did not grow")
	}
	if st := s.mustCall(t, "commit_transaction", map[string]any{"transaction_id": id}); st["status"] != "committed" {
		t.Fatalf("commit = %v", st)
	}
	if !queryBool(t, conn, "SELECT EXISTS (SELECT 1 FROM allowed_audit WHERE note = 'cls')") {
		t.Fatal("committed row is not visible to the superuser")
	}
	if _, err := conn.Exec(context.Background(), "DELETE FROM allowed_audit WHERE note = 'cls'"); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	users = queryStrings(t, conn, "SELECT DISTINCT usename FROM pg_stat_activity WHERE application_name = $1", appName)
	for _, u := range users {
		if u == "postgres" {
			t.Fatalf("a connection as the bootstrap user is still open after readiness: %v", users)
		}
	}
	if !strings.Contains(s.Logs.String(), `"msg":"postgres roles provisioned"`) {
		t.Fatal("provisioning summary missing from logs")
	}
	if strings.Contains(s.Logs.String(), "SCRAM-SHA-256$") || strings.Contains(s.Logs.String(), "postgres:postgres@") {
		t.Fatal("logs leak a credential")
	}
}

func TestPostgresConnectionLevelSecurityNotProvisionedWhenUnprivileged(t *testing.T) {
	conn := superuserConn(t)
	setup := []string{
		"DROP ROLE IF EXISTS e2e_unpriv",
		"CREATE ROLE e2e_unpriv LOGIN PASSWORD 'unpriv'",
		"GRANT USAGE ON SCHEMA public TO e2e_unpriv",
		"GRANT SELECT ON allowed_orders, allowed_customers TO e2e_unpriv",
	}
	for _, stmt := range setup {
		if _, err := conn.Exec(context.Background(), stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = conn.Exec(ctx, "REVOKE ALL ON ALL TABLES IN SCHEMA public FROM e2e_unpriv")
		_, _ = conn.Exec(ctx, "REVOKE ALL ON SCHEMA public FROM e2e_unpriv")
		if _, err := conn.Exec(ctx, "DROP ROLE e2e_unpriv"); err != nil {
			t.Errorf("drop e2e_unpriv: %v", err)
		}
	})

	dsn := strings.Replace(pgDSN(), "postgres:postgres@", "e2e_unpriv:unpriv@", 1)
	s := bootServer(t, ServerOpts{DSN: dsn, ExtraArgs: []string{"--connection-level-security"}, ExpectReady: boolPtr(false)})
	status, body := httpGet(t, s.URL+"/readyz")
	if status != http.StatusServiceUnavailable {
		t.Fatalf("/readyz = %d %s", status, body)
	}
	for _, want := range []string{"not provisioned", "permission denied", "CREATE OR ALTER ROLE"} {
		if !strings.Contains(body, want) {
			t.Fatalf("/readyz body %q does not mention %q", body, want)
		}
	}
	if strings.Contains(body, "unpriv@") {
		t.Fatalf("/readyz leaks the DSN: %s", body)
	}
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT 1"}, "not provisioned")
	s.mustReject(t, "list_schemas", nil, "not provisioned")
}

func TestPostgresConnectionLevelSecurityReprovisionIdempotent(t *testing.T) {
	conn := superuserConn(t)
	opts := ServerOpts{WriteTables: []string{"allowed_audit"}, Writes: true, ExtraArgs: []string{"--connection-level-security"}}
	var firstVerifiers []string
	t.Run("first boot", func(t *testing.T) {
		s := bootServer(t, opts)
		assertRoles(t, conn)
		firstVerifiers = queryStrings(t, conn, "SELECT rolpassword FROM pg_authid WHERE rolname IN ('restrictedsql_ro', 'restrictedsql_rw')")
		s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT 1"})
	})
	s := bootServer(t, opts)
	assertRoles(t, conn)
	second := queryStrings(t, conn, "SELECT rolpassword FROM pg_authid WHERE rolname IN ('restrictedsql_ro', 'restrictedsql_rw')")
	if len(firstVerifiers) != 2 || len(second) != 2 {
		t.Fatalf("verifiers: first %d second %d", len(firstVerifiers), len(second))
	}
	for _, v := range second {
		if !strings.HasPrefix(v, "SCRAM-SHA-256$") {
			t.Fatalf("password is not stored as a SCRAM verifier: %q", v[:min(len(v), 16)])
		}
		if contains(firstVerifiers, v) {
			t.Fatal("password was not rotated on the second boot")
		}
	}
	out := s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT count(*) FROM allowed_customers"})
	if rows(t, out)[0][0] != float64(3) {
		t.Fatalf("count = %v", out)
	}
	id := beginTx(t, s)
	s.mustCall(t, "execute_sql_write", map[string]any{"transaction_id": id, "sql": "INSERT INTO allowed_audit (note) VALUES ('reprovision')"})
	s.mustCall(t, "rollback_transaction", map[string]any{"transaction_id": id})
}

func chHTTP(t *testing.T, query string, headers map[string]string) (int, string) {
	t.Helper()
	base := "http://127.0.0.1:" + envOr("E2E_CH_HTTP_PORT", "58123") + "/"
	req, err := http.NewRequest(http.MethodPost, base, strings.NewReader(query))
	if err != nil {
		t.Fatalf("clickhouse request: %v", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("clickhouse http: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(body))
}

func chLines(t *testing.T, query string) []string {
	t.Helper()
	status, body := chHTTP(t, query+" FORMAT TSV", nil)
	if status != http.StatusOK {
		t.Fatalf("clickhouse %q: %d %s", query, status, body)
	}
	if body == "" {
		return nil
	}
	lines := strings.Split(body, "\n")
	sort.Strings(lines)
	return lines
}

func TestClickHouseConnectionLevelSecurity(t *testing.T) {
	s := bootServer(t, ServerOpts{Dialect: "clickhouse", ExtraArgs: []string{"--connection-level-security"}})

	if users := chLines(t, "SELECT name FROM system.users WHERE name = 'restrictedsql_ro'"); len(users) != 1 {
		t.Fatalf("system.users has no restrictedsql_ro: %v", users)
	}
	selects := chLines(t, "SELECT concat(database, '.', table) FROM system.grants WHERE user_name = 'restrictedsql_ro' AND access_type = 'SELECT' AND database = 'app'")
	if strings.Join(selects, ",") != "app.allowed_customers,app.allowed_orders" {
		t.Fatalf("SELECT grants = %v", selects)
	}
	if bad := chLines(t, "SELECT access_type FROM system.grants WHERE user_name = 'restrictedsql_ro' AND table = 'forbidden_secrets'"); len(bad) != 0 {
		t.Fatalf("grants on forbidden_secrets: %v", bad)
	}
	settings := chLines(t, "SELECT concat(setting_name, '=', toString(value), ':', toString(writability)) FROM system.settings_profile_elements WHERE user_name = 'restrictedsql_ro' AND setting_name = 'readonly'")
	if strings.Join(settings, ",") != "readonly=1:CONST" {
		t.Fatalf("readonly setting = %v", settings)
	}
	if status, _ := chHTTP(t, "SELECT 1", map[string]string{"X-ClickHouse-User": "restrictedsql_ro"}); status == http.StatusOK {
		t.Fatal("restrictedsql_ro accepted a query without a password")
	}

	out := s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT count() FROM allowed_orders"})
	if fmt.Sprint(rows(t, out)[0][0]) != "5" {
		t.Fatalf("count = %v", out)
	}
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT * FROM forbidden_secrets"}, "allowlist")
	trunc := s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT id FROM allowed_orders ORDER BY id", "max_rows": 2})
	if trunc["truncated"] != true || len(rows(t, trunc)) != 2 {
		t.Fatalf("truncation under the pinned user settings = %v", trunc)
	}
	schemas := s.mustCall(t, "list_schemas", nil)
	if !strings.Contains(fmt.Sprint(schemas["schemas"]), "app") {
		t.Fatalf("list_schemas = %v", schemas)
	}
	objects := s.mustCall(t, "list_objects", map[string]any{"schema": "app", "object_type": "table"})
	if !strings.Contains(fmt.Sprint(objects["objects"]), "allowed_orders") {
		t.Fatalf("list_objects = %v", objects)
	}
	details := s.mustCall(t, "get_object_details", map[string]any{"schema": "app", "name": "allowed_orders"})
	if len(details["columns"].([]any)) != 5 {
		t.Fatalf("get_object_details = %v", details)
	}
	plan := s.mustCall(t, "explain_query", map[string]any{"sql": "SELECT * FROM allowed_orders WHERE id = 1"})
	if !strings.Contains(fmt.Sprint(plan["plan"]), "allowed_orders") {
		t.Fatalf("explain = %v", plan)
	}
	if !strings.Contains(s.Logs.String(), `"msg":"clickhouse user provisioned"`) {
		t.Fatal("provisioning summary missing from logs")
	}
	if strings.Contains(s.Logs.String(), "sha256_password BY '") && !strings.Contains(s.Logs.String(), "BY '<redacted>'") {
		t.Fatal("logs leak the clickhouse password")
	}
}
