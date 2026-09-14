package e2e

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestPostgresReadyzWhenDatabaseFrozen pauses the container and checks that
// /readyz answers 503 within its probe timeout instead of hanging, then
// recovers once the container is unpaused.
func TestPostgresReadyzWhenDatabaseFrozen(t *testing.T) {
	s := bootServer(t, ServerOpts{DSN: dsnWithApp(uniqueName("e2e_frozenready"))})
	unpause := pausePostgres(t)
	for i := 0; i < 3; i++ {
		start := time.Now()
		status, body := tryGet(s.URL + "/readyz")
		elapsed := time.Since(start)
		if status != 503 {
			unpause()
			t.Fatalf("probe %d: /readyz = %d %q after %s, want 503", i, status, body, elapsed)
		}
		if elapsed > 4*time.Second {
			unpause()
			t.Fatalf("probe %d: /readyz took %s, over the 3s probe timeout", i, elapsed)
		}
		if !strings.Contains(body, `"ready":false`) || !strings.Contains(body, "ping") {
			unpause()
			t.Fatalf("probe %d: /readyz body %q", i, body)
		}
	}
	status, _ := tryGet(s.URL + "/healthz")
	unpause()
	if status != 200 {
		t.Fatalf("/healthz = %d while the database was frozen", status)
	}
	waitReadyz(t, s.URL, 200, 30*time.Second)
	if r := rows(t, s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT count(*) FROM allowed_orders"})); r[0][0] != float64(5) {
		t.Fatalf("query after recovery = %v", r)
	}
}

// TestPostgresReadyzRecoversWhenTableCreated checks readiness is
// re-evaluated per probe: a missing allowlisted table flips /readyz to 200
// once created and back to 503 once dropped.
func TestPostgresReadyzRecoversWhenTableCreated(t *testing.T) {
	probe := pgProbe(t)
	table := uniqueName("e2e_late")
	t.Cleanup(func() { execSQL(t, probe, "DROP TABLE IF EXISTS "+table) })
	s := bootServer(t, ServerOpts{ReadTables: []string{"allowed_orders", table}, ExpectReady: boolPtr(false)})
	if body := waitReadyz(t, s.URL, 503, 5*time.Second); !strings.Contains(body, "public."+table) {
		t.Fatalf("/readyz body %q does not name the missing table", body)
	}
	execSQL(t, probe, "CREATE TABLE "+table+" (id int)")
	waitReadyz(t, s.URL, 200, 10*time.Second)
	if r := rows(t, s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT count(*) FROM " + table})); r[0][0] != float64(0) {
		t.Fatalf("query on late table = %v", r)
	}
	execSQL(t, probe, "DROP TABLE "+table)
	if body := waitReadyz(t, s.URL, 503, 10*time.Second); !strings.Contains(body, "public."+table) {
		t.Fatalf("/readyz body %q after drop", body)
	}
}

// TestPostgresMaxRowsBounds checks max_rows at zero, negative, above the
// server cap and at the cap, for both execute tools.
func TestPostgresMaxRowsBounds(t *testing.T) {
	s := bootServer(t, ServerOpts{WriteTables: []string{"allowed_audit"}, Writes: true, ExtraArgs: []string{"--max-rows", "3"}})
	id := beginTx(t, s)
	cases := []struct {
		maxRows   any
		wantRows  int
		truncated bool
	}{
		{0, 3, true}, {-1, 3, true}, {-1000000, 3, true}, {100, 3, true}, {3, 3, true}, {2, 2, true}, {1, 1, true}, {nil, 3, true},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprint(tc.maxRows), func(t *testing.T) {
			for _, tool := range []string{"execute_sql_readonly", "execute_sql_write"} {
				args := map[string]any{"sql": "SELECT id FROM allowed_orders ORDER BY id"}
				if tc.maxRows != nil {
					args["max_rows"] = tc.maxRows
				}
				if tool == "execute_sql_write" {
					args["transaction_id"] = id
				}
				out := s.mustCall(t, tool, args)
				if got := len(rows(t, out)); got != tc.wantRows || out["truncated"] != tc.truncated || num(t, out, "row_count") != float64(tc.wantRows) {
					t.Fatalf("%s max_rows=%v: rows=%d truncated=%v row_count=%v, want %d/%v", tool, tc.maxRows, got, out["truncated"], out["row_count"], tc.wantRows, tc.truncated)
				}
			}
		})
	}
	out := s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT id FROM allowed_orders WHERE id <= 3 ORDER BY id", "max_rows": 0})
	if len(rows(t, out)) != 3 || out["truncated"] != false {
		t.Fatalf("exactly-cap result = %v", out)
	}
	s.mustCall(t, "rollback_transaction", map[string]any{"transaction_id": id})
}

const (
	leakRole     = "e2e_leakprobe"
	leakPassword = "LeakProbeS3cretPw"
	leakWrongPw  = "WrongLeakProbePw"
	leakTunnel   = "LeakProbeTunnelKey"
)

// TestPostgresNoSecretInErrorsOrLogs drives every error path it can reach
// with a role whose password is unique, then greps every tool error and
// every log line for that password, a wrong password and the tunnel key.
func TestPostgresNoSecretInErrorsOrLogs(t *testing.T) {
	probe := pgProbe(t)
	execSQL(t, probe, fmt.Sprintf(`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '%s') THEN CREATE ROLE %s LOGIN; END IF; END $$`, leakRole, leakRole))
	execSQL(t, probe, fmt.Sprintf("ALTER ROLE %s LOGIN PASSWORD '%s'", leakRole, leakPassword))
	execSQL(t, probe, "GRANT ALL ON ALL TABLES IN SCHEMA public TO "+leakRole)
	execSQL(t, probe, "GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO "+leakRole)

	base := strings.Replace(pgDSN(), "postgres:postgres@", leakRole+":"+leakPassword+"@", 1)
	if base == pgDSN() {
		t.Skip("E2E_PG_DSN does not use the default credentials; cannot substitute the probe role")
	}
	var texts []string
	record := func(label string, s string) {
		texts = append(texts, label+": "+s)
	}
	collect := func(s *Server, tool string, args map[string]any) {
		_, errText := s.call(t, tool, args)
		record(tool, errText)
	}

	s := bootServer(t, ServerOpts{DSN: base, WriteTables: []string{"allowed_audit"}, Writes: true, ExtraArgs: []string{"--statement-timeout", "1s"}})
	collect(s, "execute_sql_readonly", map[string]any{"sql": "SELECT * FROM forbidden_secrets"})
	collect(s, "execute_sql_readonly", map[string]any{"sql": "SELECT 1/0"})
	collect(s, "execute_sql_readonly", map[string]any{"sql": slowQuery})
	collect(s, "execute_sql_readonly", map[string]any{"sql": "SELECT nope FROM allowed_orders"})
	collect(s, "list_objects", map[string]any{"schema": "does_not_exist"})
	collect(s, "get_object_details", map[string]any{"schema": "public", "name": "does_not_exist"})
	collect(s, "explain_query", map[string]any{"sql": "SELECT * FROM allowed_orders", "hypothetical_indexes": []map[string]any{{"table": "allowed_orders", "columns": []string{"no_such_column"}}}})
	id := beginTx(t, s)
	collect(s, "execute_sql_write", map[string]any{"transaction_id": id, "sql": "SELECT 1/0"})
	collect(s, "commit_transaction", map[string]any{"transaction_id": id})
	collect(s, "execute_sql_write", map[string]any{"transaction_id": "nope", "sql": "SELECT 1"})
	_, body := httpGet(t, s.URL+"/readyz")
	record("readyz", body)

	unreachable := strings.Replace(base, "127.0.0.1:"+envOr("E2E_PG_PORT", "55433"), "127.0.0.1:1", 1) + "&connect_timeout=1"
	u := bootServer(t, ServerOpts{DSN: unreachable, WriteTables: []string{"allowed_audit"}, Writes: true, ExpectReady: boolPtr(false)})
	_, body = httpGet(t, u.URL+"/readyz")
	record("readyz unreachable", body)
	collect(u, "execute_sql_readonly", map[string]any{"sql": "SELECT 1"})
	collect(u, "begin_transaction", nil)
	collect(u, "list_schemas", nil)

	wrong := strings.Replace(base, leakPassword, leakWrongPw, 1)
	w := bootServer(t, ServerOpts{DSN: wrong, ExpectReady: boolPtr(false)})
	_, body = httpGet(t, w.URL+"/readyz")
	record("readyz wrong password", body)
	if !strings.Contains(body, "password authentication failed") {
		t.Fatalf("wrong password readyz body: %s", body)
	}
	collect(w, "execute_sql_readonly", map[string]any{"sql": "SELECT 1"})

	invalid := strings.Replace(base, "127.0.0.1:"+envOr("E2E_PG_PORT", "55433"), "127.0.0.1:notaport", 1)
	code, out := runServerCaptureAll(t, []string{"--dialect", "postgres", "--dsn", invalid, "--read-tables", "allowed_orders", "--listen", fmt.Sprintf("127.0.0.1:%d", freePort(t))}, nil, 10*time.Second)
	if code == 0 {
		t.Fatalf("invalid DSN did not make the server exit")
	}
	record("invalid dsn exit", out)

	tun := bootServer(t, ServerOpts{
		DSN:       base,
		ExtraArgs: []string{"--tunnel"},
		Env:       []string{"TUNNEL_GATEWAY_URL=ws://127.0.0.1:1/", "TUNNEL_KEY=" + leakTunnel},
	})
	time.Sleep(1500 * time.Millisecond)
	_, body = httpGet(t, tun.URL+"/readyz")
	record("readyz tunnel", body)

	for _, srv := range []*Server{s, u, w, tun} {
		record("logs", srv.Logs.String())
	}
	for _, secret := range []string{leakPassword, leakWrongPw, leakTunnel} {
		for _, text := range texts {
			if strings.Contains(text, secret) {
				t.Errorf("secret %q leaked in %s", secret, firstLine(text, secret))
			}
		}
	}
	if len(texts) < 20 {
		t.Fatalf("only %d texts collected", len(texts))
	}
}

func firstLine(text, needle string) string {
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, needle) {
			return line
		}
	}
	return text
}

// TestPostgresLargeValuesRoundTrip pushes big and nested values through the
// tool and the MCP transport and checks they arrive intact.
func TestPostgresLargeValuesRoundTrip(t *testing.T) {
	s := bootServer(t, ServerOpts{ExtraArgs: []string{"--max-rows", "5"}})
	out := s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": `
SELECT decode(repeat('ab', 524288), 'hex') AS big_bytea,
       ('[' || repeat('1,', 99999) || '1]')::jsonb AS big_jsonb,
       string_to_array(repeat('x,', 9999) || 'x', ',') AS big_arr,
       ARRAY[ARRAY[1, 2], ARRAY[3, 4]] AS nested,
       decode('00ff10', 'hex') AS bin,
       '{"a":{"b":[1,2,{"c":null}]},"d":"é"}'::jsonb AS nested_json,
       ARRAY['a', NULL, 'b']::text[] AS arr_null,
       ARRAY[]::int[] AS empty_arr,
       ARRAY['{"k":1}'::jsonb, '[true]'::jsonb] AS jsonb_arr,
       repeat('é', 100000) AS big_text`})
	row := rows(t, out)[0]
	cols := columnNames(t, out)
	get := func(name string) any {
		for i, c := range cols {
			if c == name {
				return row[i]
			}
		}
		t.Fatalf("no column %s", name)
		return nil
	}
	if v, _ := get("big_bytea").(string); v != `\x`+strings.Repeat("ab", 524288) {
		t.Fatalf("big_bytea length %d, prefix %q", len(v), v[:min(len(v), 12)])
	}
	if v, _ := get("big_jsonb").([]any); len(v) != 100000 || v[0] != float64(1) || v[99999] != float64(1) {
		t.Fatalf("big_jsonb = %T len %d", get("big_jsonb"), len(v))
	}
	if v, _ := get("big_arr").([]any); len(v) != 10000 || v[0] != "x" || v[9999] != "x" {
		t.Fatalf("big_arr = %T len %d", get("big_arr"), len(v))
	}
	if v := get("nested"); !reflect.DeepEqual(v, []any{[]any{float64(1), float64(2)}, []any{float64(3), float64(4)}}) {
		t.Fatalf("nested = %#v", v)
	}
	if v := get("bin"); v != `\x00ff10` {
		t.Fatalf("bin = %#v", v)
	}
	if v := get("nested_json"); !reflect.DeepEqual(v, map[string]any{"a": map[string]any{"b": []any{float64(1), float64(2), map[string]any{"c": nil}}}, "d": "é"}) {
		t.Fatalf("nested_json = %#v", v)
	}
	if v := get("arr_null"); !reflect.DeepEqual(v, []any{"a", nil, "b"}) {
		t.Fatalf("arr_null = %#v", v)
	}
	if v := get("empty_arr"); !reflect.DeepEqual(v, []any{}) {
		t.Fatalf("empty_arr = %#v", v)
	}
	if v := get("jsonb_arr"); !reflect.DeepEqual(v, []any{map[string]any{"k": float64(1)}, []any{true}}) {
		t.Fatalf("jsonb_arr = %#v", v)
	}
	if v, _ := get("big_text").(string); v != strings.Repeat("é", 100000) {
		t.Fatalf("big_text length %d", len(v))
	}
}

// TestPostgresExplainRejectsWriteStatements checks explain_query never runs
// a mutation, even with analyze=true and even when the table is writable.
func TestPostgresExplainRejectsWriteStatements(t *testing.T) {
	probe := pgProbe(t)
	s := bootServer(t, ServerOpts{WriteTables: []string{"allowed_audit"}, Writes: true})
	before := scalar(t, probe, "SELECT count(*) FROM allowed_audit")
	for sql, want := range map[string]string{
		"INSERT INTO allowed_audit (note) VALUES ('explain')":                       "rejected",
		"UPDATE allowed_audit SET note = 'x'":                                       "rejected",
		"DELETE FROM allowed_audit":                                                 "rejected",
		"WITH d AS (DELETE FROM allowed_audit RETURNING id) SELECT count(*) FROM d": "rejected",
		"SELECT * FROM allowed_audit":                                               "public.allowed_audit",
		"UPDATE allowed_orders SET amount = 0":                                      "rejected",
	} {
		for _, analyze := range []bool{true, false} {
			s.mustReject(t, "explain_query", map[string]any{"sql": sql, "analyze": analyze}, want)
		}
	}
	if after := scalar(t, probe, "SELECT count(*) FROM allowed_audit"); after != before {
		t.Fatalf("explain_query changed allowed_audit: %d -> %d", before, after)
	}
	out := s.mustCall(t, "explain_query", map[string]any{"sql": "SELECT * FROM allowed_orders WHERE id = 1", "analyze": true})
	if _, ok := out["plan"].([]any); !ok {
		t.Fatalf("analyze plan = %T", out["plan"])
	}
}

// TestPostgresToolSchemas checks tools/list renders a description, an object
// input schema with the right required fields, and an output schema.
func TestPostgresToolSchemas(t *testing.T) {
	s := bootServer(t, ServerOpts{WriteTables: []string{"allowed_audit"}, Writes: true, AnyReadiness: true})
	res, err := s.Session.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	wantRequired := map[string][]string{
		"execute_sql_readonly": {"sql"},
		"explain_query":        {"sql"},
		"list_schemas":         {},
		"list_objects":         {"schema"},
		"get_object_details":   {"schema", "name"},
		"begin_transaction":    {},
		"execute_sql_write":    {"transaction_id", "sql"},
		"commit_transaction":   {"transaction_id"},
		"rollback_transaction": {"transaction_id"},
	}
	wantOptional := map[string][]string{
		"execute_sql_readonly": {"max_rows"},
		"explain_query":        {"analyze", "hypothetical_indexes"},
		"list_objects":         {"object_type"},
		"execute_sql_write":    {"max_rows"},
	}
	seen := map[string]bool{}
	for _, tool := range res.Tools {
		seen[tool.Name] = true
		want, ok := wantRequired[tool.Name]
		if !ok {
			t.Errorf("unexpected tool %s", tool.Name)
			continue
		}
		if len(tool.Description) < 20 {
			t.Errorf("%s: description too short: %q", tool.Name, tool.Description)
		}
		in := schemaMap(t, tool.InputSchema)
		if in["type"] != "object" {
			t.Errorf("%s: input schema type = %v", tool.Name, in["type"])
		}
		var required []string
		for _, r := range asSlice(in["required"]) {
			required = append(required, fmt.Sprint(r))
		}
		sortStrings(required)
		wantSorted := append([]string{}, want...)
		sortStrings(wantSorted)
		if !reflect.DeepEqual(required, wantSorted) && !(len(required) == 0 && len(wantSorted) == 0) {
			t.Errorf("%s: required = %v, want %v", tool.Name, required, wantSorted)
		}
		props, _ := in["properties"].(map[string]any)
		for _, name := range append(append([]string{}, want...), wantOptional[tool.Name]...) {
			p, ok := props[name].(map[string]any)
			if !ok {
				t.Errorf("%s: property %s missing from input schema", tool.Name, name)
				continue
			}
			if d, _ := p["description"].(string); d == "" {
				t.Errorf("%s: property %s has no description", tool.Name, name)
			}
		}
		if tool.OutputSchema == nil {
			t.Errorf("%s: no output schema", tool.Name)
		} else if out := schemaMap(t, tool.OutputSchema); out["type"] != "object" {
			t.Errorf("%s: output schema type = %v", tool.Name, out["type"])
		}
	}
	for name := range wantRequired {
		if !seen[name] {
			t.Errorf("tool %s not listed", name)
		}
	}
	// The server enforces the schema: a missing required field is a tool error.
	s.mustReject(t, "execute_sql_readonly", map[string]any{}, "sql")
	s.mustReject(t, "get_object_details", map[string]any{"schema": "public"}, "name")
}

func schemaMap(t *testing.T, v any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal schema: %v", err)
	}
	m := map[string]any{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("schema is not an object: %v", err)
	}
	return m
}

func asSlice(v any) []any {
	s, _ := v.([]any)
	return s
}

var _ = mcp.Tool{}
