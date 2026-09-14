package e2e

import (
	"reflect"
	"strings"
	"testing"
)

var readToolNames = []string{
	"execute_sql_readonly", "explain_query", "get_object_details", "list_objects", "list_schemas",
}

var writeToolNames = []string{
	"begin_transaction", "commit_transaction", "execute_sql_write", "rollback_transaction",
}

func allToolNames() []string {
	names := append([]string{}, readToolNames...)
	names = append(names, writeToolNames...)
	sortStrings(names)
	return names
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func TestCommonBootRejectsBadFlags(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"unknown dialect", []string{"--dialect", "mysql", "--dsn", "x", "--read-tables", "a"}, "--dialect"},
		{"missing dialect", []string{"--dsn", "x", "--read-tables", "a"}, "--dialect"},
		{"missing dsn", []string{"--dialect", "postgres", "--read-tables", "a"}, "--dsn"},
		{"missing read tables", []string{"--dialect", "postgres", "--dsn", "x"}, "--read-tables"},
		{"unparsable table", []string{"--dialect", "postgres", "--dsn", "x", "--read-tables", "a.b.c"}, "--read-tables"},
		{"unterminated quote", []string{"--dialect", "postgres", "--dsn", "x", "--read-tables", `"a`}, "--read-tables"},
		{"write tools on clickhouse", []string{"--dialect", "clickhouse", "--dsn", "x", "--read-tables", "a", "--write-tables", "b", "--dangerously-add-write-tools"}, "clickhouse"},
		{"write tools without write tables", []string{"--dialect", "postgres", "--dsn", "x", "--read-tables", "a", "--dangerously-add-write-tools"}, "--write-tables"},
		{"tunnel without env", []string{"--dialect", "postgres", "--dsn", "x", "--read-tables", "a", "--tunnel"}, "--tunnel"},
		{"bad transport", []string{"--dialect", "postgres", "--dsn", "x", "--read-tables", "a", "--transport", "grpc"}, "--transport"},
		{"bad log level", []string{"--dialect", "postgres", "--dsn", "x", "--read-tables", "a", "--log-level", "loud"}, "--log-level"},
		{"unknown flag", []string{"--dialect", "postgres", "--dsn", "x", "--read-tables", "a", "--bogus"}, "bogus"},
		{"zero max rows", []string{"--dialect", "postgres", "--dsn", "x", "--read-tables", "a", "--max-rows", "0"}, "--max-rows"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, stderr := bootServerExpectExit(t, tc.args)
			if code != 2 {
				t.Fatalf("exit code = %d, want 2; stderr: %s", code, stderr)
			}
			if !strings.Contains(stderr, tc.want) {
				t.Fatalf("stderr %q does not mention %q", stderr, tc.want)
			}
		})
	}
}

func TestCommonHelpExitsZero(t *testing.T) {
	code, stderr := bootServerExpectExit(t, []string{"--help"})
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %s", code, stderr)
	}
	if !strings.Contains(stderr, "--read-tables") && !strings.Contains(stderr, "-read-tables") {
		t.Fatalf("usage does not list flags: %s", stderr)
	}
}

func TestPostgresHealthzReadyz(t *testing.T) {
	s := bootServer(t, ServerOpts{Dialect: "postgres"})
	status, body := httpGet(t, s.URL+"/healthz")
	if status != 200 || !strings.Contains(body, `"ok"`) {
		t.Fatalf("/healthz = %d %s", status, body)
	}
	status, body = httpGet(t, s.URL+"/readyz")
	if status != 200 || !strings.Contains(body, `"ready":true`) {
		t.Fatalf("/readyz = %d %s", status, body)
	}
	if !strings.Contains(body, `"tunnel":"disabled"`) {
		t.Fatalf("/readyz body should report tunnel disabled: %s", body)
	}
}

func TestPostgresReadyzFalseWhenTableMissing(t *testing.T) {
	s := bootServer(t, ServerOpts{Dialect: "postgres", ReadTables: []string{"allowed_orders", "nope"}, ExpectReady: boolPtr(false)})
	status, body := httpGet(t, s.URL+"/readyz")
	if status != 503 || !strings.Contains(body, `"ready":false`) || !strings.Contains(body, "public.nope") {
		t.Fatalf("/readyz = %d %s", status, body)
	}
	status, _ = httpGet(t, s.URL+"/healthz")
	if status != 200 {
		t.Fatalf("/healthz = %d, want 200 even when not ready", status)
	}
}

func TestPostgresReadyzFalseWhenDBUnreachable(t *testing.T) {
	s := bootServer(t, ServerOpts{
		Dialect:     "postgres",
		DSN:         "postgres://postgres:postgres@127.0.0.1:1/app?sslmode=disable&connect_timeout=1",
		ExpectReady: boolPtr(false),
	})
	status, body := httpGet(t, s.URL+"/readyz")
	if status != 503 || !strings.Contains(body, "ping") {
		t.Fatalf("/readyz = %d %s", status, body)
	}
	if strings.Contains(body, "postgres:postgres@") {
		t.Fatalf("/readyz leaks the DSN: %s", body)
	}
}

func TestPostgresToolListWithoutWriteFlag(t *testing.T) {
	s := bootServer(t, ServerOpts{Dialect: "postgres"})
	if got := s.toolNames(t); !reflect.DeepEqual(got, readToolNames) {
		t.Fatalf("tools = %v, want %v", got, readToolNames)
	}
}

func TestPostgresToolListWithWriteFlag(t *testing.T) {
	s := bootServer(t, ServerOpts{Dialect: "postgres", WriteTables: []string{"allowed_audit"}, Writes: true})
	if got := s.toolNames(t); !reflect.DeepEqual(got, allToolNames()) {
		t.Fatalf("tools = %v, want %v", got, allToolNames())
	}
}

func TestClickHouseToolList(t *testing.T) {
	s := bootServer(t, ServerOpts{Dialect: "clickhouse"})
	if got := s.toolNames(t); !reflect.DeepEqual(got, readToolNames) {
		t.Fatalf("tools = %v, want %v", got, readToolNames)
	}
}

func TestClickHouseWriteFlagRejectedAtBoot(t *testing.T) {
	code, stderr := bootServerExpectExit(t, []string{"--dialect", "clickhouse", "--dsn", chDSN(), "--read-tables", "allowed_orders", "--write-tables", "allowed_audit", "--dangerously-add-write-tools"})
	if code != 2 || !strings.Contains(stderr, "clickhouse") {
		t.Fatalf("exit=%d stderr=%q", code, stderr)
	}
}

func TestClickHouseHealthzReadyz(t *testing.T) {
	s := bootServer(t, ServerOpts{Dialect: "clickhouse"})
	status, body := httpGet(t, s.URL+"/readyz")
	if status != 200 || !strings.Contains(body, `"ready":true`) {
		t.Fatalf("/readyz = %d %s", status, body)
	}
}

func TestClickHouseReadyzFalseWhenTableMissing(t *testing.T) {
	s := bootServer(t, ServerOpts{Dialect: "clickhouse", ReadTables: []string{"allowed_orders", "nope"}, ExpectReady: boolPtr(false)})
	status, body := httpGet(t, s.URL+"/readyz")
	if status != 503 || !strings.Contains(body, "app.nope") {
		t.Fatalf("/readyz = %d %s", status, body)
	}
}
