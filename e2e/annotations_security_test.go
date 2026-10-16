package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/jackc/pgx/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/dbsec"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/policy"
)

func TestAnnotationsFlagValidation(t *testing.T) {
	base := []string{"--dialect", "postgres", "--dsn", pgDSN(), "--columns-from-annotations", "safe", "--connection-level-security"}
	for name, args := range map[string][]string{
		"uppercase class":       append(append([]string{}, base...), "--columns-from-annotations", "Safe"),
		"malformed class":       append(append([]string{}, base...), "--columns-from-annotations", "safe,opaque_restricted"),
		"empty selection":       append(append([]string{}, base...), "--columns-from-annotations", ""),
		"static allowlist":      append(append([]string{}, base...), "--read-tables", "records"),
		"write table":           append(append([]string{}, base...), "--write-tables", "records"),
		"write tools":           append(append([]string{}, base...), "--dangerously-add-write-tools"),
		"missing column grants": base[:len(base)-1],
		"invalid refresh":       append(append([]string{}, base...), "--annotation-refresh-interval", "0s"),
	} {
		t.Run(name, func(t *testing.T) {
			if code, text := bootServerExpectExit(t, args); code != 2 {
				t.Fatalf("exit=%d %s", code, text)
			}
		})
	}
}
func TestPostgresAnnotationsColdFailureDeniesTools(t *testing.T) {
	o := annotationOpts("public", "safe")
	o.DSN = "postgres://postgres:postgres@127.0.0.1:1/app?sslmode=disable"
	o.ExpectReady = boolPtr(false)
	s := bootServer(t, o)
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT 1"}, "unavailable")
	s.mustReject(t, "explain_query", map[string]any{"sql": "SELECT 1"}, "unavailable")
	if names := s.toolNames(t); contains(names, "begin_transaction") {
		t.Fatal(names)
	}
}
func annotationServerRole(t *testing.T, s *Server) string {
	t.Helper()
	role := ""
	for _, line := range strings.Split(s.Logs.String(), "\n") {
		var entry map[string]any
		if json.Unmarshal([]byte(line), &entry) == nil {
			if r, ok := entry["read_role"].(string); ok {
				role = r
			}
		}
	}
	if role == "" {
		t.Fatal("missing provisioned role in logs")
	}
	return role
}
func TestPostgresAnnotationsEffectiveGrantsAndRecovery(t *testing.T) {
	c, schema := annotationPG(t)
	s := bootServer(t, annotationOpts(schema, "safe"))
	role := annotationServerRole(t, s)
	if queryBool(t, c, "SELECT has_table_privilege($1,$2,'SELECT')", role, schema+".records") {
		t.Fatal("table-wide SELECT was granted")
	}
	for _, name := range []string{"id", "amount", "content", "secret", "legacy"} {
		want := name == "id" || name == "amount"
		if got := queryBool(t, c, "SELECT has_column_privilege($1,$2,$3,'SELECT')", role, schema+".records", name); got != want {
			t.Fatalf("%s=%v", name, got)
		}
	}
	if _, err := c.Exec(context.Background(), "GRANT SELECT ON "+schema+".records TO PUBLIC"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = c.Exec(context.Background(), "REVOKE SELECT ON "+schema+".records FROM PUBLIC") })
	if status, _ := refreshReadyz(t, s); status != 503 {
		t.Fatalf("broader PUBLIC access not detected: %d", status)
	}
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT id FROM records"}, "unavailable")
	if _, err := c.Exec(context.Background(), "REVOKE SELECT ON "+schema+".records FROM PUBLIC"); err != nil {
		t.Fatal(err)
	}
	if status, body := refreshReadyz(t, s); status != 200 {
		t.Fatalf("recovery: %d %s", status, body)
	}
	s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT id FROM records"})
	if _, err := c.Exec(context.Background(), "GRANT UPDATE(amount) ON "+schema+".records TO "+pgx.Identifier{role}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	if status, _ := refreshReadyz(t, s); status != 503 {
		t.Fatalf("excess write privilege not detected: %d", status)
	}
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT id FROM records"}, "unavailable")
	// A failed audit closes admission; the next complete reconciliation repairs
	// drift on this process's own role, without changing unrelated PUBLIC grants.
	if status, body := refreshReadyz(t, s); status != 200 {
		t.Fatalf("repair: %d %s", status, body)
	}
	if queryBool(t, c, "SELECT has_column_privilege($1,$2,'amount','UPDATE')", role, schema+".records") {
		t.Fatal("excess write grant survived reconciliation")
	}
}
func TestPostgresAnnotationsBuiltinShadowing(t *testing.T) {
	c, schema := annotationPG(t)
	sql := fmt.Sprintf(`CREATE FUNCTION %s.lower(text) RETURNS text LANGUAGE sql SECURITY DEFINER AS $$SELECT 'SENSITIVE_UDF'::text$$;
 CREATE FUNCTION %s.add_fake(integer,integer) RETURNS integer LANGUAGE sql SECURITY DEFINER AS $$SELECT 777$$;
 CREATE OPERATOR %s.+ (LEFTARG=integer,RIGHTARG=integer,FUNCTION=%s.add_fake);`, schema, schema, schema, schema)
	if _, err := c.Exec(context.Background(), sql); err != nil {
		t.Fatal(err)
	}
	s := bootServer(t, annotationOpts(schema, "safe"))
	out := s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT lower('ABC'),id+1 FROM records ORDER BY id"})
	got := rows(t, out)
	if got[0][0] != "abc" || got[0][1] != float64(2) {
		t.Fatalf("custom routine/operator invoked: %v", got)
	}
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT " + schema + ".lower('ABC')"}, "schema-qualified")
}
func TestClickHouseAnnotationsRejectUserFunctionSpelling(t *testing.T) {
	const name = "aRrAyMaP"
	if lines := chLines(t, "SELECT count() FROM system.functions WHERE name='"+name+"'"); len(lines) != 1 || lines[0] != "0" {
		t.Skip("probe function name already exists")
	}
	chExecAnnotation(t, "CREATE FUNCTION "+name+" AS (xs) -> 'SENSITIVE_UDF'")
	t.Cleanup(func() { chExecAnnotation(t, "DROP FUNCTION "+name) })
	schema := annotationCH(t)
	s := bootServer(t, annotationCHOpts(schema, "safe"))
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT " + name + "(tags) FROM records"}, "approved built-in")
	s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT arrayMap(x -> x+1,tags) AS values FROM records"})
}
func TestPostgresAnnotationsCancelInflightQuery(t *testing.T) {
	c, schema := annotationPG(t)
	if _, err := c.Exec(context.Background(), "INSERT INTO "+schema+".records(id,amount) SELECT x,x FROM generate_series(1,1000) x"); err != nil {
		t.Fatal(err)
	}
	o := annotationOpts(schema, "safe")
	o.ExtraArgs = append(o.ExtraArgs, "--statement-timeout", "3s")
	s := bootServer(t, o)
	role := annotationServerRole(t, s)
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		res, err := s.Session.CallTool(ctx, &mcp.CallToolParams{Name: "execute_sql_readonly", Arguments: map[string]any{"sql": "SELECT sum(a.amount+b.amount+c.amount+d.amount) FROM records a CROSS JOIN records b CROSS JOIN records c CROSS JOIN records d"}})
		if err == nil && !res.IsError {
			err = fmt.Errorf("old-generation result was returned")
		}
		done <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for !queryBool(t, c, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename=$1 AND state='active' AND query LIKE '%CROSS JOIN%')", role) {
		if time.Now().After(deadline) {
			t.Fatal("query did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := c.Exec(context.Background(), "COMMENT ON COLUMN "+schema+".records.amount IS '@access: content'"); err != nil {
		t.Fatal(err)
	}
	if status, body := refreshReadyz(t, s); status != 200 {
		t.Fatalf("refresh while query active: %d %s", status, body)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("query did not cancel")
	}
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT amount FROM records"}, "content")
}
func TestAnnotationsDirectDatabaseCredentials(t *testing.T) {
	for _, dialect := range []policy.Dialect{policy.Postgres, policy.ClickHouse} {
		t.Run(string(dialect), func(t *testing.T) {
			var schema string
			var source dbsec.AnnotationSource
			prefix, err := dbsec.AnnotationRolePrefix("e2e_annotation_direct")
			if err != nil {
				t.Fatal(err)
			}
			if dialect == policy.Postgres {
				_, schema = annotationPG(t)
				source = &dbsec.PostgresAnnotations{DSN: pgDSN(), Prefix: prefix}
			} else {
				schema = annotationCH(t)
				source = &dbsec.ClickHouseAnnotations{DSN: chDSN(), Prefix: prefix}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			catalog, err := source.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			pol := (&policy.Policy{Dialect: dialect, DefaultSchema: schema, AnnotationTiers: map[policy.Tier]bool{policy.Tier("safe"): true}, StatementTimeout: time.Second, MaxRows: 100}).WithCatalog(catalog)
			creds, err := source.Reconcile(ctx, pol)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := source.Close(ctx); err != nil {
					t.Error(err)
				}
			})
			if dialect == policy.Postgres {
				conn, err := pgx.Connect(ctx, creds.ReadDSN)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close(context.Background())
				var count int64
				if err := conn.QueryRow(ctx, "SELECT count(*) FROM "+schema+".records").Scan(&count); err != nil || count != 2 {
					t.Fatalf("count=%d err=%v", count, err)
				}
				for _, sql := range []string{"SELECT secret FROM " + schema + ".records", "SELECT * FROM " + schema + ".records", "SELECT count(*) FROM " + schema + ".closed"} {
					if _, err := conn.Exec(ctx, sql); err == nil {
						t.Fatalf("direct role permitted %s", sql)
					}
				}
			} else {
				directCtx, directCancel := context.WithCancel(context.WithoutCancel(ctx))
				stop := context.AfterFunc(ctx, directCancel)
				defer stop()
				defer directCancel()
				opts, err := clickhouse.ParseDSN(creds.ReadDSN)
				if err != nil {
					t.Fatal(err)
				}
				conn, err := clickhouse.Open(opts)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				var count uint64
				if err := conn.QueryRow(directCtx, "SELECT count(*) FROM "+schema+".records").Scan(&count); err != nil || count != 2 {
					t.Fatalf("count=%d err=%v", count, err)
				}
				for _, sql := range []string{"SELECT secret FROM " + schema + ".records", "SELECT * FROM " + schema + ".records", "SELECT count(*) FROM " + schema + ".closed"} {
					if err := conn.Exec(directCtx, sql); err == nil {
						t.Fatalf("direct role permitted %s", sql)
					}
				}
			}
		})
	}
}
func TestAnnotationsExistingBypassCorpus(t *testing.T) {
	for _, dialect := range []string{"postgres", "clickhouse"} {
		t.Run(dialect, func(t *testing.T) {
			var o ServerOpts
			corpus := append([]string{}, bypassCorpusCommon...)
			if dialect == "postgres" {
				_, schema := annotationPG(t)
				o = annotationOpts(schema, "safe")
				corpus = append(corpus, bypassCorpusPostgres...)
			} else {
				schema := annotationCH(t)
				o = annotationCHOpts(schema, "safe")
				corpus = append(corpus, bypassCorpusClickHouse...)
			}
			s := bootServer(t, o)
			for _, sql := range corpus {
				s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": sql}, "rejected")
			}
		})
	}
}
