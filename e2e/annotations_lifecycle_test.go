package e2e

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestAnnotationsStdioPeriodicRefresh(t *testing.T) {
	for _, dialect := range []string{"postgres", "clickhouse"} {
		t.Run(dialect, func(t *testing.T) {
			var o ServerOpts
			var retier func()
			if dialect == "postgres" {
				c, schema := annotationPG(t)
				o = annotationOpts(schema, "safe")
				retier = func() {
					if _, err := c.Exec(context.Background(), "COMMENT ON COLUMN "+schema+".records.amount IS '@access: content'"); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				schema := annotationCH(t)
				o = annotationCHOpts(schema, "safe")
				retier = func() { chExecAnnotation(t, "ALTER TABLE "+schema+".records COMMENT COLUMN amount '@access: content'") }
			}
			o.ExtraArgs = append(o.ExtraArgs, "--transport", "stdio", "--annotation-refresh-interval", "250ms")
			cmd := exec.Command(binaryPath, o.args("")...)
			logs := &syncBuffer{}
			cmd.Stderr = logs
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			client := mcp.NewClient(&mcp.Implementation{Name: "annotation-stdio-test", Version: "1"}, nil)
			session, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
			if err != nil {
				t.Fatalf("stdio connect: %v\n%s", err, logs.String())
			}
			t.Cleanup(func() {
				_ = session.Close()
				if t.Failed() {
					t.Log(logs.String())
				}
			})
			s := &Server{Session: session, Logs: logs}
			s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT amount FROM records"})
			retier()
			deadline := time.Now().Add(10 * time.Second)
			for {
				res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "execute_sql_readonly", Arguments: map[string]any{"sql": "SELECT amount FROM records"}})
				if err != nil {
					t.Fatal(err)
				}
				applied := false
				if res.IsError {
					for _, c := range res.Content {
						if txt, ok := c.(*mcp.TextContent); ok && strings.Contains(txt.Text, `tier "content"`) {
							applied = true
						}
					}
				}
				if applied {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("stdio never applied the new tier without a readiness probe")
				}
				time.Sleep(50 * time.Millisecond)
			}
			s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT id FROM records"})
		})
	}
}

func TestClickHouseAnnotationsStoppedMigration(t *testing.T) {
	schema := annotationCH(t)
	var oldRole string
	t.Run("before", func(t *testing.T) {
		s := bootServer(t, annotationCHOpts(schema, "safe"))
		oldRole = annotationServerRole(t, s)
		s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT id,amount FROM records"})
	})
	if lines := chLines(t, "SELECT count() FROM system.users WHERE name='"+oldRole+"'"); len(lines) != 1 || lines[0] != "0" {
		t.Fatal("graceful shutdown did not remove its user")
	}
	for _, sql := range []string{
		"ALTER TABLE " + schema + ".records RENAME COLUMN amount TO previous_amount",
		"ALTER TABLE " + schema + ".records COMMENT COLUMN previous_amount '@access: restricted'",
		"ALTER TABLE " + schema + ".records ADD COLUMN amount String",
		"DROP TABLE " + schema + ".all_safe SYNC",
		"CREATE TABLE " + schema + ".all_safe (id String) ENGINE=Memory",
		"INSERT INTO " + schema + ".all_safe VALUES ('SENSITIVE_RECREATED')",
		"ALTER TABLE " + schema + ".records MODIFY COLUMN id Nullable(String) COMMENT '@access: restricted'",
	} {
		chExecAnnotation(t, sql)
	}
	s := bootServer(t, annotationCHOpts(schema, "safe"))
	role := annotationServerRole(t, s)
	if role == oldRole {
		t.Fatal("user reused across processes")
	}
	for _, col := range []string{"amount", "previous_amount", "id"} {
		s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT " + col + " FROM records"}, "rejected")
	}
	if lines := chLines(t, "SELECT count() FROM system.grants WHERE user_name='"+role+"' AND database='"+schema+"' AND table='records' AND (column IN ('amount','previous_amount','id') OR column IS NULL)"); len(lines) != 1 || lines[0] != "0" {
		t.Fatalf("stale grants: %v", lines)
	}
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT count(*) FROM all_safe"}, "no selectable")
	s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT tags FROM records"})
}

func TestPostgresAnnotationsStoppedMigration(t *testing.T) {
	c, schema := annotationPG(t)
	var oldRole string
	t.Run("before", func(t *testing.T) {
		s := bootServer(t, annotationOpts(schema, "safe"))
		oldRole = annotationServerRole(t, s)
		s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT id,amount FROM records"})
	}) // the server is stopped and drained before changing existing meanings
	if queryBool(t, c, "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)", oldRole) {
		t.Fatal("graceful shutdown did not remove its role")
	}
	ddl := fmt.Sprintf(`ALTER TABLE %s.records RENAME COLUMN amount TO previous_amount;
COMMENT ON COLUMN %s.records.previous_amount IS '@access: restricted';
ALTER TABLE %s.records ADD COLUMN amount text DEFAULT 'SENSITIVE_REUSED_NAME';
DROP TABLE %s.all_safe;
CREATE TABLE %s.all_safe(id text);
INSERT INTO %s.all_safe VALUES ('SENSITIVE_RECREATED');
ALTER TABLE %s.records ALTER COLUMN id TYPE text USING id::text;
COMMENT ON COLUMN %s.records.id IS '@access: restricted';`, schema, schema, schema, schema, schema, schema, schema, schema)
	if _, err := c.Exec(context.Background(), ddl); err != nil {
		t.Fatal(err)
	}
	s := bootServer(t, annotationOpts(schema, "safe"))
	if annotationServerRole(t, s) == oldRole {
		t.Fatal("role reused across processes")
	}
	for _, col := range []string{"amount", "previous_amount", "id"} {
		s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT " + col + " FROM records"}, "rejected")
		if queryBool(t, c, "SELECT has_column_privilege($1,$2,$3,'SELECT')", annotationServerRole(t, s), schema+".records", col) {
			t.Fatalf("stale grant on %s", col)
		}
	}
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT count(*) FROM all_safe"}, "no selectable")
	s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT tags FROM records"})
}

func TestAnnotationsUnsupportedDependencies(t *testing.T) {
	t.Run("postgres", func(t *testing.T) {
		c, schema := annotationPG(t)
		ddl := fmt.Sprintf(`ALTER TABLE %s.all_safe ENABLE ROW LEVEL SECURITY;
CREATE POLICY content_filter ON %s.all_safe USING (id=1);
CREATE DOMAIN %s.custom AS text;
ALTER TABLE %s.records ADD COLUMN custom_value %s.custom;
COMMENT ON COLUMN %s.records.custom_value IS '@access: safe';
CREATE TABLE %s.function_index(id integer);
COMMENT ON COLUMN %s.function_index.id IS '@access: safe';
CREATE FUNCTION %s.bump(integer) RETURNS integer LANGUAGE sql IMMUTABLE AS 'SELECT $1+1';
CREATE INDEX ON %s.function_index (%s.bump(id));`, schema, schema, schema, schema, schema, schema, schema, schema, schema, schema, schema)
		if _, err := c.Exec(context.Background(), ddl); err != nil {
			t.Fatal(err)
		}
		s := bootServer(t, annotationOpts(schema, "safe"))
		s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT id FROM all_safe"}, "unsupported relation")
		s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT custom_value FROM records"}, "unsupported column type")
		s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT count(*) FROM function_index"}, "unsupported relation")
	})
	t.Run("clickhouse", func(t *testing.T) {
		schema := annotationCH(t)
		chExecAnnotation(t, "CREATE TABLE "+schema+".dynamic (id UInt64 COMMENT '@access: safe', payload Array(JSON) COMMENT '@access: safe') ENGINE=Memory")
		chExecAnnotation(t, "CREATE ROW POLICY annotation_filter ON "+schema+".all_safe USING id=1 TO ALL")
		t.Cleanup(func() { chExecAnnotation(t, "DROP ROW POLICY IF EXISTS annotation_filter ON "+schema+".all_safe") })
		s := bootServer(t, annotationCHOpts(schema, "safe"))
		s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT id FROM all_safe"}, "row policies")
		s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT payload FROM dynamic"}, "dynamic")
	})
}
