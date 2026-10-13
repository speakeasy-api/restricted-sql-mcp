package e2e

import (
	"context"
	_ "embed"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

//go:embed fixtures/postgres-annotations.sql
var postgresAnnotationFixture string

func annotationPG(t *testing.T) (*pgx.Conn, string) {
	t.Helper()
	c := superuserConn(t)
	schema := fmt.Sprintf("annotation_%d", time.Now().UnixNano())
	if _, err := c.Exec(context.Background(), strings.ReplaceAll(postgresAnnotationFixture, "__SCHEMA__", schema)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, err := c.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		if err != nil {
			t.Error(err)
		}
	})
	return c, schema
}
func annotationOpts(schema, tiers string) ServerOpts {
	return ServerOpts{Dialect: "postgres", ReadTables: []string{}, ExtraArgs: []string{"--default-schema", schema, "--columns-from-annotations", tiers, "--connection-level-security", "--annotation-refresh-interval", "1h"}}
}
func TestPostgresAnnotationsReadAndBinding(t *testing.T) {
	_, schema := annotationPG(t)
	s := bootServer(t, annotationOpts(schema, "safe"))
	allow := []string{
		"SELECT id,amount FROM records ORDER BY id",
		"SELECT count(*),count(1),sum(amount) FROM records",
		"SELECT r.id FROM records r WHERE r.amount>0 ORDER BY r.id",
		"WITH c(k) AS (SELECT id FROM records) SELECT k FROM c ORDER BY k",
		"SELECT x.k FROM (SELECT id AS k FROM records) x",
		"SELECT id AS k FROM records ORDER BY k",
		"SELECT amount AS k,count(*) FROM records GROUP BY k ORDER BY k",
		"SELECT r.id,o.label FROM records r JOIN owners o USING(id)",
		"SELECT id FROM records r FULL JOIN owners o USING(id) ORDER BY id",
		"SELECT j.id FROM (records r JOIN owners o USING(id)) j",
		"SELECT r.id FROM records r WHERE EXISTS (SELECT o.id FROM owners o WHERE o.id=r.id)",
		"SELECT r.id,x.id FROM records r CROSS JOIN LATERAL (SELECT r.id) x",
		"SELECT id FROM records UNION SELECT id FROM owners ORDER BY id",
		"SELECT row_number() OVER (PARTITION BY amount ORDER BY id),id FROM records",
		"SELECT count(*) FILTER (WHERE amount>0) FROM records",
		"SELECT tags[1] FROM records",
		"SELECT 1 AS one",
	}
	for _, sql := range allow {
		t.Run(sql, func(t *testing.T) {
			out := s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": sql})
			if strings.Contains(fmt.Sprint(out), "SENSITIVE_") {
				t.Fatal(out)
			}
		})
	}
	deny := map[string]string{
		"SELECT * FROM records":                                           "wildcard",
		"SELECT r.* FROM records r":                                       "wildcard",
		"SELECT * FROM all_safe":                                          "wildcard",
		"SELECT content FROM records":                                     "content",
		"SELECT email FROM records":                                       "pii",
		"SELECT legacy FROM records":                                      "not annotated",
		"SELECT invalid FROM records":                                     "duplicate",
		"SELECT count(content) FROM records":                              "content",
		"SELECT count(*) FROM records WHERE content='x'":                  "content",
		"SELECT id FROM records ORDER BY secret":                          "secret",
		"SELECT count(*) FROM records GROUP BY content":                   "content",
		"SELECT row_number() OVER(PARTITION BY content) FROM records":     "content",
		"WITH c AS (SELECT content AS id FROM records) SELECT id FROM c":  "content",
		"SELECT x.id FROM records AS x(a,b,c,id)":                         "content",
		"SELECT id FROM records r JOIN owners o ON r.content=o.content":   "content",
		"SELECT r.id FROM records r JOIN owners o USING(content)":         "content",
		"SELECT id FROM records NATURAL JOIN owners":                      "NATURAL",
		"SELECT r FROM records r":                                         "whole-row",
		"SELECT to_json(r) FROM records r":                                "whole-row",
		"SELECT (r).* FROM records r":                                     "wildcard",
		"SELECT count(*) FROM closed":                                     "no selectable",
		"SELECT id FROM unsafe_view":                                      "unsupported relation",
		"SELECT echo FROM generated":                                      "generated",
		"SELECT id FROM records JOIN owners ON records.id=owners.id":      "ambiguous",
		"SELECT xmin FROM records":                                        "unknown",
		"SELECT id FROM records WHERE EXISTS(SELECT content FROM owners)": "content",
	}
	for sql, reason := range deny {
		t.Run(sql, func(t *testing.T) { s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": sql}, reason) })
	}
	details := s.mustCall(t, "get_object_details", map[string]any{"schema": schema, "name": "records"})
	if strings.Contains(fmt.Sprint(details), "SENSITIVE_") || !strings.Contains(fmt.Sprint(details), "selectable:false") {
		t.Fatalf("metadata=%v", details)
	}
	if !strings.Contains(fmt.Sprint(details["constraints"]), "referenced_columns:[id]") {
		t.Fatalf("foreign key structure missing: %v", details)
	}
	s.mustCall(t, "get_object_details", map[string]any{"schema": schema, "name": "closed"})
	global := s.mustCall(t, "get_object_details", map[string]any{"schema": "public", "name": "allowed_orders"})
	if global["access"].(map[string]any)["queryable"] != false {
		t.Fatalf("unannotated global metadata: %v", global)
	}
	s.mustCall(t, "explain_query", map[string]any{"sql": "SELECT id FROM records"})
	s.mustReject(t, "explain_query", map[string]any{"sql": "SELECT id FROM records", "hypothetical_indexes": []any{map[string]any{"table": "records", "columns": []string{"secret"}}}}, "secret")
}
func TestPostgresAnnotationsPiiAndMigration(t *testing.T) {
	c, schema := annotationPG(t)
	s := bootServer(t, annotationOpts(schema, "safe,pii"))
	s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT email FROM records"})
	exec := func(sql string) {
		t.Helper()
		if _, err := c.Exec(context.Background(), sql); err != nil {
			t.Fatal(err)
		}
	}
	exec("ALTER TABLE " + schema + ".records ADD COLUMN ssn text DEFAULT 'SENSITIVE_NEW_PHI'")
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT ssn FROM records"}, "unknown")
	if status, body := refreshReadyz(t, s); status != 200 {
		t.Fatalf("refresh: %d %s", status, body)
	}
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT ssn FROM records"}, "not annotated")
	exec("COMMENT ON COLUMN " + schema + ".records.ssn IS '@access: restricted'")
	exec("COMMENT ON COLUMN " + schema + ".records.amount IS '@access: content'")
	if status, body := refreshReadyz(t, s); status != 200 {
		t.Fatalf("refresh: %d %s", status, body)
	}
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT ssn FROM records"}, "restricted")
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT amount FROM records"}, "content")
	role := annotationServerRole(t, s)
	for _, col := range []string{"amount", "ssn"} {
		if queryBool(t, c, "SELECT has_column_privilege($1,$2,$3,'SELECT')", role, schema+".records", col) {
			t.Fatalf("obsolete grant: %s", col)
		}
	}
	s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT id FROM records"})
}

// TestPostgresAnnotationsNonSuperuserBootstrap boots with the production shape:
// a bootstrap role that is not a superuser and does not own the tables, only
// CREATEROLE plus USAGE and SELECT WITH GRANT OPTION. Unrelated objects in the
// database (a sequence it has no rights on) must not stop provisioning.
func TestPostgresAnnotationsNonSuperuserBootstrap(t *testing.T) {
	c, schema := annotationPG(t)
	ctx := context.Background()
	role := fmt.Sprintf("bootstrap_%d", time.Now().UnixNano())
	for _, sql := range []string{
		"CREATE ROLE " + role + " LOGIN CREATEROLE NOSUPERUSER PASSWORD 'bootstrap-pw'",
		"CREATE SEQUENCE " + schema + ".unrelated_seq",
		"GRANT USAGE ON SCHEMA " + schema + " TO " + role + " WITH GRANT OPTION",
		"GRANT SELECT ON ALL TABLES IN SCHEMA " + schema + " TO " + role + " WITH GRANT OPTION",
	} {
		if _, err := c.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, sql := range []string{"DROP OWNED BY " + role, "DROP ROLE " + role} {
			if _, err := c.Exec(ctx, sql); err != nil {
				t.Error(err)
			}
		}
	})
	u, err := url.Parse(pgDSN())
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(role, "bootstrap-pw")
	opts := annotationOpts(schema, "safe")
	opts.DSN = u.String()
	s := bootServer(t, opts)
	s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT id,amount FROM records ORDER BY id"})
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT content FROM records"}, "content")
}
