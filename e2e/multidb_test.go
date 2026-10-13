package e2e

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/speakeasy-api/gram-restricted-sql-mcp/internal/dbsec"
)

// dsnForDatabase points the e2e superuser DSN at another database.
func dsnForDatabase(t *testing.T, database string) string {
	t.Helper()
	u, err := url.Parse(pgDSN())
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + database
	return u.String()
}

func roleExists(t *testing.T, c *pgx.Conn, role string) bool {
	t.Helper()
	return queryBool(t, c, "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = $1)", role)
}

// eventually retries f until it returns "" or the deadline passes, then
// fails with the last reason.
func eventually(t *testing.T, what string, f func() string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		reason := f()
		if reason == "" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %s", what, reason)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// TestPostgresMultiDatabase serves two databases of one server with
// --databases, from a non-superuser bootstrap in static wildcard mode with
// connection-level security, and covers routing, per-database policies and
// roles, transactions pinned to their database, connection loss, and
// teardown when a database is dropped.
func TestPostgresMultiDatabase(t *testing.T) {
	ctx := context.Background()
	su := superuserConn(t)
	stamp := time.Now().UnixNano()
	prefix := fmt.Sprintf("e2e_multi_%d_", stamp)
	dbA, dbB := prefix+"a", prefix+"b"
	const schema = "multi"
	bootstrap := fmt.Sprintf("bootstrap_multi_%d", stamp)
	rolePrefix := fmt.Sprintf("rsqlmulti%d", stamp%1000000)
	rolesA := []string{rolePrefix + "_ro", rolePrefix + "_rw"}
	prefixB := dbsec.DatabaseRolePrefix(rolePrefix, dbB)
	rolesB := []string{prefixB + "_ro", prefixB + "_rw"}

	exec := func(c *pgx.Conn, sql string) {
		t.Helper()
		if _, err := c.Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	exec(su, "CREATE ROLE "+bootstrap+" LOGIN CREATEROLE NOSUPERUSER PASSWORD 'bootstrap-pw'")
	// Cleanups run last-in first-out: the server is killed first (bootServer),
	// then the databases are dropped, then the roles.
	t.Cleanup(func() {
		for _, role := range append(append(append([]string{}, rolesA...), rolesB...), bootstrap) {
			if _, err := su.Exec(ctx, "DROP ROLE IF EXISTS "+pgx.Identifier{role}.Sanitize()); err != nil {
				t.Errorf("drop role %s: %v", role, err)
			}
		}
	})
	t.Cleanup(func() {
		for _, database := range []string{dbA, dbB} {
			if _, err := su.Exec(ctx, "DROP DATABASE IF EXISTS "+database+" WITH (FORCE)"); err != nil {
				t.Errorf("drop database %s: %v", database, err)
			}
		}
	})
	for _, database := range []string{dbA, dbB} {
		exec(su, "CREATE DATABASE "+database)
		c, err := pgx.Connect(ctx, dsnForDatabase(t, database))
		if err != nil {
			t.Fatal(err)
		}
		exec(c, strings.ReplaceAll(postgresAnnotationFixture, "__SCHEMA__", schema))
		exec(c, "INSERT INTO "+schema+".owners (id, label) VALUES (100, 'marker-"+database+"')")
		if database == dbB {
			exec(c, "CREATE TABLE "+schema+".only_b (id integer)")
		}
		for _, sql := range []string{
			"GRANT USAGE ON SCHEMA " + schema + " TO " + bootstrap + " WITH GRANT OPTION",
			"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA " + schema + " TO " + bootstrap + " WITH GRANT OPTION",
			"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA " + schema + " TO " + bootstrap + " WITH GRANT OPTION",
		} {
			exec(c, sql)
		}
		_ = c.Close(ctx)
	}

	u, err := url.Parse(dsnForDatabase(t, dbA))
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(bootstrap, "bootstrap-pw")
	s := bootServer(t, ServerOpts{
		Dialect:     "postgres",
		DSN:         u.String(),
		ReadTables:  []string{schema + ".*"},
		WriteTables: []string{schema + ".*"},
		Writes:      true,
		ExtraArgs: []string{"--default-schema", schema, "--connection-level-security",
			"--security-role-prefix", rolePrefix, "--databases", "^" + prefix},
	})

	if !contains(s.toolNames(t), "list_databases") {
		t.Fatalf("list_databases not registered: %v", s.toolNames(t))
	}
	listed := func() map[string]bool {
		t.Helper()
		out := s.mustCall(t, "list_databases", nil)
		names := map[string]bool{}
		for _, d := range out["databases"].([]any) {
			m := d.(map[string]any)
			names[fmt.Sprint(m["name"])] = m["default"] == true
		}
		return names
	}
	if got := listed(); len(got) != 2 || !got[dbA] || got[dbB] {
		t.Fatalf("list_databases = %v, want %s (default) and %s", got, dbA, dbB)
	}

	marker := func(database string) string {
		t.Helper()
		args := map[string]any{"sql": "SELECT label FROM owners WHERE id = 100"}
		if database != "" {
			args["database"] = database
		}
		r := rows(t, s.mustCall(t, "execute_sql_readonly", args))
		if len(r) != 1 {
			t.Fatalf("marker in %q: %v", database, r)
		}
		return fmt.Sprint(r[0][0])
	}
	if got := marker(""); got != "marker-"+dbA {
		t.Fatalf("default database marker = %q", got)
	}
	if got := marker(dbB); got != "marker-"+dbB {
		t.Fatalf("database b marker = %q", got)
	}
	// Both databases now have their own provisioned roles; provisioning b
	// must not have rotated a's passwords or grants out from under it.
	for _, role := range append(append([]string{}, rolesA...), rolesB...) {
		if !roleExists(t, su, role) {
			t.Fatalf("role %s not provisioned", role)
		}
	}
	if got := marker(dbA); got != "marker-"+dbA {
		t.Fatalf("database a marker after b provisioned = %q", got)
	}
	if got := marker(dbB); got != "marker-"+dbB {
		t.Fatalf("database b marker after both provisioned = %q", got)
	}

	// Each database has its own policy, expanded from its own schemas.
	s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT id FROM only_b", "database": dbB})
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT id FROM only_b"}, "allowlist")
	objects := s.mustCall(t, "list_objects", map[string]any{"schema": schema, "database": dbB})
	if !strings.Contains(fmt.Sprint(objects), "only_b") {
		t.Fatalf("list_objects in b misses only_b: %v", objects)
	}
	if objects := s.mustCall(t, "list_objects", map[string]any{"schema": schema}); strings.Contains(fmt.Sprint(objects), "only_b") {
		t.Fatalf("list_objects in a shows only_b: %v", objects)
	}
	s.mustCall(t, "get_object_details", map[string]any{"schema": schema, "name": "only_b", "database": dbB})
	s.mustCall(t, "explain_query", map[string]any{"sql": "SELECT id FROM only_b", "database": dbB})
	s.mustCall(t, "list_schemas", map[string]any{"database": dbB})

	// A column added after b was opened becomes resolvable once the column
	// snapshot is refreshed (periodically, and by list_databases).
	addColumn, err := pgx.Connect(ctx, dsnForDatabase(t, dbB))
	if err != nil {
		t.Fatal(err)
	}
	exec(addColumn, "ALTER TABLE "+schema+".owners ADD COLUMN extra integer DEFAULT 5")
	_ = addColumn.Close(ctx)
	listed()
	if r := rows(t, s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT o.extra FROM owners o WHERE o.id = 100", "database": dbB})); fmt.Sprint(r[0][0]) != "5" {
		t.Fatalf("new column in b = %v", r)
	}

	// Unknown databases are rejected, whether or not they match the pattern.
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT 1", "database": "postgres"}, "unknown database")
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT 1", "database": prefix + "missing"}, "unknown database")
	s.mustReject(t, "begin_transaction", map[string]any{"database": prefix + "missing"}, "unknown database")

	// A transaction stays in the database it was begun in: the write tools
	// take no database argument and the write lands in a, not b.
	begun := s.mustCall(t, "begin_transaction", map[string]any{"database": dbA})
	id, _ := begun["transaction_id"].(string)
	if begun["database"] != dbA {
		t.Fatalf("begin_transaction database = %v", begun["database"])
	}
	if _, errText := s.call(t, "execute_sql_write", map[string]any{"transaction_id": id, "database": dbB,
		"sql": "INSERT INTO owners (id, label) VALUES (300, 'x')"}); errText == "" {
		t.Fatal("execute_sql_write accepted a database argument")
	}
	s.mustCall(t, "execute_sql_write", map[string]any{"transaction_id": id, "sql": "INSERT INTO owners (id, label) VALUES (300, 'from-a-txn')"})
	// only_b is b's table; a transaction in a is checked against a's policy.
	s.mustReject(t, "execute_sql_write", map[string]any{"transaction_id": id, "sql": "INSERT INTO only_b (id) VALUES (1)"}, "allowlist")
	s.mustCall(t, "commit_transaction", map[string]any{"transaction_id": id})
	count := func(database string) int {
		t.Helper()
		r := rows(t, s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT count(*) FROM owners WHERE id = 300", "database": database}))
		return int(r[0][0].(float64))
	}
	if a, b := count(dbA), count(dbB); a != 1 || b != 0 {
		t.Fatalf("row 300: a=%d b=%d, want 1 and 0", a, b)
	}
	// A transaction in b writes to b.
	begun = s.mustCall(t, "begin_transaction", map[string]any{"database": dbB})
	idB, _ := begun["transaction_id"].(string)
	s.mustCall(t, "execute_sql_write", map[string]any{"transaction_id": idB, "sql": "INSERT INTO only_b (id) VALUES (7)"})
	s.mustCall(t, "commit_transaction", map[string]any{"transaction_id": idB})
	if r := rows(t, s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT count(*) FROM only_b", "database": dbB})); r[0][0].(float64) != 1 {
		t.Fatalf("only_b count = %v", r)
	}

	// Terminated backends are a connection loss, not a dropped database:
	// queries recover and nothing is evicted.
	for _, database := range []string{dbA, dbB} {
		exec(su, "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '"+database+"' AND pid <> pg_backend_pid()")
	}
	for _, database := range []string{dbA, dbB} {
		eventually(t, "query after pg_terminate_backend in "+database, func() string {
			_, errText := s.call(t, "execute_sql_readonly", map[string]any{"sql": "SELECT label FROM owners WHERE id = 100", "database": database})
			return errText
		})
	}
	for _, role := range append(append([]string{}, rolesA...), rolesB...) {
		if !roleExists(t, su, role) {
			t.Fatalf("role %s dropped after pg_terminate_backend", role)
		}
	}
	if got := listed(); len(got) != 2 {
		t.Fatalf("list_databases after pg_terminate_backend = %v", got)
	}

	// A transaction left open in b is rolled back when b is dropped.
	// The write pool may still hold a terminated connection; it recovers too.
	var openB string
	eventually(t, "begin_transaction after pg_terminate_backend in b", func() string {
		out, errText := s.call(t, "begin_transaction", map[string]any{"database": dbB})
		openB, _ = out["transaction_id"].(string)
		return errText
	})

	exec(su, "DROP DATABASE "+dbB+" WITH (FORCE)")
	eventually(t, "database b reported unknown after DROP DATABASE", func() string {
		_, errText := s.call(t, "execute_sql_readonly", map[string]any{"sql": "SELECT 1", "database": dbB})
		if !strings.Contains(errText, "unknown database") {
			return "last error: " + errText
		}
		return ""
	})
	if got := marker(""); got != "marker-"+dbA {
		t.Fatalf("database a marker after b dropped = %q", got)
	}
	if got := listed(); len(got) != 1 || !got[dbA] {
		t.Fatalf("list_databases after b dropped = %v", got)
	}
	s.mustReject(t, "execute_sql_write", map[string]any{"transaction_id": openB, "sql": "INSERT INTO owners (id, label) VALUES (400, 'x')"}, "unknown")
	s.mustReject(t, "begin_transaction", map[string]any{"database": dbB}, "unknown database")
	eventually(t, "roles of b dropped", func() string {
		for _, role := range rolesB {
			if roleExists(t, su, role) {
				return "role " + role + " still exists"
			}
		}
		return ""
	})
	for _, role := range rolesA {
		if !roleExists(t, su, role) {
			t.Fatalf("role %s of the default database dropped", role)
		}
	}
	if logs := s.Logs.String(); !strings.Contains(logs, `"database":"`+dbB+`"`) || !strings.Contains(logs, "roles of evicted database dropped") {
		t.Fatalf("logs lack the database name or the role drop outcome:\n%s", logs)
	}
}
