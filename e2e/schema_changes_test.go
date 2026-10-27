package e2e

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestClickHouseReadyzToleratesSchemaChanges(t *testing.T) {
	table := uniqueName("e2e_schema")
	chExecAnnotation(t, "CREATE TABLE app."+table+" (id Int32, legacy String) ENGINE=MergeTree ORDER BY id")
	t.Cleanup(func() { chExecAnnotation(t, "DROP TABLE IF EXISTS app."+table+" SYNC") })
	s := chServer(t, ServerOpts{ReadTables: []string{"allowed_orders", table}})
	s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT id FROM " + table})
	chExecAnnotation(t, "ALTER TABLE app."+table+" DROP COLUMN legacy, ADD COLUMN replacement Int32 DEFAULT 7")
	waitReadyz(t, s.URL, 200, 5*time.Second)
	s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT replacement FROM " + table})
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT legacy FROM " + table}, "")
	chExecAnnotation(t, "DROP TABLE app."+table+" SYNC")
	waitReadyz(t, s.URL, 200, 5*time.Second)
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT id FROM " + table}, "")
	s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT id FROM allowed_orders"})
}

func TestPostgresHealthListenerIsProbeOnly(t *testing.T) {
	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	s := bootServer(t, ServerOpts{ExtraArgs: []string{"--health-listen", addr}})
	for path, want := range map[string]int{"/healthz": 200, "/readyz": 200, "/mcp": 404, "/": 404} {
		if status, body := httpGet(t, "http://"+addr+path); status != want {
			t.Fatalf("health listener %s = %d %s, want %d", path, status, body, want)
		}
	}
	s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT id FROM allowed_orders"})
}

// Reuse a static policy across fresh server processes: provisioning must omit
// tables deleted since that policy was configured, including owned sequences.
func TestPostgresReprovisionAfterTableDrop(t *testing.T) {
	c, schema := annotationPG(t)
	for _, sql := range []string{
		"CREATE TABLE " + schema + ".retired (id serial PRIMARY KEY)",
		"CREATE TABLE " + schema + ".survivor (id serial PRIMARY KEY)",
		"CREATE TABLE " + schema + ".outside_policy (id int)",
	} {
		execSQL(t, c, sql)
	}
	prefix := uniqueName("rsql_reprovision")
	t.Cleanup(func() {
		for _, suffix := range []string{"_ro", "_rw"} {
			execSQL(t, c, "DROP OWNED BY "+prefix+suffix)
			execSQL(t, c, "DROP ROLE IF EXISTS "+prefix+suffix)
		}
	})
	tables := []string{schema + ".retired", schema + ".survivor"}
	opts := ServerOpts{ReadTables: tables, WriteTables: tables, Writes: true,
		ExtraArgs: []string{"--default-schema", schema, "--connection-level-security", "--security-role-prefix", prefix}}
	checkSurvivor := func(t *testing.T, s *Server) {
		t.Helper()
		s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT id FROM survivor"})
		id := beginTx(t, s)
		s.mustCall(t, "execute_sql_write", map[string]any{"transaction_id": id, "sql": "INSERT INTO survivor DEFAULT VALUES RETURNING id"})
		s.mustCall(t, "rollback_transaction", map[string]any{"transaction_id": id})
		for _, suffix := range []string{"_ro", "_rw"} {
			if queryBool(t, c, "SELECT has_table_privilege($1, $2, 'SELECT')", prefix+suffix, schema+".outside_policy") {
				t.Fatal("provisioning granted a table outside the configured policy")
			}
		}
	}
	t.Run("before drop", func(t *testing.T) {
		s := bootServer(t, opts)
		checkSurvivor(t, s)
		s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT id FROM retired"})
	})
	execSQL(t, c, "DROP TABLE "+schema+".retired")
	t.Run("new process after drop", func(t *testing.T) {
		s := bootServer(t, opts)
		checkSurvivor(t, s)
		s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT id FROM retired"}, "")
	})
	execSQL(t, c, "DROP TABLE "+schema+".survivor")
	t.Run("all configured tables dropped", func(t *testing.T) {
		s := bootServer(t, opts)
		s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT 1"})
		s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT id FROM survivor"}, "")
	})
}

// Missing objects may be skipped, but a present object with insufficient
// bootstrap privileges must not silently disappear from provisioning.
func TestPostgresProvisioningKeepsPermissionFailures(t *testing.T) {
	c, schema := annotationPG(t)
	role := uniqueName("rsql_unprivileged")
	prefix := uniqueName("rsql_denied")
	execSQL(t, c, "CREATE ROLE "+role+" LOGIN CREATEROLE PASSWORD 'synthetic-bootstrap'")
	execSQL(t, c, "GRANT USAGE ON SCHEMA "+schema+" TO "+role+" WITH GRANT OPTION")
	execSQL(t, c, "GRANT SELECT ON "+schema+".owners TO "+role+" WITH GRANT OPTION")
	t.Cleanup(func() {
		// The bootstrap granted privileges onward; revoke that grant chain first.
		execSQL(t, c, "DROP OWNED BY "+role+" CASCADE")
		if queryBool(t, c, "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=$1)", prefix+"_ro") {
			execSQL(t, c, "DROP OWNED BY "+prefix+"_ro")
			execSQL(t, c, "DROP ROLE "+prefix+"_ro")
		}
		execSQL(t, c, "DROP ROLE "+role)
	})
	u, err := url.Parse(pgDSN())
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(role, "synthetic-bootstrap")
	s := bootServer(t, ServerOpts{
		DSN: u.String(), ReadTables: []string{schema + ".records", schema + ".owners"}, ExpectReady: boolPtr(false),
		ExtraArgs: []string{"--connection-level-security", "--security-role-prefix", prefix},
	})
	status, body := httpGet(t, s.URL+"/readyz")
	if status != 503 || !strings.Contains(body, "GRANT SELECT") || !strings.Contains(body, "permission denied") {
		t.Fatalf("expected a real provisioning permission failure, got %d %s", status, body)
	}
	// The same running process must re-read the catalog on its next attempt.
	execSQL(t, c, "DROP TABLE "+schema+".records CASCADE")
	waitReadyz(t, s.URL, 200, 5*time.Second)
	s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT id FROM " + schema + ".owners"})
}
