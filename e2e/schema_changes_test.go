package e2e

import (
	"fmt"
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
