package e2e

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// A user-defined cast between built-in types is resolved by type OID, so the
// pg_catalog search path cannot keep its function out of a query. Annotation
// mode must refuse to serve while such a cast exists, and recover once it is
// removed.
func TestAnnotationsRefuseUserDefinedCasts(t *testing.T) {
	c, schema := annotationPG(t)
	ctx := context.Background()
	mustExec := func(sql string) {
		t.Helper()
		if _, err := c.Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	mustExec(fmt.Sprintf(`CREATE FUNCTION %s.custom_cast(integer) RETURNS text LANGUAGE sql SECURITY DEFINER STABLE AS $$SELECT 'CAST_MARKER:' || (SELECT string_agg(secret, ',') FROM %s.records)$$`, schema, schema))
	mustExec(fmt.Sprintf(`CREATE CAST (integer AS text) WITH FUNCTION %s.custom_cast(integer) AS IMPLICIT`, schema))
	dropped := false
	dropCast := func() {
		if !dropped {
			dropped = true
			_, _ = c.Exec(ctx, "DROP CAST IF EXISTS (integer AS text)")
		}
	}
	t.Cleanup(dropCast)

	opts := annotationOpts(schema, "safe")
	notReady := false
	opts.ExpectReady = &notReady
	s := bootServer(t, opts)
	for _, sql := range []string{
		"SELECT id::text FROM records",
		"SELECT CAST(id AS text) FROM records",
		"SELECT lower(id) FROM records",
		"SELECT ARRAY[id]::text[] FROM records",
		"SELECT id FROM records",
	} {
		out, errText := s.call(t, "execute_sql_readonly", map[string]any{"sql": sql})
		if errText == "" || strings.Contains(fmt.Sprint(out), "CAST_MARKER") {
			t.Fatalf("%s served while a user-defined cast exists: err=%q out=%v", sql, errText, out)
		}
		if !strings.Contains(errText, "user-defined casts") {
			t.Fatalf("%s: unexpected refusal reason %q", sql, errText)
		}
	}
	if st, body := httpGet(t, s.URL+"/readyz"); st != 503 || !strings.Contains(body, "user-defined casts") {
		t.Fatalf("readyz with custom cast: %d %s", st, body)
	}

	dropCast()
	deadline := time.Now().Add(10 * time.Second)
	for {
		time.Sleep(probeCooldown)
		if st, _ := httpGet(t, s.URL+"/readyz"); st == 200 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("server did not recover after the cast was dropped")
		}
	}
	s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT id::text FROM records"})
}

// Extensions such as pgvector install casts through functions outside
// pg_catalog, always involving their own types. Guarded SQL cannot produce or
// name those types, so they must not make the server unavailable.
func TestAnnotationsAllowExtensionTypeCasts(t *testing.T) {
	c, schema := annotationPG(t)
	ctx := context.Background()
	for _, sql := range []string{
		fmt.Sprintf(`CREATE TYPE %s.ext_kind AS ENUM ('one')`, schema),
		fmt.Sprintf(`CREATE FUNCTION %s.int_to_ext_kind(integer) RETURNS %s.ext_kind LANGUAGE sql IMMUTABLE AS $$SELECT 'one'::%s.ext_kind$$`, schema, schema, schema),
		fmt.Sprintf(`CREATE CAST (integer AS %s.ext_kind) WITH FUNCTION %s.int_to_ext_kind(integer) AS IMPLICIT`, schema, schema),
		fmt.Sprintf(`CREATE FUNCTION %s.ext_kind_to_text(%s.ext_kind) RETURNS text LANGUAGE sql IMMUTABLE AS $$SELECT 'ext'$$`, schema, schema),
		fmt.Sprintf(`CREATE CAST (%s.ext_kind AS text) WITH FUNCTION %s.ext_kind_to_text(%s.ext_kind)`, schema, schema, schema),
	} {
		if _, err := c.Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	t.Cleanup(func() {
		_, _ = c.Exec(ctx, fmt.Sprintf("DROP CAST IF EXISTS (integer AS %s.ext_kind)", schema))
		_, _ = c.Exec(ctx, fmt.Sprintf("DROP CAST IF EXISTS (%s.ext_kind AS text)", schema))
	})
	s := bootServer(t, annotationOpts(schema, "safe"))
	s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT id::text FROM records"})
	s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT lower(id::text) FROM records"})
	for _, sql := range []string{
		"SELECT id::ext_kind FROM records",
		fmt.Sprintf("SELECT id::%s.ext_kind FROM records", schema),
	} {
		if _, errText := s.call(t, "execute_sql_readonly", map[string]any{"sql": sql}); errText == "" {
			t.Fatalf("extension type reachable: %s", sql)
		}
	}
}

// probeCooldown exceeds the gate's probe-triggered refresh rate limit.
const probeCooldown = 2100 * time.Millisecond

// refreshReadyz probes readiness after the probe rate limit has expired, so
// the probe performs a fresh catalog refresh rather than reusing a result.
// A refresh that outlives one probe keeps running; later probes join it.
func refreshReadyz(t *testing.T, s *Server) (int, string) {
	t.Helper()
	time.Sleep(probeCooldown)
	deadline := time.Now().Add(15 * time.Second)
	for {
		status, body := httpGet(t, s.URL+"/readyz")
		if !strings.Contains(body, "refresh still running") || time.Now().After(deadline) {
			return status, body
		}
	}
}

// A readiness probe whose own deadline passes while the catalog is slow must
// not close admission once the catalog recovers.
func TestAnnotationsSlowReadinessProbeKeepsAdmission(t *testing.T) {
	_, schema := annotationPG(t)
	s := bootServer(t, annotationOpts(schema, "safe"))
	s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT id FROM records"})
	time.Sleep(probeCooldown)
	locker := superuserConn(t)
	tx, err := locker.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(context.Background(), "LOCK TABLE pg_catalog.pg_namespace IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	status, body := httpGet(t, s.URL+"/readyz")
	_ = tx.Rollback(context.Background())
	if status != 503 {
		t.Fatalf("readyz during catalog stall: %d %s", status, body)
	}
	s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT id FROM records"})
	if st, b := httpGet(t, s.URL+"/readyz"); st != 200 {
		t.Fatalf("readyz after stall: %d %s", st, b)
	}
}

// Clients that abandon /readyz mid-request must not affect tool admission.
func TestAnnotationsAbandonedReadinessProbesKeepAdmission(t *testing.T) {
	_, schema := annotationPG(t)
	s := bootServer(t, annotationOpts(schema, "safe"))
	s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT id FROM records"})
	addr := strings.TrimPrefix(s.URL, "http://")
	for attempt := 0; attempt < 20; attempt++ {
		if attempt%5 == 0 {
			time.Sleep(probeCooldown) // let probes trigger real refreshes, not cached results
		}
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = conn.Write([]byte("GET /readyz HTTP/1.1\r\nHost: x\r\n\r\n"))
		time.Sleep(2 * time.Millisecond)
		_ = conn.Close()
		time.Sleep(20 * time.Millisecond)
		if _, errText := s.call(t, "execute_sql_readonly", map[string]any{"sql": "SELECT id FROM records"}); errText != "" {
			t.Fatalf("attempt %d: abandoned probe closed admission: %s", attempt, errText)
		}
	}
}

// Class names belong to the database owner. The server allows exactly the
// configured classes and denies every other, including ones it never saw.
func TestAnnotationsDeploymentDefinedClasses(t *testing.T) {
	c, schema := annotationPG(t)
	for _, sql := range []string{
		fmt.Sprintf(`CREATE TABLE %s.events (id integer, payload text, note text)`, schema),
		fmt.Sprintf(`COMMENT ON COLUMN %s.events.id IS '@access: operational'`, schema),
		fmt.Sprintf(`COMMENT ON COLUMN %s.events.payload IS 'Raw event body submitted by customers.
@access: opaque-restricted'`, schema),
		fmt.Sprintf(`COMMENT ON COLUMN %s.events.note IS '@access: safe'`, schema),
		fmt.Sprintf(`INSERT INTO %s.events VALUES (1, 'hidden', 'also hidden')`, schema),
	} {
		if _, err := c.Exec(context.Background(), sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	s := bootServer(t, annotationOpts(schema, "operational"))
	s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT id FROM events"})
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT payload FROM events"}, "opaque-restricted")
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT note FROM events"}, `"safe" is not selected`)
}
