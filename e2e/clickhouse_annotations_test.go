package e2e

import (
	_ "embed"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

//go:embed fixtures/clickhouse-annotations.sql
var clickhouseAnnotationFixture string

func annotationCH(t *testing.T) string {
	t.Helper()
	schema := fmt.Sprintf("annotation_%d", time.Now().UnixNano())
	t.Cleanup(func() { chExecAnnotation(t, "DROP DATABASE IF EXISTS "+schema+" SYNC") })
	for _, sql := range strings.Split(strings.ReplaceAll(clickhouseAnnotationFixture, "__SCHEMA__", schema), ";") {
		if strings.TrimSpace(sql) != "" {
			chExecAnnotation(t, sql)
		}
	}
	return schema
}
func chExecAnnotation(t *testing.T, sql string) {
	t.Helper()
	if status, body := chHTTP(t, sql, nil); status != 200 {
		t.Fatalf("%s: %d %s", sql, status, body)
	}
}
func annotationCHOpts(schema, tiers string) ServerOpts {
	o := annotationOpts(schema, tiers)
	o.Dialect = "clickhouse"
	return o
}
func TestClickHouseAnnotationsReadAndBinding(t *testing.T) {
	schema := annotationCH(t)
	s := bootServer(t, annotationCHOpts(schema, "safe"))
	allow := []string{
		"SELECT id,amount FROM records ORDER BY id",
		"SELECT count(*),count(),count(1),count(id),sum(amount) FROM records",
		"SELECT r.id FROM records r WHERE r.amount>0 ORDER BY r.id",
		"WITH c AS (SELECT id FROM records) SELECT id FROM c",
		"WITH 2 AS k SELECT id,k FROM records",
		"SELECT x.k FROM (SELECT id AS k FROM records) x",
		"SELECT id AS k FROM records WHERE k>0 ORDER BY k",
		"SELECT amount AS k,count() AS n FROM records GROUP BY k ORDER BY k",
		"SELECT r.id,o.label FROM records r JOIN owners o ON r.id=o.id",
		"SELECT r.id,o.label FROM records r JOIN owners o USING(id)",
		"SELECT row_number() OVER (PARTITION BY amount ORDER BY id) AS n FROM records",
		"SELECT arrayMap(x -> x + amount,tags) AS mapped FROM records",
		"SELECT arrayMap(amount -> amount + 1,tags) AS mapped FROM records",
		"SELECT tags[1] AS first FROM records",
		"SELECT id FROM records PREWHERE amount>0",
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
		"SELECT * FROM records":                                            "wildcard",
		"SELECT r.* FROM records r":                                        "wildcard",
		"SELECT * FROM all_safe":                                           "wildcard",
		"SELECT COLUMNS('.*') FROM records":                                "wildcard",
		"SELECT * EXCEPT(secret) FROM records":                             "wildcard",
		"SELECT content FROM records":                                      "content",
		"SELECT email FROM records":                                        "pii",
		"SELECT legacy FROM records":                                       "not annotated",
		"SELECT invalid FROM records":                                      "duplicate",
		"SELECT count(content) FROM records":                               "content",
		"SELECT count(*) FROM records WHERE content='x'":                   "content",
		"SELECT id FROM records ORDER BY secret":                           "secret",
		"SELECT count(*) FROM records GROUP BY content":                    "content",
		"SELECT row_number() OVER(PARTITION BY content) AS n FROM records": "content",
		"WITH c AS (SELECT content AS id FROM records) SELECT id FROM c":   "collides",
		"WITH content AS innocent SELECT innocent FROM records":            "content",
		"SELECT r.id FROM records r JOIN owners o USING(content)":          "content",
		"SELECT count(*) FROM closed":                                      "no selectable",
		"SELECT id FROM unsafe_view":                                       "unsupported relation",
		"SELECT echo FROM generated":                                       "computed",
		"SELECT arrayMap(x -> concat(x,content),tags) FROM records":        "content",
		"SELECT id AS content FROM records WHERE content='x'":              "collides",
		"SELECT secret.field FROM records":                                 "unknown",
		"SELECT _part FROM records":                                        "unknown",
		"SELECT id FROM records SETTINGS prefer_column_name_to_alias=0":    "SETTINGS",
	}
	for sql, reason := range deny {
		t.Run(sql, func(t *testing.T) { s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": sql}, reason) })
	}
	details := s.mustCall(t, "get_object_details", map[string]any{"schema": schema, "name": "records"})
	if strings.Contains(fmt.Sprint(details), "SENSITIVE_") || !strings.Contains(fmt.Sprint(details), "selectable:false") {
		t.Fatalf("metadata=%v", details)
	}
	s.mustCall(t, "get_object_details", map[string]any{"schema": schema, "name": "closed"})
	global := s.mustCall(t, "get_object_details", map[string]any{"schema": "app", "name": "allowed_orders"})
	if global["access"].(map[string]any)["queryable"] != false {
		t.Fatalf("unannotated global metadata: %v", global)
	}
	s.mustCall(t, "explain_query", map[string]any{"sql": "SELECT id FROM records"})
	counts := rows(t, s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT count(*),count(),count(id) FROM records"}))
	if !reflect.DeepEqual(counts[0], []any{float64(2), float64(2), float64(1)}) {
		t.Fatalf("nullable count semantics changed: %v", counts)
	}
}
func TestClickHouseAnnotationsPiiAndMigration(t *testing.T) {
	schema := annotationCH(t)
	s := bootServer(t, annotationCHOpts(schema, "safe,pii"))
	s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT email FROM records"})
	chExecAnnotation(t, "ALTER TABLE "+schema+".records ADD COLUMN ssn String")
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT ssn FROM records"}, "unknown")
	if status, body := refreshReadyz(t, s); status != 200 {
		t.Fatalf("refresh: %d %s", status, body)
	}
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT ssn FROM records"}, "not annotated")
	chExecAnnotation(t, "ALTER TABLE "+schema+".records COMMENT COLUMN ssn '@access: restricted'")
	chExecAnnotation(t, "ALTER TABLE "+schema+".records COMMENT COLUMN amount '@access: content'")
	if status, body := refreshReadyz(t, s); status != 200 {
		t.Fatalf("refresh: %d %s", status, body)
	}
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT ssn FROM records"}, "restricted")
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT amount FROM records"}, "content")
	role := annotationServerRole(t, s)
	if lines := chLines(t, "SELECT count() FROM system.grants WHERE user_name='"+role+"' AND database='"+schema+"' AND table='records' AND (column IN ('amount','ssn') OR column IS NULL)"); len(lines) != 1 || lines[0] != "0" {
		t.Fatalf("obsolete or broad grants: %v", lines)
	}
}
