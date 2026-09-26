package e2e

import (
	"fmt"
	"strings"
	"testing"
)

// Relation aliases that equal a column name are ambiguous with ClickHouse
// subcolumn reads, and inlined aliases must keep their grouping.
func TestClickHouseAnnotationsAliasSemantics(t *testing.T) {
	schema := annotationCH(t)
	chExecAnnotation(t, fmt.Sprintf("CREATE TABLE %s.shapes (id UInt64 COMMENT '@access: safe', x String COMMENT '@access: safe', tup Tuple(x String) COMMENT '@access: content') ENGINE=MergeTree ORDER BY id", schema))
	chExecAnnotation(t, fmt.Sprintf("INSERT INTO %s.shapes VALUES (1, 'visible', tuple('hidden'))", schema))
	s := bootServer(t, annotationCHOpts(schema, "safe"))

	// The binder must refuse these itself, not rely on the column grants.
	for sql, reason := range map[string]string{
		"SELECT tup.x AS r FROM shapes AS tup":                          "shadows a column",
		"SELECT count() AS c FROM shapes AS tup WHERE tup.x = 'hidden'": "shadows a column",
		"SELECT id, {'k': x} AS m FROM shapes":                          "map literals",
	} {
		s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": sql}, reason)
	}
	for sql, want := range map[string]string{
		"SELECT id + 1 AS k, k * 2 AS r FROM shapes":                 "[[2 4]]",
		"SELECT id - 1 AS k, 10 - k AS r FROM shapes":                "[[0 10]]",
		"SELECT id AS k, arrayMap(id -> k, [1000]) AS r FROM shapes": "[[1 [1]]]",
		"SELECT s.x AS r FROM shapes AS s":                           "[[visible]]",
	} {
		out := s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": sql})
		if got := fmt.Sprint(rows(t, out)); got != want {
			t.Errorf("%s: got %s want %s", sql, got, want)
		}
	}
}

// The binder depends on settings pinned on the process user. Drift while the
// catalog is unchanged must close access at the next verification.
func TestClickHouseAnnotationsSettingsDriftClosesAccess(t *testing.T) {
	schema := annotationCH(t)
	s := bootServer(t, annotationCHOpts(schema, "safe"))
	s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT id FROM records"})
	role := annotationServerRole(t, s)
	chExecAnnotation(t, fmt.Sprintf("ALTER USER `%s` SETTINGS readonly = 1 READONLY, prefer_column_name_to_alias = 0", role))
	if status, body := refreshReadyz(t, s); status != 503 || !strings.Contains(body, "prefer_column_name_to_alias") {
		t.Fatalf("settings drift not detected: %d %s", status, body)
	}
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT id FROM records"}, "unavailable")
}
