package e2e

import (
	"strings"
	"testing"
)

// TestPostgresReadInputLimits covers inputs the guard must refuse before
// parsing: NUL bytes (the C parser would silently truncate at the first one)
// and oversized statements (the deparser is superlinear in size).
func TestPostgresReadInputLimits(t *testing.T) {
	s := bootServer(t, ServerOpts{})
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT 1\x00; SELECT * FROM forbidden_secrets"}, "NUL")
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT * FROM allowed_orders\x00, forbidden_secrets"}, "NUL")
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": "SELECT '\x00'"}, "NUL")

	long := "SELECT " + strings.Repeat("1,", 40000) + "1"
	s.mustReject(t, "execute_sql_readonly", map[string]any{"sql": long}, "too long")
	ok := "SELECT id FROM allowed_orders WHERE id IN (" + strings.Repeat("1,", 3000) + "1)"
	s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": ok})
}
