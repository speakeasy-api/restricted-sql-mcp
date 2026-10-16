package dbsec

import (
	"regexp"
	"strings"
	"testing"
)

var rolePrefixRE = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,59}$`)

func TestDatabaseRolePrefix(t *testing.T) {
	long := strings.Repeat("x", 70)
	cases := map[string]string{
		"app_preview_pr_123": "restrictedsql_app_preview_pr_123",
		"e2e":                "restrictedsql_e2e",
	}
	for db, want := range cases {
		if got := DatabaseRolePrefix("restrictedsql", db); got != want {
			t.Errorf("DatabaseRolePrefix(%q) = %q, want %q", db, got, want)
		}
	}
	seen := map[string]string{}
	for _, db := range []string{
		"app_preview_pr_1", "App_Preview_PR_1", "app-preview-pr-1", "app preview pr 1",
		long + "a", long + "b", "ünïcode", "unicode", strings.Repeat("é", 40),
	} {
		for _, prefix := range []string{"restrictedsql", strings.Repeat("p", 60), "_"} {
			got := DatabaseRolePrefix(prefix, db)
			if !rolePrefixRE.MatchString(got) || len(got+"_rw") > 63 {
				t.Errorf("DatabaseRolePrefix(%q, %q) = %q: not a valid role prefix", prefix, db, got)
			}
			key := prefix + "|" + got
			if other, dup := seen[key]; dup {
				t.Errorf("databases %q and %q both map to %q", other, db, got)
			}
			seen[key] = db
		}
	}
}

func TestWithDatabase(t *testing.T) {
	got, err := WithDatabase("postgres://u:p%40ss@db.internal:5432/app?sslmode=require&dbname=other", "app_preview_pr_7")
	if err != nil {
		t.Fatal(err)
	}
	if want := "postgres://u:p%40ss@db.internal:5432/app_preview_pr_7?sslmode=require"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if _, err := WithDatabase("host=localhost dbname=app", "x"); err == nil {
		t.Fatal("key/value DSN accepted")
	}
}
