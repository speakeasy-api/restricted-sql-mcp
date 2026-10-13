package config

import (
	"strings"
	"testing"
)

func TestDatabasesFlag(t *testing.T) {
	env := func(string) string { return "" }
	base := []string{"--dialect", "postgres", "--dsn", "postgres://u:p@h:5432/gram", "--read-tables", "gram.*"}
	c, err := ParseFlags(append(base, "--databases", "^gram_preview_pr_[0-9]+$"), env, "test")
	if err != nil {
		t.Fatal(err)
	}
	if c.DatabasesRE == nil || !c.DatabasesRE.MatchString("gram_preview_pr_12") || c.DefaultDatabase() != "gram" {
		t.Fatalf("config = %+v", c)
	}
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"clickhouse": {[]string{"--dialect", "clickhouse", "--dsn", "clickhouse://h:9000/app", "--read-tables", "t", "--databases", "x"}, "postgres only"},
		"annotations": {[]string{"--dialect", "postgres", "--dsn", "postgres://u:p@h/gram", "--columns-from-annotations", "safe",
			"--connection-level-security", "--databases", "x"}, "columns-from-annotations"},
		"regex":       {append(append([]string{}, base...), "--databases", "("), "invalid regular expression"},
		"no database": {[]string{"--dialect", "postgres", "--dsn", "postgres://u:p@h:5432", "--read-tables", "t", "--databases", "x"}, "names its database"},
		"keyvalue":    {[]string{"--dialect", "postgres", "--dsn", "host=h dbname=gram", "--read-tables", "t", "--databases", "x"}, "names its database"},
	} {
		if _, err := ParseFlags(tc.args, env, "test"); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}
