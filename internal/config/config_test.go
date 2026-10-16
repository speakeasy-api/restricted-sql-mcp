package config

import (
	"strings"
	"testing"
)

func TestDatabasesFlag(t *testing.T) {
	env := func(string) string { return "" }
	base := []string{"--dialect", "postgres", "--dsn", "postgres://u:p@h:5432/app", "--read-tables", "app.*"}
	c, err := ParseFlags(append(base, "--databases", "^app_preview_pr_[0-9]+$"), env, "test")
	if err != nil {
		t.Fatal(err)
	}
	if c.DatabasesRE == nil || !c.DatabasesRE.MatchString("app_preview_pr_12") || c.DefaultDatabase() != "app" {
		t.Fatalf("config = %+v", c)
	}
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"clickhouse": {[]string{"--dialect", "clickhouse", "--dsn", "clickhouse://h:9000/app", "--read-tables", "t", "--databases", "x"}, "postgres only"},
		"annotations": {[]string{"--dialect", "postgres", "--dsn", "postgres://u:p@h/app", "--columns-from-annotations", "safe",
			"--connection-level-security", "--databases", "x"}, "columns-from-annotations"},
		"regex":       {append(append([]string{}, base...), "--databases", "("), "invalid regular expression"},
		"no database": {[]string{"--dialect", "postgres", "--dsn", "postgres://u:p@h:5432", "--read-tables", "t", "--databases", "x"}, "names its database"},
		"keyvalue":    {[]string{"--dialect", "postgres", "--dsn", "host=h dbname=app", "--read-tables", "t", "--databases", "x"}, "names its database"},
	} {
		if _, err := ParseFlags(tc.args, env, "test"); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}

func TestHealthListenFlag(t *testing.T) {
	env := func(string) string { return "" }
	base := []string{"--dialect", "postgres", "--dsn", "postgres://u:p@h:5432/app", "--read-tables", "app.*"}
	c, err := ParseFlags(append(base, "--health-listen", "0.0.0.0:8081"), env, "test")
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "127.0.0.1:8080" || c.HealthListen != "0.0.0.0:8081" {
		t.Fatalf("config = %+v", c)
	}
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"stdio":       {append(append([]string{}, base...), "--transport", "stdio", "--health-listen", ":8081"), "requires --transport http"},
		"same as mcp": {append(append([]string{}, base...), "--listen", "127.0.0.1:8080", "--health-listen", "127.0.0.1:8080"), "must differ from --listen"},
	} {
		if _, err := ParseFlags(tc.args, env, "test"); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}
