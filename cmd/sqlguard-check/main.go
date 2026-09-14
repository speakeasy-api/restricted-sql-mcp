// Command sqlguard-check runs one SQL statement through a dialect guard and
// prints either the canonical SQL or the rejection, for debugging policies.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/ThomasRooney/gram-restrictedsql-tunnel-mcp/internal/policy"
	"github.com/ThomasRooney/gram-restrictedsql-tunnel-mcp/internal/sqlguard"
	pgguard "github.com/ThomasRooney/gram-restrictedsql-tunnel-mcp/internal/sqlguard/postgres"
)

func main() {
	fs := flag.NewFlagSet("sqlguard-check", flag.ExitOnError)
	dialect := fs.String("dialect", "postgres", "postgres|clickhouse")
	defaultSchema := fs.String("default-schema", "", "schema for unqualified names (default: public for postgres, default for clickhouse)")
	readTables := fs.String("read-tables", "", "comma-separated read allowlist")
	writeTables := fs.String("write-tables", "", "comma-separated write allowlist")
	modeFlag := fs.String("mode", "read", "read|write")
	verbose := fs.Bool("v", false, "debug logging to stderr")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: sqlguard-check [flags] <sql>\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(os.Args[1:])
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}
	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	d := policy.Dialect(*dialect)
	if *defaultSchema == "" {
		switch d {
		case policy.Postgres:
			*defaultSchema = "public"
		case policy.ClickHouse:
			*defaultSchema = "default"
		}
	}
	pol := &policy.Policy{
		Dialect:       d,
		DefaultSchema: *defaultSchema,
		ReadTables:    map[policy.TableRef]struct{}{},
		WriteTables:   map[policy.TableRef]struct{}{},
	}
	if err := fill(pol.ReadTables, *readTables, *defaultSchema, d); err != nil {
		fatal(err)
	}
	if err := fill(pol.WriteTables, *writeTables, *defaultSchema, d); err != nil {
		fatal(err)
	}
	pol.WritesEnabled = len(pol.WriteTables) > 0

	mode := sqlguard.ModeRead
	switch *modeFlag {
	case "read":
	case "write":
		mode = sqlguard.ModeWrite
	default:
		fatal(fmt.Errorf("unknown mode %q", *modeFlag))
	}

	var g sqlguard.Guard
	switch d {
	case policy.Postgres:
		g = pgguard.New()
	default:
		fatal(fmt.Errorf("unsupported dialect %q", *dialect))
	}

	checked, err := g.Check(fs.Arg(0), mode, pol)
	if err != nil {
		fmt.Printf("REJECTED: %v\n", err)
		os.Exit(1)
	}
	names := make([]string, len(checked.Tables))
	for i, t := range checked.Tables {
		names[i] = t.String()
	}
	fmt.Printf("OK %s tables=[%s]\n%s\n", checked.Kind, strings.Join(names, " "), checked.SQL)
}

func fill(set map[policy.TableRef]struct{}, list, defaultSchema string, d policy.Dialect) error {
	for _, s := range strings.Split(list, ",") {
		if strings.TrimSpace(s) == "" {
			continue
		}
		ref, err := policy.ParseTableRef(s, defaultSchema, d)
		if err != nil {
			return err
		}
		set[ref] = struct{}{}
	}
	return nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(2)
}
