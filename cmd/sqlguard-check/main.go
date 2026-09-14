// Command sqlguard-check runs one SQL statement through a dialect guard and
// prints the canonical SQL or the rejection. Exit status 1 on rejection.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/ThomasRooney/gram-restrictedsql-tunnel-mcp/internal/policy"
	"github.com/ThomasRooney/gram-restrictedsql-tunnel-mcp/internal/sqlguard"
	chguard "github.com/ThomasRooney/gram-restrictedsql-tunnel-mcp/internal/sqlguard/clickhouse"
)

func main() {
	fs := flag.NewFlagSet("sqlguard-check", flag.ExitOnError)
	dialect := fs.String("dialect", "postgres", "postgres|clickhouse")
	defaultSchema := fs.String("default-schema", "", "schema for unqualified names (postgres: public, clickhouse: default)")
	readTables := fs.String("read-tables", "", "comma-separated read allowlist")
	writeTables := fs.String("write-tables", "", "comma-separated write allowlist")
	modeFlag := fs.String("mode", "read", "read|write")
	verbose := fs.Bool("v", false, "debug logging to stderr")
	_ = fs.Parse(os.Args[1:])
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: sqlguard-check [flags] 'SQL'")
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
		Dialect:          d,
		DefaultSchema:    *defaultSchema,
		ReadTables:       map[policy.TableRef]struct{}{},
		WriteTables:      map[policy.TableRef]struct{}{},
		WritesEnabled:    *modeFlag == "write",
		MaxRows:          1000,
		StatementTimeout: 30 * time.Second,
	}
	if err := fillTables(pol.ReadTables, *readTables, *defaultSchema, d); err != nil {
		fmt.Fprintln(os.Stderr, "read-tables:", err)
		os.Exit(2)
	}
	if err := fillTables(pol.WriteTables, *writeTables, *defaultSchema, d); err != nil {
		fmt.Fprintln(os.Stderr, "write-tables:", err)
		os.Exit(2)
	}
	mode := sqlguard.ModeRead
	switch *modeFlag {
	case "read":
	case "write":
		mode = sqlguard.ModeWrite
	default:
		fmt.Fprintln(os.Stderr, "mode must be read or write")
		os.Exit(2)
	}

	var g sqlguard.Guard
	switch d {
	case policy.ClickHouse:
		g = chguard.New()
	case policy.Postgres:
		fmt.Fprintln(os.Stderr, "postgres guard not merged yet")
		os.Exit(2)
	default:
		fmt.Fprintln(os.Stderr, "unknown dialect:", *dialect)
		os.Exit(2)
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

func fillTables(dst map[policy.TableRef]struct{}, list, defaultSchema string, d policy.Dialect) error {
	for _, s := range strings.Split(list, ",") {
		if strings.TrimSpace(s) == "" {
			continue
		}
		ref, err := policy.ParseTableRef(s, defaultSchema, d)
		if err != nil {
			return err
		}
		dst[ref] = struct{}{}
	}
	return nil
}
