// Command sqlguard-check runs one SQL statement through a dialect guard and
// prints either the canonical SQL or the rejection, for debugging policies.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/speakeasy-api/gram-restricted-sql-mcp/internal/policy"
	"github.com/speakeasy-api/gram-restricted-sql-mcp/internal/sqlguard"
	chguard "github.com/speakeasy-api/gram-restricted-sql-mcp/internal/sqlguard/clickhouse"
	pgguard "github.com/speakeasy-api/gram-restricted-sql-mcp/internal/sqlguard/postgres"
)

func main() {
	fs := flag.NewFlagSet("sqlguard-check", flag.ExitOnError)
	dialect := fs.String("dialect", "postgres", "postgres|clickhouse")
	defaultSchema := fs.String("default-schema", "", "schema for unqualified names (default: public for postgres, default for clickhouse)")
	readTables := fs.String("read-tables", "", "comma-separated read allowlist")
	writeTables := fs.String("write-tables", "", "comma-separated write allowlist")
	modeFlag := fs.String("mode", "read", "read|write")
	columns := fs.String("columns", "", "catalog columns as table=col1,col2;table2=col1 (postgres qualified column resolution)")
	tiers := fs.String("tiers", "", "annotation tiers: safe or safe,pii; columns must be table=column:tier,...")
	catalogPath := fs.String("catalog", "", "JSON policy.Catalog snapshot, including built-in functions for ClickHouse")
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
	cols, err := parseColumns(*columns, *defaultSchema, d)
	if err != nil {
		fatal(err)
	}
	pol.SetColumns(cols)
	if *tiers != "" {
		if *readTables != "" || *writeTables != "" || *modeFlag != "read" {
			fatal(fmt.Errorf("annotation diagnostics require read mode without static table lists"))
		}
		pol.AnnotationTiers = map[policy.Tier]bool{}
		for _, tier := range strings.Split(*tiers, ",") {
			t := policy.Tier(strings.TrimSpace(tier))
			if t != policy.Safe && t != policy.PII {
				fatal(fmt.Errorf("only safe and pii may be selected"))
			}
			pol.AnnotationTiers[t] = true
		}
		catalog := &policy.Catalog{}
		if *catalogPath != "" {
			raw, err := os.ReadFile(*catalogPath)
			if err != nil {
				fatal(err)
			}
			if err := json.Unmarshal(raw, catalog); err != nil {
				fatal(err)
			}
		} else {
			for ref, names := range cols {
				r := policy.Relation{Ref: ref, Kind: "table", Identity: ref.String()}
				for i, spec := range names {
					name, tier, ok := strings.Cut(spec, ":")
					col := policy.CatalogColumn{Name: name, Position: i + 1, Identity: ref.String() + "." + name}
					if ok {
						policy.Annotate(&col, "@access: "+tier)
					} else {
						policy.Annotate(&col, "")
					}
					r.Columns = append(r.Columns, col)
				}
				catalog.Relations = append(catalog.Relations, r)
			}
		}
		if err := catalog.Seal(); err != nil {
			fatal(err)
		}
		pol = pol.WithCatalog(catalog)
	} else if *catalogPath != "" {
		fatal(fmt.Errorf("--catalog requires --tiers"))
	}

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
	case policy.ClickHouse:
		g = chguard.New()
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
	if pol.AnnotationMode() {
		fmt.Printf("catalog=%s columns=%v\n", checked.Generation, checked.Columns)
	}
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

func parseColumns(spec, defaultSchema string, d policy.Dialect) (map[policy.TableRef][]string, error) {
	out := map[policy.TableRef][]string{}
	for _, entry := range strings.Split(spec, ";") {
		if strings.TrimSpace(entry) == "" {
			continue
		}
		table, list, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, fmt.Errorf("--columns entry %q must be table=col1,col2", entry)
		}
		ref, err := policy.ParseTableRef(table, defaultSchema, d)
		if err != nil {
			return nil, err
		}
		for _, c := range strings.Split(list, ",") {
			if c = strings.TrimSpace(c); c != "" {
				out[ref] = append(out[ref], c)
			}
		}
	}
	return out, nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(2)
}
