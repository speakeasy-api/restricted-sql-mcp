// Command restrictedsql-mcp serves allowlisted SQL access to a Postgres or
// ClickHouse database over MCP.
package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/ThomasRooney/gram-restrictedsql-tunnel-mcp/internal/config"
	"github.com/ThomasRooney/gram-restrictedsql-tunnel-mcp/internal/policy"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	cfg, err := config.ParseFlags(os.Args[1:], os.Getenv, version)
	if err != nil {
		if errors.Is(err, config.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "restrictedsql-mcp:", err)
		os.Exit(2)
	}
	pol, err := cfg.BuildPolicy()
	if err != nil {
		fmt.Fprintln(os.Stderr, "restrictedsql-mcp:", err)
		os.Exit(2)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel(cfg.LogLevel)}))
	logger.Info("config resolved",
		"version", cfg.Version,
		"dialect", pol.Dialect,
		"default_schema", pol.DefaultSchema,
		"read_tables", refsToStrings(pol.ReadTables),
		"write_tables", refsToStrings(pol.WriteTables),
		"writes_enabled", pol.WritesEnabled,
		"transport", cfg.Transport,
		"listen", cfg.Listen,
		"max_rows", pol.MaxRows,
		"statement_timeout", pol.StatementTimeout.String(),
		"tunnel", cfg.Tunnel,
	)
}

func logLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func refsToStrings(m map[policy.TableRef]struct{}) []string {
	out := make([]string, 0, len(m))
	for r := range m {
		out = append(out, r.String())
	}
	return out
}
