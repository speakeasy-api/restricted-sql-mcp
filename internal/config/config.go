// Package config parses command-line flags and environment into the boot
// configuration and builds the policy the guards enforce.
package config

import (
	"errors"
	"flag"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ThomasRooney/gram-restrictedsql-tunnel-mcp/internal/policy"
)

// Config is the resolved boot configuration.
type Config struct {
	Dialect          policy.Dialect
	DSN              string
	ReadTables       []string
	WriteTables      []string
	WritesEnabled    bool
	DefaultSchema    string
	Transport        string // "http" | "stdio"
	Listen           string // "127.0.0.1:8080"
	MaxRows          int
	StatementTimeout time.Duration
	TxnIdleTimeout   time.Duration
	MaxOpenTxns      int
	Tunnel           bool
	LogLevel         string
	Version          string

	// ConnectionLevelSecurity treats the DSN as a bootstrap connection used
	// to provision least-privilege database roles; tool traffic then runs as
	// those roles. SecurityRolePrefix names them (<prefix>_ro, <prefix>_rw).
	ConnectionLevelSecurity bool
	SecurityRolePrefix      string

	// Tunnel settings come from the environment, never from flags, so they do
	// not show up in process listings.
	TunnelGatewayURL     string
	TunnelKey            string
	TunnelServiceVersion string
}

// rolePrefixRE keeps provisioned role names plain identifiers in both
// dialects; the longest suffix is "_rw" and Postgres caps names at 63 bytes.
var rolePrefixRE = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,59}$`)

// ErrHelp is returned by ParseFlags when --help was requested; the usage has
// already been printed.
var ErrHelp = flag.ErrHelp

// ParseFlags parses args (without the program name) and resolves environment
// fallbacks through getenv. Validation errors are returned for main to print;
// they should map to exit code 2.
func ParseFlags(args []string, getenv func(string) string, version string) (*Config, error) {
	c := &Config{Version: version}
	fs := flag.NewFlagSet("restrictedsql-mcp", flag.ContinueOnError)
	var dialect, readTables, writeTables string
	fs.StringVar(&dialect, "dialect", "", "database dialect: postgres|clickhouse (required)")
	fs.StringVar(&c.DSN, "dsn", "", "database connection URL (or env DATABASE_URL; required)")
	fs.StringVar(&readTables, "read-tables", "", "comma-separated tables readable by the read tools, e.g. schema.t1,schema.t2 (required)")
	fs.StringVar(&writeTables, "write-tables", "", "comma-separated tables writable by the write tools (optional)")
	fs.BoolVar(&c.WritesEnabled, "dangerously-add-write-tools", false, "register the begin/execute/commit/rollback write tools (Postgres only)")
	fs.StringVar(&c.DefaultSchema, "default-schema", "", "schema used to resolve unqualified table names (postgres: public; clickhouse: database from DSN, else default)")
	fs.StringVar(&c.Transport, "transport", "http", "MCP transport: http|stdio")
	fs.StringVar(&c.Listen, "listen", "127.0.0.1:8080", "listen address for the http transport (MCP at /mcp, health at /healthz and /readyz)")
	fs.IntVar(&c.MaxRows, "max-rows", 1000, "server cap on rows returned per call")
	fs.DurationVar(&c.StatementTimeout, "statement-timeout", 30*time.Second, "per-statement timeout applied at the database session")
	fs.DurationVar(&c.TxnIdleTimeout, "txn-idle-timeout", 2*time.Minute, "write transactions idle longer than this are rolled back")
	fs.IntVar(&c.MaxOpenTxns, "max-open-txns", 8, "maximum concurrently open write transactions")
	fs.BoolVar(&c.Tunnel, "tunnel", false, "start the gram tunnel agent (requires TUNNEL_GATEWAY_URL and TUNNEL_KEY)")
	fs.StringVar(&c.LogLevel, "log-level", "info", "log level: debug|info|warn|error")
	fs.BoolVar(&c.ConnectionLevelSecurity, "connection-level-security", false, "provision least-privilege database roles from the (bootstrap) DSN at boot and run all tool traffic as those roles")
	fs.StringVar(&c.SecurityRolePrefix, "security-role-prefix", "restrictedsql", "prefix of the roles provisioned by --connection-level-security (<prefix>_ro, <prefix>_rw)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected positional arguments: %v", fs.Args())
	}

	c.Dialect = policy.Dialect(strings.ToLower(strings.TrimSpace(dialect)))
	c.ReadTables = splitList(readTables)
	c.WriteTables = splitList(writeTables)
	if c.DSN == "" {
		c.DSN = getenv("DATABASE_URL")
	}
	c.TunnelGatewayURL = getenv("TUNNEL_GATEWAY_URL")
	c.TunnelKey = getenv("TUNNEL_KEY")
	c.TunnelServiceVersion = getenv("TUNNEL_SERVICE_VERSION")
	if c.TunnelServiceVersion == "" {
		c.TunnelServiceVersion = version
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Validate checks the configuration and fills derived defaults such as the
// default schema.
func (c *Config) Validate() error {
	switch c.Dialect {
	case policy.Postgres, policy.ClickHouse:
	case "":
		return errors.New("--dialect is required (postgres|clickhouse)")
	default:
		return fmt.Errorf("--dialect %q is not supported (postgres|clickhouse)", c.Dialect)
	}
	if strings.TrimSpace(c.DSN) == "" {
		return errors.New("--dsn or DATABASE_URL is required")
	}
	if len(c.ReadTables) == 0 {
		return errors.New("--read-tables is required (at least one table)")
	}
	if c.DefaultSchema == "" {
		c.DefaultSchema = defaultSchemaFor(c.Dialect, c.DSN)
	}
	for _, t := range c.ReadTables {
		if _, err := policy.ParseTableRef(t, c.DefaultSchema, c.Dialect); err != nil {
			return fmt.Errorf("--read-tables: %w", err)
		}
	}
	for _, t := range c.WriteTables {
		if _, err := policy.ParseTableRef(t, c.DefaultSchema, c.Dialect); err != nil {
			return fmt.Errorf("--write-tables: %w", err)
		}
	}
	if c.WritesEnabled {
		if c.Dialect == policy.ClickHouse {
			return errors.New("--dangerously-add-write-tools: write tools are not supported on clickhouse")
		}
		if len(c.WriteTables) == 0 {
			return errors.New("--dangerously-add-write-tools requires --write-tables")
		}
	}
	switch c.Transport {
	case "http", "stdio":
	default:
		return fmt.Errorf("--transport %q is not supported (http|stdio)", c.Transport)
	}
	if c.Transport == "http" && strings.TrimSpace(c.Listen) == "" {
		return errors.New("--listen is required for the http transport")
	}
	if c.MaxRows <= 0 {
		return errors.New("--max-rows must be greater than zero")
	}
	if c.StatementTimeout <= 0 {
		return errors.New("--statement-timeout must be greater than zero")
	}
	if c.TxnIdleTimeout <= 0 {
		return errors.New("--txn-idle-timeout must be greater than zero")
	}
	if c.MaxOpenTxns <= 0 {
		return errors.New("--max-open-txns must be greater than zero")
	}
	if c.Tunnel {
		if strings.TrimSpace(c.TunnelGatewayURL) == "" || strings.TrimSpace(c.TunnelKey) == "" {
			return errors.New("--tunnel requires TUNNEL_GATEWAY_URL and TUNNEL_KEY in the environment")
		}
	}
	if c.ConnectionLevelSecurity {
		if !rolePrefixRE.MatchString(c.SecurityRolePrefix) {
			return fmt.Errorf("--security-role-prefix %q must match %s", c.SecurityRolePrefix, rolePrefixRE.String())
		}
		if u, err := url.Parse(c.DSN); err != nil || u.Scheme == "" || u.Host == "" {
			return errors.New("--connection-level-security requires a URL-form DSN (scheme://user:password@host:port/database)")
		}
	}
	switch strings.ToLower(c.LogLevel) {
	case "debug", "info", "warn", "error":
		c.LogLevel = strings.ToLower(c.LogLevel)
	default:
		return fmt.Errorf("--log-level %q is not supported (debug|info|warn|error)", c.LogLevel)
	}
	return nil
}

// BuildPolicy resolves the table lists into a Policy.
func (c *Config) BuildPolicy() (*policy.Policy, error) {
	p := &policy.Policy{
		Dialect:          c.Dialect,
		DefaultSchema:    c.DefaultSchema,
		ReadTables:       map[policy.TableRef]struct{}{},
		WriteTables:      map[policy.TableRef]struct{}{},
		WritesEnabled:    c.WritesEnabled,
		MaxRows:          c.MaxRows,
		StatementTimeout: c.StatementTimeout,
	}
	for _, t := range c.ReadTables {
		ref, err := policy.ParseTableRef(t, c.DefaultSchema, c.Dialect)
		if err != nil {
			return nil, fmt.Errorf("--read-tables: %w", err)
		}
		p.ReadTables[ref] = struct{}{}
	}
	for _, t := range c.WriteTables {
		ref, err := policy.ParseTableRef(t, c.DefaultSchema, c.Dialect)
		if err != nil {
			return nil, fmt.Errorf("--write-tables: %w", err)
		}
		p.WriteTables[ref] = struct{}{}
	}
	return p, nil
}

// defaultSchemaFor picks the schema used for unqualified names. ClickHouse
// takes the database from the DSN path when present.
func defaultSchemaFor(d policy.Dialect, dsn string) string {
	if d == policy.Postgres {
		return "public"
	}
	if u, err := url.Parse(dsn); err == nil {
		if p := strings.Trim(u.Path, "/"); p != "" {
			return p
		}
	}
	return "default"
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
