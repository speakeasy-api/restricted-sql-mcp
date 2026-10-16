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

	"github.com/speakeasy-api/restricted-sql-mcp/internal/policy"
)

// Config is the resolved boot configuration.
type Config struct {
	Dialect                   policy.Dialect
	DSN                       string
	AnnotationTiers           []string
	AnnotationRefreshInterval time.Duration
	AnnotationRefreshTimeout  time.Duration
	ReadTables                []string
	WriteTables               []string
	// ReadSchemas and WriteSchemas come from `<schema>.*` entries in
	// --read-tables and --write-tables. Every table in them is added to the
	// policy at boot (Postgres only); tables created later need a restart.
	ReadSchemas   []string
	WriteSchemas  []string
	WritesEnabled bool
	DefaultSchema string
	Transport     string // "http" | "stdio"
	Listen        string // "127.0.0.1:8080"
	// HealthListen, when set, serves only /healthz and /readyz on a second
	// listener, so probes can reach the pod while /mcp stays on loopback.
	HealthListen     string
	MaxRows          int
	StatementTimeout time.Duration
	TxnIdleTimeout   time.Duration
	TxnMaxLifetime   time.Duration
	MaxOpenTxns      int
	// PoolMaxConns caps read connections to the default database;
	// DatabasePoolMaxConns caps them to each further --databases database.
	PoolMaxConns         int
	DatabasePoolMaxConns int
	Tunnel               bool
	TunnelOnly           bool
	LogLevel             string
	Version              string

	// ConnectionLevelSecurity treats the DSN as a bootstrap connection used
	// to provision least-privilege database roles; tool traffic then runs as
	// those roles. SecurityRolePrefix names them (<prefix>_ro, <prefix>_rw).
	ConnectionLevelSecurity bool
	SecurityRolePrefix      string

	// Databases, when set, serves every database on the same Postgres server
	// whose name matches it, in addition to the DSN's own database (which
	// stays the default). DatabasesRE is its compiled form.
	Databases   string
	DatabasesRE *regexp.Regexp

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
	var dialect, readTables, writeTables, annotationTiers string
	fs.StringVar(&dialect, "dialect", "", "database dialect: postgres|clickhouse (required)")
	fs.StringVar(&c.DSN, "dsn", "", "database connection URL (or env DATABASE_URL; required)")
	fs.StringVar(&readTables, "read-tables", "", "comma-separated tables readable by the read tools; <schema>.* adds every table in the schema at boot (postgres only; required unless using columns-from-annotations)")
	fs.StringVar(&annotationTiers, "columns-from-annotations", "", "comma-separated @access classes whose columns are readable, e.g. safe or safe,pii; all other classes are denied (requires connection-level-security)")
	fs.DurationVar(&c.AnnotationRefreshInterval, "annotation-refresh-interval", 30*time.Second, "periodic catalog and column-grant refresh interval")
	fs.DurationVar(&c.AnnotationRefreshTimeout, "annotation-refresh-timeout", 10*time.Second, "maximum catalog/grant refresh and drain duration")
	fs.StringVar(&writeTables, "write-tables", "", "comma-separated tables writable by the write tools; <schema>.* adds every table in the schema at boot (postgres only; optional)")
	fs.BoolVar(&c.WritesEnabled, "dangerously-add-write-tools", false, "register the begin/execute/commit/rollback write tools (Postgres only)")
	fs.StringVar(&c.DefaultSchema, "default-schema", "", "schema used to resolve unqualified table names (postgres: public; clickhouse: database from DSN, else default)")
	fs.StringVar(&c.Transport, "transport", "http", "MCP transport: http|stdio")
	fs.StringVar(&c.Listen, "listen", "127.0.0.1:8080", "listen address for the http transport (MCP at /mcp, health at /healthz and /readyz)")
	fs.StringVar(&c.HealthListen, "health-listen", "", "optional second listen address serving only /healthz and /readyz, e.g. 0.0.0.0:8081 for kubelet probes while --listen stays on loopback")
	fs.IntVar(&c.MaxRows, "max-rows", 1000, "server cap on rows returned per call")
	fs.DurationVar(&c.StatementTimeout, "statement-timeout", 30*time.Second, "per-statement timeout applied at the database session")
	fs.DurationVar(&c.TxnIdleTimeout, "txn-idle-timeout", 2*time.Minute, "write transactions idle longer than this are rolled back")
	fs.DurationVar(&c.TxnMaxLifetime, "txn-max-lifetime", 5*time.Minute, "write transactions are rolled back this long after begin_transaction, however busy")
	fs.IntVar(&c.MaxOpenTxns, "max-open-txns", 8, "maximum concurrently open write transactions")
	fs.IntVar(&c.PoolMaxConns, "pool-max-conns", 16, "maximum read connections to the default database (write transactions add up to --max-open-txns)")
	fs.IntVar(&c.DatabasePoolMaxConns, "database-pool-max-conns", 4, "maximum read connections to each further --databases database")
	fs.BoolVar(&c.Tunnel, "tunnel", false, "start the Speakeasy Control Plane tunnel agent (requires TUNNEL_GATEWAY_URL and TUNNEL_KEY)")
	fs.BoolVar(&c.TunnelOnly, "tunnel-only", false, "refuse /mcp requests that did not arrive through the in-process Speakeasy Control Plane tunnel agent (requires --tunnel and --transport http)")
	fs.StringVar(&c.LogLevel, "log-level", "info", "log level: debug|info|warn|error")
	fs.BoolVar(&c.ConnectionLevelSecurity, "connection-level-security", false, "provision least-privilege database roles from the (bootstrap) DSN at boot and run all tool traffic as those roles")
	fs.StringVar(&c.SecurityRolePrefix, "security-role-prefix", "restrictedsql", "prefix of the roles provisioned by --connection-level-security (<prefix>_ro, <prefix>_rw)")
	fs.StringVar(&c.Databases, "databases", "", "regular expression naming further databases on the same server to serve alongside the DSN's database (postgres static table mode only); tools take an optional database argument")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected positional arguments: %v", fs.Args())
	}

	c.Dialect = policy.Dialect(strings.ToLower(strings.TrimSpace(dialect)))
	c.ReadTables, c.ReadSchemas = splitWildcards(splitList(readTables))
	c.AnnotationTiers = splitList(annotationTiers)
	annotationSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "columns-from-annotations" {
			annotationSet = true
		}
	})
	if annotationSet && len(c.AnnotationTiers) == 0 {
		return nil, errors.New("--columns-from-annotations requires at least one class")
	}
	c.WriteTables, c.WriteSchemas = splitWildcards(splitList(writeTables))
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
	if len(c.AnnotationTiers) > 0 {
		for _, tier := range c.AnnotationTiers {
			if !policy.ValidTierName(tier) {
				return fmt.Errorf("--columns-from-annotations: invalid class name %q (lowercase words joined by hyphens)", tier)
			}
		}
		if len(c.ReadTables) > 0 || len(c.ReadSchemas) > 0 {
			return errors.New("--columns-from-annotations and --read-tables are mutually exclusive")
		}
		if c.WritesEnabled || len(c.WriteTables) > 0 || len(c.WriteSchemas) > 0 {
			return errors.New("annotation mode is read-only; write flags are not supported")
		}
		if !c.ConnectionLevelSecurity {
			return errors.New("--columns-from-annotations requires --connection-level-security")
		}
		if c.AnnotationRefreshInterval <= 0 || c.AnnotationRefreshTimeout <= 0 {
			return errors.New("annotation refresh durations must be positive")
		}
	}
	if len(c.ReadTables) == 0 && len(c.ReadSchemas) == 0 && len(c.AnnotationTiers) == 0 {
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
	for flag, schemas := range map[string][]string{"--read-tables": c.ReadSchemas, "--write-tables": c.WriteSchemas} {
		for _, s := range schemas {
			if c.Dialect != policy.Postgres {
				return fmt.Errorf("%s: %s.* is supported on postgres only", flag, s)
			}
			if _, err := policy.ParseTableRef(s+".x", c.DefaultSchema, c.Dialect); err != nil {
				return fmt.Errorf("%s: invalid schema in %s.*: %w", flag, s, err)
			}
		}
	}
	if c.WritesEnabled {
		if c.Dialect == policy.ClickHouse {
			return errors.New("--dangerously-add-write-tools: write tools are not supported on clickhouse")
		}
		if len(c.WriteTables) == 0 && len(c.WriteSchemas) == 0 {
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
	if c.PoolMaxConns <= 0 || c.DatabasePoolMaxConns <= 0 {
		return errors.New("--pool-max-conns and --database-pool-max-conns must be greater than zero")
	}
	if c.TxnMaxLifetime <= 0 {
		return errors.New("--txn-max-lifetime must be greater than zero")
	}
	if c.MaxOpenTxns <= 0 {
		return errors.New("--max-open-txns must be greater than zero")
	}
	if c.HealthListen != "" {
		if c.Transport != "http" {
			return errors.New("--health-listen requires --transport http")
		}
		if c.HealthListen == c.Listen {
			return errors.New("--health-listen must differ from --listen")
		}
	}
	if c.TunnelOnly {
		if !c.Tunnel {
			return errors.New("--tunnel-only requires --tunnel")
		}
		if c.Transport != "http" {
			return errors.New("--tunnel-only requires --transport http")
		}
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
	if c.Databases != "" {
		if c.Dialect != policy.Postgres {
			return errors.New("--databases is supported on postgres only")
		}
		if len(c.AnnotationTiers) > 0 {
			return errors.New("--databases is not supported with --columns-from-annotations")
		}
		re, err := regexp.Compile(c.Databases)
		if err != nil {
			return fmt.Errorf("--databases: invalid regular expression: %w", err)
		}
		c.DatabasesRE = re
		if c.DefaultDatabase() == "" {
			return errors.New("--databases requires a URL-form DSN that names its database (postgres://user:password@host:port/database)")
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

// DefaultDatabase is the database named in the path of a URL-form DSN, or
// "" when the DSN does not name one.
func (c *Config) DefaultDatabase() string {
	u, err := url.Parse(c.DSN)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return strings.TrimPrefix(u.Path, "/")
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
	for _, tier := range c.AnnotationTiers {
		if p.AnnotationTiers == nil {
			p.AnnotationTiers = map[policy.Tier]bool{}
		}
		p.AnnotationTiers[policy.Tier(tier)] = true
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

// splitWildcards separates `<schema>.*` entries from plain table names.
func splitWildcards(entries []string) (tables, schemas []string) {
	for _, e := range entries {
		if s, ok := strings.CutSuffix(e, ".*"); ok {
			schemas = append(schemas, s)
			continue
		}
		tables = append(tables, e)
	}
	return tables, schemas
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
