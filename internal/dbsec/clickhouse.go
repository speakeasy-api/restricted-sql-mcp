package dbsec

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"

	"github.com/speakeasy-api/gram-restricted-sql-mcp/internal/policy"
)

// ClickHouseProvisioner replaces the <prefix>_ro user on every boot with a
// fresh sha256_password, pins readonly = 1 at the user (with the backend's
// per-query limits allowed only within the policy's caps), and grants SELECT
// on exactly the read tables plus the catalog visibility the metadata tools
// need. ClickHouse has no write tools, so there is no <prefix>_rw user.
type ClickHouseProvisioner struct {
	DSN    string
	Policy *policy.Policy
	Prefix string
	Logger *slog.Logger
}

func (p *ClickHouseProvisioner) readRole() string { return p.Prefix + "_ro" }

// Provision implements Provisioner.
func (p *ClickHouseProvisioner) Provision(ctx context.Context) (Creds, error) {
	log := p.Logger
	if log == nil {
		log = slog.Default()
	}
	password, err := NewPassword()
	if err != nil {
		return Creds{}, err
	}
	opts, err := clickhouse.ParseDSN(p.DSN)
	if err != nil {
		return Creds{}, fmt.Errorf("bootstrap connection: invalid clickhouse dsn")
	}
	if opts.DialTimeout == 0 {
		opts.DialTimeout = 10 * time.Second
	}
	opts.MaxOpenConns = 1
	opts.MaxIdleConns = 1
	conn, err := clickhouse.Open(opts)
	if err != nil {
		return Creds{}, fmt.Errorf("bootstrap connection: %w", err)
	}
	defer conn.Close()

	user := chIdent(p.readRole())
	readTables := sortedRefs(p.Policy.ReadTables)
	dbs := map[string]struct{}{}
	for _, t := range readTables {
		dbs[t.Schema] = struct{}{}
	}
	databases := sortedKeys(dbs)

	createSQL := fmt.Sprintf("CREATE USER OR REPLACE %s IDENTIFIED WITH sha256_password BY %s SETTINGS %s",
		user, chLiteral(password), p.settingsClause())
	stmts := []statement{{
		sql:     createSQL,
		display: fmt.Sprintf("CREATE USER OR REPLACE %s IDENTIFIED WITH sha256_password BY '<redacted>' SETTINGS %s", user, p.settingsClause()),
	}}
	stmts = append(stmts, plain("REVOKE ALL ON *.* FROM "+user))
	for _, t := range readTables {
		stmts = append(stmts, plain("GRANT SELECT ON "+chIdent(t.Schema)+"."+chIdent(t.Name)+" TO "+user))
	}
	for _, d := range databases {
		stmts = append(stmts, plain("GRANT SHOW TABLES, SHOW COLUMNS ON "+chIdent(d)+".* TO "+user))
	}
	stmts = append(stmts, plain("GRANT SELECT ON system.data_skipping_indices TO "+user))
	for _, st := range stmts {
		if err := conn.Exec(ctx, st.sql); err != nil {
			return Creds{}, &StatementError{Statement: st.display, Err: err}
		}
	}
	log.Info("clickhouse user provisioned",
		"read_role", p.readRole(),
		"read_role_select", refStrings(readTables),
		"show_tables_and_columns_on", databases,
		"password_rotated", true)

	readDSN, err := RewriteDSN(p.DSN, p.readRole(), password)
	if err != nil {
		return Creds{}, err
	}
	return Creds{ReadDSN: readDSN}, nil
}

// settingsClause pins readonly = 1 and lets the backend's per-query settings
// through only within the policy's caps (CHANGEABLE_IN_READONLY), so a
// caller can lower but never raise the limits.
func (p *ClickHouseProvisioner) settingsClause() string {
	timeout := math.Ceil(p.Policy.StatementTimeout.Seconds()*1000) / 1000
	maxRows := p.Policy.MaxRows + 1
	return strings.Join([]string{
		"readonly = 1 READONLY",
		fmt.Sprintf("max_execution_time = %g CHANGEABLE_IN_READONLY MIN 0 MAX %g", timeout, timeout),
		fmt.Sprintf("max_result_rows = %d CHANGEABLE_IN_READONLY MIN 0 MAX %d", maxRows, maxRows),
		"result_overflow_mode = 'break' CHANGEABLE_IN_READONLY",
	}, ", ")
}

// chLiteral quotes s as a ClickHouse string literal, where backslash escapes.
func chLiteral(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `'`, `\'`)
	return "'" + r.Replace(s) + "'"
}

// chIdent quotes an identifier with backticks.
func chIdent(s string) string {
	r := strings.NewReplacer("`", "\\`", `\`, `\\`)
	return "`" + r.Replace(s) + "`"
}
