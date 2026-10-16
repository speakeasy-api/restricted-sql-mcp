package dbsec

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/policy"
)

type ClickHouseAnnotations struct {
	DSN, Prefix string
	Logger      *slog.Logger
	password    string
}

// Match dynamic types inside wrappers such as Array(JSON), too.
var chDynamicType = regexp.MustCompile(`(^|[,( ])(JSON|Object)([(), ]|$)`)

func (p *ClickHouseAnnotations) role() string { return p.Prefix + "_ro" }
func (p *ClickHouseAnnotations) connect() (driver.Conn, error) {
	o, err := clickhouse.ParseDSN(p.DSN)
	if err != nil {
		return nil, err
	}
	o.MaxOpenConns = 1
	o.MaxIdleConns = 1
	return clickhouse.Open(o)
}
func (p *ClickHouseAnnotations) Load(ctx context.Context) (*policy.Catalog, error) {
	c, err := p.connect()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	cat := &policy.Catalog{}
	rows, err := c.Query(ctx, `SELECT name FROM system.databases WHERE name NOT IN ('system','INFORMATION_SCHEMA','information_schema') ORDER BY name`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			rows.Close()
			return nil, err
		}
		cat.Schemas = append(cat.Schemas, s)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = c.Query(ctx, `SELECT c.database,c.table,toString(t.uuid),t.engine,t.create_table_query,c.name,toUInt64(c.position),c.type,c.comment,c.default_kind,c.default_expression FROM system.columns c INNER JOIN system.tables t ON t.database=c.database AND t.name=c.table WHERE c.database NOT IN ('system','INFORMATION_SCHEMA','information_schema') AND NOT t.is_temporary ORDER BY c.database,c.table,c.position`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var ref policy.TableRef
		var identity, engine, definition, comment, defaultKind string
		var pos uint64
		var col policy.CatalogColumn
		if err := rows.Scan(&ref.Schema, &ref.Name, &identity, &engine, &definition, &col.Name, &pos, &col.Type, &comment, &defaultKind, &col.Definition); err != nil {
			rows.Close()
			return nil, err
		}
		if len(cat.Relations) == 0 || cat.Relations[len(cat.Relations)-1].Ref != ref {
			r := policy.Relation{Ref: ref, Identity: identity, Kind: "table", Engine: engine, Definition: definition}
			switch engine {
			case "View":
				r.Kind = "view"
			case "MaterializedView":
				r.Kind = "materialized_view"
			}
			switch engine {
			case "MergeTree", "Log", "TinyLog", "StripeLog", "Memory":
			default:
				r.Denial = "unsupported relation engine: dependency validation is required"
			}
			cat.Relations = append(cat.Relations, r)
		}
		col.Position = int(pos)
		col.Identity = identity + ":" + strconv.FormatUint(pos, 10) + ":" + col.Name
		col.Nullable = strings.Contains(col.Type, "Nullable(")
		policy.Annotate(&col, comment)
		if defaultKind != "" {
			col.Denial = "computed/default columns require dependency validation"
		}
		if strings.Contains(col.Type, "AggregateFunction(") || chDynamicType.MatchString(col.Type) {
			col.Denial = "dynamic and aggregate-state column types are not supported"
		}
		r := &cat.Relations[len(cat.Relations)-1]
		r.Columns = append(r.Columns, col)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	cat.BuiltinFunctions = map[string]string{}
	cat.CaseInsensitiveFunctions = map[string]string{}
	functions, err := c.Query(ctx, "SELECT name,case_insensitive FROM system.functions WHERE origin='System' ORDER BY name")
	if err != nil {
		return nil, err
	}
	for functions.Next() {
		var name string
		var insensitive uint8
		if err := functions.Scan(&name, &insensitive); err != nil {
			functions.Close()
			return nil, err
		}
		if policy.AllowedFunction(policy.ClickHouse, name) {
			cat.BuiltinFunctions[name] = name
			if insensitive != 0 {
				cat.CaseInsensitiveFunctions[strings.ToLower(name)] = name
			}
		}
	}
	functions.Close()
	if err := functions.Err(); err != nil {
		return nil, err
	}
	policies, err := c.Query(ctx, "SELECT database,table FROM system.row_policies")
	if err != nil {
		return nil, err
	}
	for policies.Next() {
		var database, table string
		if err := policies.Scan(&database, &table); err != nil {
			policies.Close()
			return nil, err
		}
		for i := range cat.Relations {
			r := &cat.Relations[i]
			if (database == "" || database == "*" || database == r.Ref.Schema) && (table == "" || table == "*" || table == r.Ref.Name) {
				r.Denial = "row policies require dependency validation"
			}
		}
	}
	policies.Close()
	if err := policies.Err(); err != nil {
		return nil, err
	}
	return cat, cat.Seal()
}
func (p *ClickHouseAnnotations) Reconcile(ctx context.Context, pol *policy.Policy) (Creds, error) {
	if p.password == "" {
		password, err := NewPassword()
		if err != nil {
			return Creds{}, err
		}
		p.password = password
	}
	c, err := p.connect()
	if err != nil {
		return Creds{}, err
	}
	defer c.Close()
	role := chIdent(p.role())
	settings := (&ClickHouseProvisioner{Policy: pol}).settingsClause() + ", prefer_column_name_to_alias = 1 READONLY, optimize_functions_to_subcolumns = 0 READONLY, enable_analyzer = 1 READONLY"
	// Keep a stable process credential, replacing all prior roles/settings/grants.
	sql := "CREATE USER OR REPLACE " + role + " IDENTIFIED WITH sha256_password BY " + chLiteral(p.password) + " SETTINGS " + settings
	if err := c.Exec(ctx, sql); err != nil {
		return Creds{}, fmt.Errorf("create annotation user failed (credentials redacted)")
	}
	for _, ref := range pol.AllTables() {
		cols := pol.ReadableColumns(ref)
		if len(cols) == 0 {
			continue
		}
		if err := c.Exec(ctx, "GRANT SELECT("+columnIdents(cols, chIdent)+") ON "+chIdent(ref.Schema)+"."+chIdent(ref.Name)+" TO "+role); err != nil {
			return Creds{}, err
		}
	}
	if err := verifyCHAnnotations(ctx, c, p.role(), pol); err != nil {
		return Creds{}, err
	}
	if p.Logger != nil {
		p.Logger.Info("annotation column grants reconciled", "read_role", p.role(), "generation", pol.Catalog.Digest)
	}
	dsn, err := RewriteDSN(p.DSN, p.role(), p.password)
	return Creds{ReadDSN: dsn}, err
}
func (p *ClickHouseAnnotations) Verify(ctx context.Context, pol *policy.Policy) error {
	c, err := p.connect()
	if err != nil {
		return err
	}
	defer c.Close()
	return verifyCHAnnotations(ctx, c, p.role(), pol)
}
func verifyCHAnnotations(ctx context.Context, c driver.Conn, role string, pol *policy.Policy) error {
	var users uint64
	if err := c.QueryRow(ctx, `SELECT count() FROM system.users WHERE name=?`, role).Scan(&users); err != nil {
		return err
	}
	if users != 1 {
		return fmt.Errorf("annotation user is missing")
	}
	var memberships uint64
	if err := c.QueryRow(ctx, `SELECT count() FROM system.role_grants WHERE user_name=?`, role).Scan(&memberships); err != nil {
		return err
	}
	if memberships != 0 {
		return fmt.Errorf("annotation role has excess memberships")
	}
	if err := verifyCHPinnedSettings(ctx, c, role); err != nil {
		return err
	}
	rows, err := c.Query(ctx, `SELECT access_type,coalesce(database,''),coalesce(table,''),coalesce(column,''),is_partial_revoke,grant_option FROM system.grants WHERE user_name=?`, role)
	if err != nil {
		return err
	}
	defer rows.Close()
	seen := map[policy.TableRef]map[string]bool{}
	for rows.Next() {
		var access, db, table, col string
		var revoke, grant uint8
		if err := rows.Scan(&access, &db, &table, &col, &revoke, &grant); err != nil {
			return err
		}
		ref := policy.TableRef{Schema: db, Name: table}
		if access != "SELECT" || revoke != 0 || grant != 0 || col == "" || !pol.CanReadColumn(ref, col) {
			return fmt.Errorf("column grants do not match policy for %s.%s", ref, col)
		}
		if seen[ref] == nil {
			seen[ref] = map[string]bool{}
		}
		seen[ref][col] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, ref := range pol.AllTables() {
		for _, col := range pol.ReadableColumns(ref) {
			if !seen[ref][col] {
				return fmt.Errorf("missing column grant for %s.%s", ref, col)
			}
		}
	}
	return nil
}
func (p *ClickHouseAnnotations) Close(ctx context.Context) error {
	c, err := p.connect()
	if err != nil {
		return err
	}
	defer c.Close()
	return c.Exec(ctx, "DROP USER IF EXISTS "+chIdent(p.role()))
}

// chPinnedSettings are settings the column binder relies on. They must stay
// at these values and be immutable (CONST) for the annotation user.
var chPinnedSettings = map[string]string{
	"readonly":                         "1",
	"enable_analyzer":                  "1",
	"prefer_column_name_to_alias":      "1",
	"optimize_functions_to_subcolumns": "0",
}

// verifyCHPinnedSettings detects drift from ALTER USER ... SETTINGS or an
// assigned settings profile while the catalog digest is unchanged.
func verifyCHPinnedSettings(ctx context.Context, c driver.Conn, role string) error {
	rows, err := c.Query(ctx, `SELECT coalesce(setting_name,''),coalesce(value,''),coalesce(toString(writability),''),coalesce(inherit_profile,'') FROM system.settings_profile_elements WHERE user_name=?`, role)
	if err != nil {
		return err
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var name, value, writability, profile string
		if err := rows.Scan(&name, &value, &writability, &profile); err != nil {
			return err
		}
		if profile != "" {
			return fmt.Errorf("annotation user inherits settings profile %q", profile)
		}
		want, pinned := chPinnedSettings[name]
		if !pinned {
			continue
		}
		if value != want || writability != "CONST" {
			return fmt.Errorf("annotation user setting %s drifted (value %q, %s)", name, value, writability)
		}
		seen[name] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for name := range chPinnedSettings {
		if !seen[name] {
			return fmt.Errorf("annotation user setting %s is not pinned", name)
		}
	}
	return nil
}
