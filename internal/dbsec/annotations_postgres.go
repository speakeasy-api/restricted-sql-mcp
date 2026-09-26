package dbsec

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/speakeasy-api/gram-restricted-sql-mcp/internal/policy"
)

type PostgresAnnotations struct {
	DSN, Prefix string
	Logger      *slog.Logger
	password    string
}

func (p *PostgresAnnotations) role() string { return p.Prefix + "_ro" }
func (p *PostgresAnnotations) connect(ctx context.Context) (*pgx.Conn, error) {
	return pgx.Connect(ctx, p.DSN)
}
func closePG(c *pgx.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = c.Close(ctx)
}
func (p *PostgresAnnotations) Load(ctx context.Context) (*policy.Catalog, error) {
	c, err := p.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer closePG(c)
	tx, err := c.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.Background())
	if err := checkPGResolutionHooks(ctx, tx); err != nil {
		return nil, err
	}
	cat := &policy.Catalog{}
	rows, err := tx.Query(ctx, `SELECT nspname FROM pg_catalog.pg_namespace WHERE nspname <> 'information_schema' AND nspname !~ '^pg_' ORDER BY nspname`)
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
	rows, err = tx.Query(ctx, `
 SELECT n.nspname,c.relname,c.oid::text,c.relkind::text,
 c.relrowsecurity OR EXISTS(SELECT 1 FROM pg_catalog.pg_inherits i WHERE i.inhrelid=c.oid OR i.inhparent=c.oid)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_rewrite w WHERE w.ev_class=c.oid)
 OR EXISTS(
   SELECT 1 FROM pg_catalog.pg_depend d
   LEFT JOIN pg_catalog.pg_proc f ON d.refclassid='pg_catalog.pg_proc'::pg_catalog.regclass AND f.oid=d.refobjid
   LEFT JOIN pg_catalog.pg_operator op ON d.refclassid='pg_catalog.pg_operator'::pg_catalog.regclass AND op.oid=d.refobjid
   LEFT JOIN pg_catalog.pg_opclass oc ON d.refclassid='pg_catalog.pg_opclass'::pg_catalog.regclass AND oc.oid=d.refobjid
   WHERE ((d.classid='pg_catalog.pg_class'::pg_catalog.regclass AND d.objid IN (SELECT i.indexrelid FROM pg_catalog.pg_index i WHERE i.indrelid=c.oid))
       OR (d.classid='pg_catalog.pg_constraint'::pg_catalog.regclass AND d.objid IN (SELECT co.oid FROM pg_catalog.pg_constraint co WHERE co.conrelid=c.oid)))
   AND (f.pronamespace<>'pg_catalog'::pg_catalog.regnamespace OR op.oprnamespace<>'pg_catalog'::pg_catalog.regnamespace OR oc.opcnamespace<>'pg_catalog'::pg_catalog.regnamespace))
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class ic ON ic.oid=i.indexrelid
   JOIN pg_catalog.pg_am am ON am.oid=ic.relam JOIN pg_catalog.pg_proc f ON f.oid=am.amhandler
   WHERE i.indrelid=c.oid AND f.pronamespace<>'pg_catalog'::pg_catalog.regnamespace),
 a.attname,a.attnum::int,pg_catalog.format_type(a.atttypid,a.atttypmod),NOT a.attnotnull,
 coalesce(pg_catalog.col_description(c.oid,a.attnum),''),a.attgenerated::text,
 tn.nspname='pg_catalog' AND t.typtype='b' AND (t.typelem=0 OR (etn.nspname='pg_catalog' AND et.typtype='b')),
 a.atttypid::text || ':' || a.atttypmod::text || ':' || a.attcollation::text || ':' || coalesce(pg_catalog.pg_get_expr(ad.adbin,ad.adrelid),'')
 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
 JOIN pg_catalog.pg_type t ON t.oid=a.atttypid JOIN pg_catalog.pg_namespace tn ON tn.oid=t.typnamespace
 LEFT JOIN pg_catalog.pg_type et ON et.oid=t.typelem LEFT JOIN pg_catalog.pg_namespace etn ON etn.oid=et.typnamespace
 LEFT JOIN pg_catalog.pg_attrdef ad ON ad.adrelid=c.oid AND ad.adnum=a.attnum
 WHERE n.nspname <> 'information_schema' AND n.nspname !~ '^pg_' AND c.relkind IN ('r','p','v','m','f')
 ORDER BY n.nspname,c.relname,a.attnum`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var ref policy.TableRef
		var oid, kind, comment, generated string
		var indirect, builtin bool
		var col policy.CatalogColumn
		if err := rows.Scan(&ref.Schema, &ref.Name, &oid, &kind, &indirect, &col.Name, &col.Position, &col.Type, &col.Nullable, &comment, &generated, &builtin, &col.Definition); err != nil {
			rows.Close()
			return nil, err
		}
		if len(cat.Relations) == 0 || cat.Relations[len(cat.Relations)-1].Ref != ref {
			r := policy.Relation{Ref: ref, Identity: oid, Kind: "table"}
			switch kind {
			case "v":
				r.Kind = "view"
			case "m":
				r.Kind = "materialized_view"
			case "f":
				r.Kind = "foreign_table"
			}
			if kind != "r" || indirect {
				r.Denial = "unsupported relation: views, inheritance, policies, rewrite rules and custom index/constraint dependencies require validation"
			}
			cat.Relations = append(cat.Relations, r)
		}
		col.Identity = oid + ":" + strconv.Itoa(col.Position)
		policy.Annotate(&col, comment)
		if !builtin {
			col.Denial = "unsupported column type: only built-in scalar and array types are supported"
		}
		if generated != "" {
			col.Denial = "generated columns require dependency validation"
		}
		r := &cat.Relations[len(cat.Relations)-1]
		r.Columns = append(r.Columns, col)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	constraints, err := tx.Query(ctx, `SELECT n.nspname,c.relname,co.conname,co.contype::text,
 ARRAY(SELECT a.attname::text FROM unnest(co.conkey) WITH ORDINALITY k(num,ord) JOIN pg_catalog.pg_attribute a ON a.attrelid=co.conrelid AND a.attnum=k.num ORDER BY k.ord),
 coalesce(fn.nspname,''),coalesce(fc.relname,''),
 ARRAY(SELECT a.attname::text FROM unnest(co.confkey) WITH ORDINALITY k(num,ord) JOIN pg_catalog.pg_attribute a ON a.attrelid=co.confrelid AND a.attnum=k.num ORDER BY k.ord)
 FROM pg_catalog.pg_constraint co JOIN pg_catalog.pg_class c ON c.oid=co.conrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 LEFT JOIN pg_catalog.pg_class fc ON fc.oid=co.confrelid LEFT JOIN pg_catalog.pg_namespace fn ON fn.oid=fc.relnamespace
 WHERE n.nspname <> 'information_schema' AND n.nspname !~ '^pg_' ORDER BY n.nspname,c.relname,co.conname`)
	if err != nil {
		return nil, err
	}
	byRef := map[policy.TableRef]*policy.Relation{}
	for i := range cat.Relations {
		byRef[cat.Relations[i].Ref] = &cat.Relations[i]
	}
	for constraints.Next() {
		var ref, target policy.TableRef
		var constraint policy.CatalogConstraint
		var kind string
		if err := constraints.Scan(&ref.Schema, &ref.Name, &constraint.Name, &kind, &constraint.Columns, &target.Schema, &target.Name, &constraint.ReferencedColumns); err != nil {
			constraints.Close()
			return nil, err
		}
		switch kind {
		case "p":
			constraint.Kind = "primary_key"
		case "u":
			constraint.Kind = "unique"
		case "f":
			constraint.Kind = "foreign_key"
		case "c":
			constraint.Kind = "check"
		case "x":
			constraint.Kind = "exclusion"
		default:
			constraint.Kind = kind
		}
		if target.Name != "" {
			constraint.ReferencedTable = &target
		}
		if r := byRef[ref]; r != nil {
			r.Constraints = append(r.Constraints, constraint)
		}
	}
	constraints.Close()
	if err := constraints.Err(); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return cat, cat.Seal()
}
func (p *PostgresAnnotations) Reconcile(ctx context.Context, pol *policy.Policy) (Creds, error) {
	if p.password == "" {
		pass, err := NewPassword()
		if err != nil {
			return Creds{}, err
		}
		p.password = pass
	}
	c, err := p.connect(ctx)
	if err != nil {
		return Creds{}, err
	}
	defer closePG(c)
	tx, err := c.Begin(ctx)
	if err != nil {
		return Creds{}, err
	}
	defer tx.Rollback(context.Background())
	schemas, err := revocableSchemas(ctx, tx)
	if err != nil {
		return Creds{}, err
	}
	stmts, err := roleStatements(p.role(), p.password, true, pol, schemas)
	if err != nil {
		return Creds{}, err
	}
	stmts = append(stmts, plain("ALTER ROLE "+pgx.Identifier{p.role()}.Sanitize()+" NOBYPASSRLS"), plain("ALTER ROLE "+pgx.Identifier{p.role()}.Sanitize()+" SET search_path = pg_catalog"))
	for _, ref := range pol.AllTables() {
		cols := pol.ReadableColumns(ref)
		if len(cols) == 0 {
			continue
		}
		quote := func(s string) string { return pgx.Identifier{s}.Sanitize() }
		stmts = append(stmts, plain("GRANT USAGE ON SCHEMA "+quote(ref.Schema)+" TO "+quote(p.role())), plain("GRANT SELECT ("+columnIdents(cols, quote)+") ON "+refIdent(ref)+" TO "+quote(p.role())))
	}
	if err := runStatements(ctx, tx, stmts); err != nil {
		return Creds{}, err
	}
	if err := verifyPGAnnotations(ctx, tx, p.role(), pol); err != nil {
		return Creds{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Creds{}, err
	}
	if p.Logger != nil {
		p.Logger.Info("annotation column grants reconciled", "read_role", p.role(), "generation", pol.Catalog.Digest)
	}
	dsn, err := RewriteDSN(p.DSN, p.role(), p.password)
	return Creds{ReadDSN: dsn}, err
}
func (p *PostgresAnnotations) Verify(ctx context.Context, pol *policy.Policy) error {
	c, err := p.connect(ctx)
	if err != nil {
		return err
	}
	defer closePG(c)
	tx, err := c.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	return verifyPGAnnotations(ctx, tx, p.role(), pol)
}
func verifyPGAnnotations(ctx context.Context, tx pgx.Tx, role string, pol *policy.Policy) error {
	var broad bool
	if err := tx.QueryRow(ctx, `SELECT rolsuper OR rolcreaterole OR rolcreatedb OR rolbypassrls OR EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members WHERE member=r.oid) FROM pg_catalog.pg_roles r WHERE rolname=$1`, role).Scan(&broad); err != nil {
		return err
	}
	if broad {
		return fmt.Errorf("annotation role has excess attributes or memberships")
	}
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname <> 'information_schema' AND n.nspname !~ '^pg_' AND (n.nspowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=$1) OR pg_catalog.has_schema_privilege($1,n.oid,'CREATE')))`, role).Scan(&broad); err != nil {
		return err
	}
	if broad {
		return fmt.Errorf("annotation role has schema ownership or CREATE access (including PUBLIC)")
	}
	rows, err := tx.Query(ctx, `SELECT n.nspname,c.relname,a.attname,
 pg_catalog.has_column_privilege($1,c.oid,a.attnum,'SELECT'),
 pg_catalog.has_table_privilege($1,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 OR pg_catalog.has_column_privilege($1,c.oid,a.attnum,'INSERT,UPDATE,REFERENCES,SELECT WITH GRANT OPTION'),
 c.relowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=$1)
 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
 WHERE n.nspname <> 'information_schema' AND n.nspname !~ '^pg_' AND c.relkind IN ('r','p','v','m','f')`, role)
	if err != nil {
		return err
	}
	defer rows.Close()
	seen := map[policy.TableRef]map[string]bool{}
	for rows.Next() {
		var ref policy.TableRef
		var name string
		var allowed, table, owner bool
		if err := rows.Scan(&ref.Schema, &ref.Name, &name, &allowed, &table, &owner); err != nil {
			return err
		}
		if table || owner || allowed != pol.CanReadColumn(ref, name) {
			return fmt.Errorf("column grants do not match policy for %s.%s (including PUBLIC or inherited access)", ref, name)
		}
		if seen[ref] == nil {
			seen[ref] = map[string]bool{}
		}
		seen[ref][name] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, ref := range pol.AllTables() {
		for _, name := range pol.ReadableColumns(ref) {
			if !seen[ref][name] {
				return fmt.Errorf("catalog changed while granting %s.%s", ref, name)
			}
		}
	}
	return nil
}
func (p *PostgresAnnotations) Close(ctx context.Context) error {
	c, err := p.connect(ctx)
	if err != nil {
		return err
	}
	defer closePG(c)
	role := pgx.Identifier{p.role()}.Sanitize()
	tx, err := c.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	schemas, err := revocableSchemas(ctx, tx)
	if err != nil {
		return err
	}
	for _, schema := range schemas {
		sid := pgx.Identifier{schema}.Sanitize()
		for _, sql := range []string{"REVOKE ALL ON ALL TABLES IN SCHEMA " + sid + " FROM " + role, "REVOKE ALL ON SCHEMA " + sid + " FROM " + role} {
			if _, err := tx.Exec(ctx, sql); err != nil {
				return err
			}
		}
	}
	if _, err := tx.Exec(ctx, "DROP ROLE "+role); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// checkPGResolutionHooks rejects catalogs where PostgreSQL resolves
// operations to non-pg_catalog code by type OID rather than by name. The
// pg_catalog search path and name qualification cannot govern these paths:
// cast lookup (explicit, implicit and array element coercion) and default
// encoding conversions. Such installations are unsupported until their
// functions can be validated, so the refresh fails and admission stays closed.
//
// Only hooks reachable from guarded SQL count. Annotation mode admits
// built-in column types, pg_catalog type names and pg_catalog functions, so
// every expression has a built-in type; a cast is reachable only when both
// ends are pg_catalog types. Extension casts (for example pgvector's) always
// involve an extension type and are ignored. Default conversions are found
// through the search path, which is pinned to pg_catalog.
func checkPGResolutionHooks(ctx context.Context, tx pgx.Tx) error {
	rows, err := tx.Query(ctx, `
 SELECT 'cast ' || pg_catalog.format_type(c.castsource,NULL) || ' AS ' || pg_catalog.format_type(c.casttarget,NULL) || ' via ' || n.nspname || '.' || p.proname
 FROM pg_catalog.pg_cast c JOIN pg_catalog.pg_proc p ON p.oid=c.castfunc JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
 JOIN pg_catalog.pg_type st ON st.oid=c.castsource JOIN pg_catalog.pg_type tt ON tt.oid=c.casttarget
 WHERE c.castmethod='f' AND n.nspname<>'pg_catalog'
 AND st.typnamespace='pg_catalog'::pg_catalog.regnamespace AND tt.typnamespace='pg_catalog'::pg_catalog.regnamespace
 UNION ALL
 SELECT 'default conversion ' || cn.nspname || '.' || v.conname || ' via ' || n.nspname || '.' || p.proname
 FROM pg_catalog.pg_conversion v JOIN pg_catalog.pg_namespace cn ON cn.oid=v.connamespace
 JOIN pg_catalog.pg_proc p ON p.oid=v.conproc JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
 WHERE v.condefault AND cn.nspname='pg_catalog' AND n.nspname<>'pg_catalog'
 ORDER BY 1 LIMIT 5`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var found []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return err
		}
		found = append(found, s)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(found) > 0 {
		return fmt.Errorf("unsupported catalog: user-defined casts/conversions execute non-pg_catalog functions (%s)", strings.Join(found, "; "))
	}
	return nil
}
