package pgbackend

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/ThomasRooney/gram-restrictedsql-tunnel-mcp/internal/db"
	"github.com/ThomasRooney/gram-restrictedsql-tunnel-mcp/internal/policy"
)

// ListSchemas returns every namespace except toast and temp schemas. Catalog
// visibility is deliberately unrestricted; only execution is.
func (b *Backend) ListSchemas(ctx context.Context) ([]db.Schema, error) {
	const q = `
SELECT n.nspname,
       pg_get_userbyid(n.nspowner),
       coalesce(obj_description(n.oid, 'pg_namespace'), '')
FROM pg_namespace n
WHERE n.nspname <> 'pg_toast'
  AND n.nspname NOT LIKE 'pg\_temp\_%'
  AND n.nspname NOT LIKE 'pg\_toast\_temp\_%'
ORDER BY n.nspname`
	rows, err := b.read.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list schemas: %w", err)
	}
	defer rows.Close()
	out := []db.Schema{}
	for rows.Next() {
		var s db.Schema
		if err := rows.Scan(&s.Name, &s.Owner, &s.Description); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list schemas: %w", err)
	}
	b.log.Debug("schemas listed", "count", len(out))
	return out, nil
}

// ListObjects lists relations of the requested type in a schema; an empty
// type returns tables, views, sequences and extensions together.
func (b *Backend) ListObjects(ctx context.Context, schema, objectType string) ([]db.Object, error) {
	var kinds []string
	withExtensions := false
	switch objectType {
	case "":
		kinds = []string{"r", "p", "v", "m", "S"}
		withExtensions = true
	case "table":
		kinds = []string{"r", "p"}
	case "view":
		kinds = []string{"v", "m"}
	case "sequence":
		kinds = []string{"S"}
	case "extension":
		withExtensions = true
	default:
		return nil, fmt.Errorf("unknown object_type %q (want table, view, sequence or extension)", objectType)
	}
	out := []db.Object{}
	if len(kinds) > 0 {
		rels, err := b.listRelations(ctx, schema, kinds)
		if err != nil {
			return nil, err
		}
		out = append(out, rels...)
	}
	if withExtensions {
		exts, err := b.listExtensions(ctx, schema)
		if err != nil {
			return nil, err
		}
		out = append(out, exts...)
	}
	b.log.Debug("objects listed", "schema", schema, "object_type", objectType, "count", len(out))
	return out, nil
}

func (b *Backend) listRelations(ctx context.Context, schema string, kinds []string) ([]db.Object, error) {
	const q = `
SELECT c.relname, c.relkind::text, c.reltuples::bigint, pg_total_relation_size(c.oid)
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = $1 AND c.relkind::text = ANY($2::text[])
ORDER BY c.relname`
	rows, err := b.read.Query(ctx, q, schema, kinds)
	if err != nil {
		return nil, fmt.Errorf("list objects: %w", err)
	}
	defer rows.Close()
	var out []db.Object
	for rows.Next() {
		var name, kind string
		var tuples, size int64
		if err := rows.Scan(&name, &kind, &tuples, &size); err != nil {
			return nil, err
		}
		o := db.Object{Name: name, Type: relkindType(kind)}
		if kind != "v" {
			o.SizeBytes = &size
		}
		if tuples >= 0 && (kind == "r" || kind == "p" || kind == "m") {
			o.RowEstimate = &tuples
		}
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list objects: %w", err)
	}
	return out, nil
}

func (b *Backend) listExtensions(ctx context.Context, schema string) ([]db.Object, error) {
	const q = `
SELECT e.extname
FROM pg_extension e
JOIN pg_namespace n ON n.oid = e.extnamespace
WHERE n.nspname = $1
ORDER BY e.extname`
	rows, err := b.read.Query(ctx, q, schema)
	if err != nil {
		return nil, fmt.Errorf("list extensions: %w", err)
	}
	defer rows.Close()
	var out []db.Object
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, db.Object{Name: name, Type: "extension"})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list extensions: %w", err)
	}
	return out, nil
}

func relkindType(kind string) string {
	switch kind {
	case "r", "p":
		return "table"
	case "v":
		return "view"
	case "m":
		return "materialized_view"
	case "S":
		return "sequence"
	case "f":
		return "foreign_table"
	}
	return kind
}

// ObjectDetails describes one relation: columns, constraints, indexes, size,
// row estimate and comment.
func (b *Backend) ObjectDetails(ctx context.Context, ref policy.TableRef) (*db.ObjectDetails, error) {
	const relQ = `
SELECT c.oid, c.relkind::text, c.reltuples::bigint, pg_total_relation_size(c.oid),
       coalesce(obj_description(c.oid, 'pg_class'), '')
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = $1 AND c.relname = $2 AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')`
	var (
		oid    uint32
		kind   string
		tuples int64
		size   int64
		desc   string
	)
	err := b.read.QueryRow(ctx, relQ, ref.Schema, ref.Name).Scan(&oid, &kind, &tuples, &size, &desc)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("object not found: %s", ref)
	}
	if err != nil {
		return nil, fmt.Errorf("describe %s: %w", ref, err)
	}
	d := &db.ObjectDetails{
		Schema:      ref.Schema,
		Name:        ref.Name,
		Type:        relkindType(kind),
		Columns:     []db.ColumnDetail{},
		Constraints: []db.Constraint{},
		Indexes:     []db.Index{},
		Description: desc,
	}
	if kind != "v" {
		d.SizeBytes = &size
	}
	if tuples >= 0 && (kind == "r" || kind == "p" || kind == "m") {
		d.RowEstimate = &tuples
	}

	const colQ = `
SELECT a.attname,
       format_type(a.atttypid, a.atttypmod),
       NOT a.attnotnull,
       coalesce(pg_get_expr(ad.adbin, ad.adrelid), ''),
       coalesce(col_description(a.attrelid, a.attnum), '')
FROM pg_attribute a
LEFT JOIN pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
WHERE a.attrelid = $1 AND a.attnum > 0 AND NOT a.attisdropped
ORDER BY a.attnum`
	rows, err := b.read.Query(ctx, colQ, oid)
	if err != nil {
		return nil, fmt.Errorf("describe columns of %s: %w", ref, err)
	}
	for rows.Next() {
		var c db.ColumnDetail
		if err := rows.Scan(&c.Name, &c.Type, &c.Nullable, &c.Default, &c.Description); err != nil {
			rows.Close()
			return nil, err
		}
		d.Columns = append(d.Columns, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("describe columns of %s: %w", ref, err)
	}

	const conQ = `
SELECT conname, contype::text, pg_get_constraintdef(oid)
FROM pg_constraint
WHERE conrelid = $1
ORDER BY conname`
	rows, err = b.read.Query(ctx, conQ, oid)
	if err != nil {
		return nil, fmt.Errorf("describe constraints of %s: %w", ref, err)
	}
	for rows.Next() {
		var c db.Constraint
		var contype string
		if err := rows.Scan(&c.Name, &contype, &c.Definition); err != nil {
			rows.Close()
			return nil, err
		}
		c.Type = constraintType(contype)
		d.Constraints = append(d.Constraints, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("describe constraints of %s: %w", ref, err)
	}

	const idxQ = `
SELECT i.relname, pg_get_indexdef(x.indexrelid), pg_relation_size(x.indexrelid)
FROM pg_index x
JOIN pg_class i ON i.oid = x.indexrelid
WHERE x.indrelid = $1
ORDER BY i.relname`
	rows, err = b.read.Query(ctx, idxQ, oid)
	if err != nil {
		return nil, fmt.Errorf("describe indexes of %s: %w", ref, err)
	}
	for rows.Next() {
		var ix db.Index
		var isize int64
		if err := rows.Scan(&ix.Name, &ix.Definition, &isize); err != nil {
			rows.Close()
			return nil, err
		}
		ix.SizeBytes = &isize
		d.Indexes = append(d.Indexes, ix)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("describe indexes of %s: %w", ref, err)
	}

	b.log.Debug("object described", "object", ref.String(), "type", d.Type,
		"columns", len(d.Columns), "constraints", len(d.Constraints), "indexes", len(d.Indexes))
	return d, nil
}

func constraintType(contype string) string {
	switch contype {
	case "p":
		return "primary_key"
	case "f":
		return "foreign_key"
	case "u":
		return "unique"
	case "c":
		return "check"
	case "x":
		return "exclusion"
	case "n":
		return "not_null"
	case "t":
		return "trigger"
	}
	return contype
}
