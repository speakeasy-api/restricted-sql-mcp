package chbackend

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/speakeasy-api/restricted-sql-mcp/internal/db"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/policy"
)

func (b *Backend) ListSchemas(ctx context.Context) ([]db.Schema, error) {
	qctx, cancel := b.readCtx(ctx, 0)
	defer cancel()
	rows, err := b.conn.Query(qctx, "SELECT name, engine, comment FROM system.databases ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []db.Schema
	for rows.Next() {
		var name, engine, comment string
		if err := rows.Scan(&name, &engine, &comment); err != nil {
			return nil, err
		}
		desc := engine
		if comment != "" {
			desc = engine + ": " + comment
		}
		out = append(out, db.Schema{Name: name, Description: desc})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	b.log.Debug("schemas listed", "count", len(out))
	return out, nil
}

func objectType(engine string) string {
	switch engine {
	case "View":
		return "view"
	case "MaterializedView", "LiveView", "WindowView":
		return "materialized_view"
	case "Dictionary":
		return "dictionary"
	}
	return "table"
}

func (b *Backend) ListObjects(ctx context.Context, schema, objType string) ([]db.Object, error) {
	switch objType {
	case "", "table", "view":
	case "sequence", "extension":
		return []db.Object{}, nil
	default:
		return nil, fmt.Errorf("unsupported object_type %q", objType)
	}
	qctx, cancel := b.readCtx(ctx, 0)
	defer cancel()
	rows, err := b.conn.Query(qctx,
		"SELECT name, engine, total_rows, total_bytes FROM system.tables WHERE database = ? ORDER BY name", schema)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []db.Object{}
	for rows.Next() {
		var (
			name, engine string
			totalRows    *uint64
			totalBytes   *uint64
		)
		if err := rows.Scan(&name, &engine, &totalRows, &totalBytes); err != nil {
			return nil, err
		}
		o := db.Object{Name: name, Engine: engine, Type: objectType(engine)}
		o.RowEstimate = toInt64(totalRows)
		o.SizeBytes = toInt64(totalBytes)
		switch objType {
		case "table":
			if o.Type != "table" {
				continue
			}
		case "view":
			if o.Type != "view" && o.Type != "materialized_view" {
				continue
			}
		}
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	b.log.Debug("objects listed", "schema", schema, "type", objType, "count", len(out))
	return out, nil
}

func toInt64(v *uint64) *int64 {
	if v == nil {
		return nil
	}
	n := int64(*v)
	return &n
}

func (b *Backend) ObjectDetails(ctx context.Context, ref policy.TableRef) (*db.ObjectDetails, error) {
	qctx, cancel := b.readCtx(ctx, 0)
	defer cancel()
	rows, err := b.conn.Query(qctx,
		"SELECT engine, sorting_key, partition_key, total_rows, total_bytes, comment FROM system.tables WHERE database = ? AND name = ?",
		ref.Schema, ref.Name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("object not found: %s", ref)
	}
	var (
		totalRows, totalBytes *uint64
	)
	d := &db.ObjectDetails{Schema: ref.Schema, Name: ref.Name, Constraints: []db.Constraint{}, Indexes: []db.Index{}}
	if err := rows.Scan(&d.Engine, &d.SortingKey, &d.PartitionKey, &totalRows, &totalBytes, &d.Description); err != nil {
		return nil, err
	}
	rows.Close()
	d.Type = objectType(d.Engine)
	d.RowEstimate = toInt64(totalRows)
	d.SizeBytes = toInt64(totalBytes)

	cols, err := b.conn.Query(qctx,
		"SELECT name, type, default_expression, comment FROM system.columns WHERE database = ? AND table = ? ORDER BY position",
		ref.Schema, ref.Name)
	if err != nil {
		return nil, err
	}
	defer cols.Close()
	for cols.Next() {
		var c db.ColumnDetail
		if err := cols.Scan(&c.Name, &c.Type, &c.Default, &c.Description); err != nil {
			return nil, err
		}
		c.Nullable = strings.HasPrefix(c.Type, "Nullable(")
		d.Columns = append(d.Columns, c)
	}
	if err := cols.Err(); err != nil {
		return nil, err
	}

	idx, err := b.conn.Query(qctx,
		"SELECT name, type_full, granularity FROM system.data_skipping_indices WHERE database = ? AND table = ? ORDER BY name",
		ref.Schema, ref.Name)
	if err != nil {
		return nil, err
	}
	defer idx.Close()
	for idx.Next() {
		var (
			name, typeFull string
			granularity    uint64
		)
		if err := idx.Scan(&name, &typeFull, &granularity); err != nil {
			return nil, err
		}
		d.Indexes = append(d.Indexes, db.Index{
			Name:       name,
			Definition: typeFull + " GRANULARITY " + strconv.FormatUint(granularity, 10),
		})
	}
	if err := idx.Err(); err != nil {
		return nil, err
	}
	b.log.Debug("object described", "object", ref.String(), "columns", len(d.Columns), "indexes", len(d.Indexes))
	return d, nil
}
