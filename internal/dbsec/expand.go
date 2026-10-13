package dbsec

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/speakeasy-api/gram-restricted-sql-mcp/internal/policy"
)

// ExpandSchemas adds every table in readSchemas to pol.ReadTables and every
// base table in writeSchemas to pol.WriteTables, as they exist at boot.
// Tables created later are not covered until the process restarts. It must
// run before pol is shared.
func ExpandSchemas(ctx context.Context, dsn string, pol *policy.Policy, readSchemas, writeSchemas []string) error {
	if len(readSchemas) == 0 && len(writeSchemas) == 0 {
		return nil
	}
	c, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return fmt.Errorf("expand schema wildcards: %w", err)
	}
	defer closePG(c)
	add := func(schemas []string, kinds []string, into map[policy.TableRef]struct{}) error {
		for _, s := range schemas {
			rows, err := c.Query(ctx, `SELECT c.relname FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = $1 AND c.relkind = ANY($2) AND NOT c.relispartition
ORDER BY c.relname`, s, kinds)
			if err != nil {
				return fmt.Errorf("expand %s.*: %w", s, err)
			}
			names, err := pgx.CollectRows(rows, pgx.RowTo[string])
			if err != nil {
				return fmt.Errorf("expand %s.*: %w", s, err)
			}
			if len(names) == 0 {
				return fmt.Errorf("expand %s.*: schema has no tables", s)
			}
			for _, name := range names {
				into[policy.TableRef{Schema: s, Name: name}] = struct{}{}
			}
		}
		return nil
	}
	if err := add(readSchemas, []string{"r", "p", "v", "m", "f"}, pol.ReadTables); err != nil {
		return err
	}
	return add(writeSchemas, []string{"r", "p"}, pol.WriteTables)
}
