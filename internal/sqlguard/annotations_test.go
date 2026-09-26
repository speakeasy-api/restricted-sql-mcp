package sqlguard_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/speakeasy-api/gram-restricted-sql-mcp/internal/policy"
	"github.com/speakeasy-api/gram-restricted-sql-mcp/internal/sqlguard"
	chguard "github.com/speakeasy-api/gram-restricted-sql-mcp/internal/sqlguard/clickhouse"
	pgguard "github.com/speakeasy-api/gram-restricted-sql-mcp/internal/sqlguard/postgres"
)

func annotationPolicy(t *testing.T, dialect policy.Dialect) *policy.Policy {
	t.Helper()
	cat := &policy.Catalog{BuiltinFunctions: map[string]string{"count": "count", "arrayMap": "arrayMap", "sum": "sum", "row_number": "row_number"}}
	for _, name := range []string{"records", "owners"} {
		r := policy.Relation{Ref: policy.TableRef{Schema: "app", Name: name}, Identity: name, Kind: "table"}
		for i, spec := range []struct {
			name string
			tier policy.Tier
		}{{"id", policy.Safe}, {"secret", policy.Secret}, {"tags", policy.Safe}} {
			r.Columns = append(r.Columns, policy.CatalogColumn{Name: spec.name, Identity: fmt.Sprint(i), Position: i + 1, AnnotationStatus: "valid", Tier: spec.tier})
		}
		cat.Relations = append(cat.Relations, r)
	}
	if err := cat.Seal(); err != nil {
		t.Fatal(err)
	}
	return (&policy.Policy{Dialect: dialect, DefaultSchema: "app", AnnotationTiers: map[policy.Tier]bool{policy.Safe: true}}).WithCatalog(cat)
}

func TestAnnotationGuardsRejectHiddenInputsWithoutDatabase(t *testing.T) {
	common := []string{
		"SELECT count(*) FROM records WHERE secret='x'",
		"SELECT id FROM records ORDER BY secret",
		"SELECT count(*) FROM records GROUP BY secret",
		"SELECT id FROM records GROUP BY id HAVING sum(secret)>0",
		"SELECT sum(id) OVER(PARTITION BY secret) AS total FROM records",
		"SELECT r.id FROM records r JOIN owners o ON r.secret=o.id",
		"WITH x AS (SELECT secret FROM records) SELECT 1",
		"SELECT x.exposed FROM (SELECT secret AS exposed FROM records) x",
		"SELECT id FROM records UNION ALL SELECT secret FROM owners",
		"SELECT * FROM records", "SELECT records FROM records",
	}
	for _, dialect := range []policy.Dialect{policy.Postgres, policy.ClickHouse} {
		t.Run(string(dialect), func(t *testing.T) {
			p := annotationPolicy(t, dialect)
			var g sqlguard.Guard = pgguard.New()
			corpus := append([]string{}, common...)
			if dialect == policy.ClickHouse {
				g = chguard.New()
				corpus = append(corpus, "SELECT id FROM records PREWHERE secret='x'", "SELECT id FROM records LIMIT 1 BY secret", "SELECT arrayMap(x -> secret,tags) AS values FROM records", "SELECT secret AS id FROM records")
			} else {
				corpus = append(corpus, "SELECT x.visible FROM records x(a,visible)", "SELECT count(*) FILTER(WHERE secret='x') FROM records", "SELECT r.id FROM records r WHERE EXISTS(SELECT o.id FROM owners o WHERE r.secret=o.id)", "SELECT r.id FROM records r CROSS JOIN LATERAL (SELECT r.secret) x")
			}
			for _, sql := range corpus {
				t.Run(sql, func(t *testing.T) {
					if checked, err := g.Check(sql, sqlguard.ModeRead, p); err == nil {
						t.Fatalf("guard permitted hidden input: %s", checked.SQL)
					}
				})
			}
		})
	}
}

func TestAnnotationGuardsKeepBindingsOnCanonicalRoundTrip(t *testing.T) {
	for _, dialect := range []policy.Dialect{policy.Postgres, policy.ClickHouse} {
		t.Run(string(dialect), func(t *testing.T) {
			p := annotationPolicy(t, dialect)
			var g sqlguard.Guard = pgguard.New()
			queries := []string{"SELECT r.id FROM records r ORDER BY r.id", "SELECT count(*) FROM records", "WITH x AS (SELECT id FROM records) SELECT id FROM x"}
			if dialect == policy.ClickHouse {
				g = chguard.New()
				queries = append(queries, "SELECT arrayMap(secret -> secret+1,tags) AS values FROM records")
			} else {
				queries = append(queries, "SELECT x.secret FROM records AS x(secret,visible)")
			}
			for _, sql := range queries {
				checked, err := g.Check(sql, sqlguard.ModeRead, p)
				if err != nil {
					t.Fatalf("%s: %v", sql, err)
				}
				again, err := g.Check(checked.SQL, sqlguard.ModeRead, p)
				if err != nil || !reflect.DeepEqual(checked.Columns, again.Columns) || checked.Generation != p.Catalog.Digest {
					t.Fatalf("round trip %s: %v", sql, err)
				}
				for _, cols := range checked.Columns {
					for _, col := range cols {
						if col == "secret" {
							t.Fatal("alias was confused with a base column")
						}
					}
				}
			}
		})
	}
}

func TestClickHouseAnnotationAliasExpansionIsBounded(t *testing.T) {
	var clauses []string
	clauses = append(clauses, "1 AS a0")
	for i := 1; i < 30; i++ {
		clauses = append(clauses, fmt.Sprintf("a%d+a%d AS a%d", i-1, i-1, i))
	}
	_, err := chguard.New().Check("WITH "+strings.Join(clauses, ",")+" SELECT a29 AS result", sqlguard.ModeRead, annotationPolicy(t, policy.ClickHouse))
	if err == nil || !strings.Contains(err.Error(), "expansion limit") {
		t.Fatalf("expansion was not bounded: %v", err)
	}
}

// PostgreSQL name-resolution shapes: accepted forms must match what
// PostgreSQL itself resolves, and every nearby form that would resolve to a
// denied column must still be rejected.
func TestPostgresAnnotationBinderFollowsPostgresResolution(t *testing.T) {
	p := annotationPolicy(t, policy.Postgres)
	g := pgguard.New()
	accept := []string{
		// Non-LATERAL derived tables may reference enclosing query levels.
		"SELECT r.id FROM records r WHERE EXISTS (SELECT 1 FROM (SELECT r.id AS a) s WHERE s.a > 0)",
		// Duplicate output labels with identical expressions.
		"SELECT id, id FROM records ORDER BY id",
		// Output labels inside grouping sets.
		"SELECT id AS k, count(*) FROM records GROUP BY GROUPING SETS ((k))",
		"SELECT id AS k, count(*) FROM records GROUP BY ROLLUP (k)",
		"SELECT id AS k, tags AS t, count(*) FROM records GROUP BY (k, t)",
		// GROUP BY prefers the output label over an outer-level column.
		"SELECT r.id FROM records r WHERE EXISTS (SELECT o.id AS secret, count(*) FROM (SELECT id FROM owners) o GROUP BY secret)",
	}
	reject := []string{
		"SELECT r.id FROM records r WHERE EXISTS (SELECT 1 FROM (SELECT r.secret AS a) s)",
		"SELECT s.a FROM records r, (SELECT r.id AS a) s",
		"SELECT id AS k, secret AS k FROM records ORDER BY k",
		"SELECT id AS k, tags AS k FROM records ORDER BY k",
		// GROUP BY resolves this level's input column before the output label.
		"SELECT id AS secret FROM records GROUP BY secret",
		"SELECT r.id FROM records r WHERE EXISTS (SELECT o.id AS secret, count(*) FROM owners o GROUP BY secret)",
		"SELECT count(*) FROM records GROUP BY GROUPING SETS ((secret))",
		"SELECT count(*) FROM records GROUP BY ROLLUP (secret)",
		"SELECT count(*) FROM records GROUP BY CUBE (id, secret)",
		"SELECT count(*) FROM records GROUP BY (id, secret)",
		"SELECT id AS k, count(*) FROM records GROUP BY GROUPING SETS ((k + 1))",
	}
	for _, sql := range accept {
		t.Run("accept/"+sql, func(t *testing.T) {
			if _, err := g.Check(sql, sqlguard.ModeRead, p); err != nil {
				t.Fatalf("rejected: %v", err)
			}
		})
	}
	for _, sql := range reject {
		t.Run("reject/"+sql, func(t *testing.T) {
			if checked, err := g.Check(sql, sqlguard.ModeRead, p); err == nil {
				t.Fatalf("accepted: %+v", checked)
			}
		})
	}
}
