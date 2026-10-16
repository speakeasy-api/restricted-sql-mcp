package sqlguard_test

// ClickHouse binder regression tests from the second independent review.
// Each case failed on commit 90f2b50.

import (
	"strings"
	"testing"

	"github.com/speakeasy-api/restricted-sql-mcp/internal/policy"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/sqlguard"
	chguard "github.com/speakeasy-api/restricted-sql-mcp/internal/sqlguard/clickhouse"
)

func review2CHPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	cat := &policy.Catalog{BuiltinFunctions: map[string]string{"count": "count", "arrayMap": "arrayMap"}}
	r := policy.Relation{Ref: policy.TableRef{Schema: "app", Name: "p"}, Identity: "p", Kind: "table"}
	for i, spec := range []struct {
		name string
		tier policy.Tier
	}{{"id", policy.Tier("safe")}, {"x", policy.Tier("safe")}, {"a", policy.Tier("safe")}, {"tup", policy.Tier("content")}, {"n.a", ""}, {"body", policy.Tier("content")}} {
		status := "valid"
		if spec.tier == "" {
			status = "not annotated"
		}
		r.Columns = append(r.Columns, policy.CatalogColumn{Name: spec.name, Identity: spec.name, Position: i + 1, AnnotationStatus: status, Tier: spec.tier})
	}
	cat.Relations = append(cat.Relations, r)
	if err := cat.Seal(); err != nil {
		t.Fatal(err)
	}
	return (&policy.Policy{Dialect: policy.ClickHouse, DefaultSchema: "app", AnnotationTiers: map[policy.Tier]bool{policy.Tier("safe"): true}}).WithCatalog(cat)
}

// A relation alias equal to a denied column name makes ClickHouse resolve
// alias.field as a subcolumn of that denied column (confirmed on 25.8: the
// server asks for SELECT(`tup.x`)), but the binder binds it to column x.
func TestReview2CHAliasShadowedBySubcolumn(t *testing.T) {
	p := review2CHPolicy(t)
	for _, sql := range []string{
		"SELECT tup.x AS r FROM p AS tup",
		"SELECT count() AS c FROM p AS tup WHERE tup.x = 'guess'",
		"SELECT n.a AS r FROM p AS n",
	} {
		t.Run(sql, func(t *testing.T) {
			if checked, err := chguard.New().Check(sql, sqlguard.ModeRead, p); err == nil {
				t.Fatalf("accepted; ClickHouse reads a denied subcolumn: %s columns=%v", checked.SQL, checked.Columns)
			}
		})
	}
}

// MapLiteral.KeyValues is []KeyValue (not an Expr), so the reflective walker
// never binds the values.
func TestReview2CHMapLiteralValuesBound(t *testing.T) {
	p := review2CHPolicy(t)
	sql := "SELECT id, {'k': body} AS m FROM p"
	if checked, err := chguard.New().Check(sql, sqlguard.ModeRead, p); err == nil {
		t.Fatalf("accepted with unbound denied column: %s columns=%v", checked.SQL, checked.Columns)
	}
}

// Alias inlining must preserve the alias expression's grouping and lexical
// scope; today it changes query results.
func TestReview2CHAliasInliningPreservesSemantics(t *testing.T) {
	p := review2CHPolicy(t)
	for sql, forbidden := range map[string]string{
		"SELECT id + 1 AS k, k * 2 AS r FROM p":                 "`app`.`p`.`id` + 1 * 2",
		"SELECT id - 1 AS k, 10 - k AS r FROM p":                "10 - `app`.`p`.`id` - 1",
		"SELECT id AS k, arrayMap(id -> k, [1000]) AS r FROM p": "arrayMap(id -> id,",
	} {
		t.Run(sql, func(t *testing.T) {
			checked, err := chguard.New().Check(sql, sqlguard.ModeRead, p)
			if err != nil {
				return // rejecting is acceptable
			}
			if strings.Contains(checked.SQL, forbidden) {
				t.Fatalf("canonical SQL changes semantics: %s", checked.SQL)
			}
		})
	}
}

// Inlined aliases keep their grouping, and aliases that do not collide with
// lambda parameters still work inside lambdas.
func TestClickHouseAliasInliningCanonicalForm(t *testing.T) {
	p := review2CHPolicy(t)
	for sql, want := range map[string]string{
		"SELECT id + 1 AS k, k * 2 AS r FROM p":                 "(`app`.`p`.`id` + 1) * 2",
		"SELECT id - 1 AS k, 10 - k AS r FROM p":                "10 - (`app`.`p`.`id` - 1)",
		"SELECT id AS k, arrayMap(v -> v + k, [1]) AS r FROM p": "arrayMap(v -> v + `app`.`p`.`id`",
		// A qualified path is not captured by the parameter (ClickHouse returns [1]).
		"SELECT id AS k, arrayMap(id -> k, [1000]) AS r FROM p": "arrayMap(id -> `app`.`p`.`id`",
		"WITH id + 1 AS k SELECT k * 2 AS r FROM p":             "(`app`.`p`.`id` + 1) * 2",
		"WITH id + 1 AS k SELECT k FROM p":                      "`app`.`p`.`id` + 1",
	} {
		t.Run(sql, func(t *testing.T) {
			checked, err := chguard.New().Check(sql, sqlguard.ModeRead, p)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(checked.SQL, want) {
				t.Fatalf("canonical SQL %s does not contain %s", checked.SQL, want)
			}
		})
	}
	// An ARRAY JOIN alias stays unqualified, so a same-named parameter would capture it.
	if _, err := chguard.New().Check("SELECT t AS k, arrayMap(t -> k, [1]) AS r FROM p ARRAY JOIN x AS t", sqlguard.ModeRead, p); err == nil {
		t.Fatal("alias captured by a lambda parameter was accepted")
	}
}
