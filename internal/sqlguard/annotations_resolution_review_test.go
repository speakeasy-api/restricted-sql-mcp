package sqlguard_test

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/speakeasy-api/gram-restricted-sql-mcp/internal/policy"
	"github.com/speakeasy-api/gram-restricted-sql-mcp/internal/sqlguard"
	pgguard "github.com/speakeasy-api/gram-restricted-sql-mcp/internal/sqlguard/postgres"
)

// This corpus is also run against PostgreSQL and the MCP server in e2e.
// These tests deliberately assert the contract, not today's implementation.
func TestPostgresResolutionReviewUnit(t *testing.T) {
	var cases []struct {
		Name, SQL, Denial string
		Allowed           bool
		Columns           map[string][]string
	}
	raw, err := os.ReadFile("testdata/postgres_resolution_review.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	cat := &policy.Catalog{}
	for _, name := range []string{"a", "b"} {
		r := policy.Relation{Ref: policy.TableRef{Schema: "review", Name: name}, Kind: "table", Identity: name}
		for i, col := range []string{"id", "k", "content", "secret", "restricted", "txt"} {
			tier := policy.Safe
			if col == "content" || col == "secret" || col == "restricted" {
				tier = policy.Tier(col)
			}
			r.Columns = append(r.Columns, policy.CatalogColumn{Name: col, Position: i + 1, Identity: name + "." + col, Tier: tier, AnnotationStatus: "valid"})
		}
		cat.Relations = append(cat.Relations, r)
	}
	if err := cat.Seal(); err != nil {
		t.Fatal(err)
	}
	pol := (&policy.Policy{Dialect: policy.Postgres, DefaultSchema: "review", AnnotationTiers: map[policy.Tier]bool{policy.Safe: true}}).WithCatalog(cat)
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			got, err := pgguard.New().Check(tc.SQL, sqlguard.ModeRead, pol)
			if !tc.Allowed {
				if err == nil {
					t.Fatalf("denied %s input accepted: %s", tc.Denial, got.SQL)
				}
				if !strings.Contains(err.Error(), tc.Denial) {
					t.Fatalf("expected tier-specific rejection for %s; got %v", tc.SQL, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("safe PostgreSQL query rejected: %s: %v", tc.SQL, err)
			}
			actual := map[string][]string{}
			for ref, cols := range got.Columns {
				actual[ref.Name] = append([]string{}, cols...)
				sort.Strings(actual[ref.Name])
			}
			for _, cols := range tc.Columns {
				sort.Strings(cols)
			}
			if !reflect.DeepEqual(actual, tc.Columns) {
				t.Errorf("column identities: got %v want %v", actual, tc.Columns)
			}
			if got.Generation != cat.Digest {
				t.Errorf("wrong generation: %q", got.Generation)
			}
		})
	}
}
