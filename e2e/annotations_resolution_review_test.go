package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/dbsec"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/policy"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/sqlguard"
	pgguard "github.com/speakeasy-api/restricted-sql-mcp/internal/sqlguard/postgres"
)

type reviewResult struct {
	Names []string
	Types []uint32
	Rows  [][]any
}

func reviewQuery(ctx context.Context, c *pgx.Conn, sql string) (reviewResult, error) {
	out := reviewResult{Rows: [][]any{}}
	rs, err := c.Query(ctx, sql)
	if err != nil {
		return out, err
	}
	defer rs.Close()
	for _, f := range rs.FieldDescriptions() {
		out.Names = append(out.Names, f.Name)
		out.Types = append(out.Types, f.DataTypeOID)
	}
	for rs.Next() {
		v, err := rs.Values()
		if err != nil {
			return out, err
		}
		out.Rows = append(out.Rows, v)
	}
	return out, rs.Err()
}
func reviewRows(t *testing.T, v [][]any, ordered bool) string {
	t.Helper()
	encoded := make([]string, 0, len(v))
	for _, r := range v {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		encoded = append(encoded, string(b))
	}
	if !ordered {
		sort.Strings(encoded)
	}
	return strings.Join(encoded, "\n")
}

func TestPostgresResolutionReviewDifferential(t *testing.T) {
	var cases []struct {
		Name, SQL, Denial string
		Allowed, Ordered  bool
	}
	raw, err := os.ReadFile("../internal/sqlguard/testdata/postgres_resolution_review.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	c := superuserConn(t)
	schema := fmt.Sprintf("resolution_review_%d", time.Now().UnixNano())
	ctx := context.Background()
	execSQL(t, c, "CREATE SCHEMA "+schema)
	t.Cleanup(func() { execSQL(t, c, "DROP SCHEMA "+schema+" CASCADE") })
	for _, table := range []string{"a", "b"} {
		num, txt := "integer", "varchar(20)"
		if table == "b" {
			num, txt = "bigint", "text"
		}
		execSQL(t, c, fmt.Sprintf("CREATE TABLE %s.%s(id %s,k %s,content integer,secret integer,restricted integer,txt %s)", schema, table, num, num, txt))
		for _, col := range []string{"id", "k", "content", "secret", "restricted", "txt"} {
			tier := "safe"
			if col == "content" || col == "secret" || col == "restricted" {
				tier = col
			}
			execSQL(t, c, fmt.Sprintf("COMMENT ON COLUMN %s.%s.%s IS '@access: %s'", schema, table, col, tier))
		}
	}
	// Distinct data makes alias/input confusion visible; unmatched rows exercise
	// null extension. int4/int8 and varchar/text exercise merged USING coercions.
	execSQL(t, c, "INSERT INTO "+schema+".a VALUES (1,20,101,901,801,'one'),(2,10,102,902,802,'two'),(4,20,104,904,804,'four')")
	execSQL(t, c, "INSERT INTO "+schema+".b VALUES (1,30,101,901,801,'one'),(2,40,102,902,802,'two'),(3,30,103,903,803,'three')")
	execSQL(t, c, "SET search_path="+schema+",pg_catalog")
	s := bootServer(t, annotationOpts(schema, "safe"))
	role := annotationServerRole(t, s)
	direct := superuserConn(t)
	execSQL(t, direct, "SET ROLE "+pgx.Identifier{role}.Sanitize())
	execSQL(t, direct, "SET search_path="+schema+",pg_catalog")
	execSQL(t, direct, "SET default_transaction_read_only=on")
	source := &dbsec.PostgresAnnotations{DSN: pgDSN()}
	cat, err := source.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pol := (&policy.Policy{Dialect: policy.Postgres, DefaultSchema: schema, AnnotationTiers: map[policy.Tier]bool{policy.Tier("safe"): true}}).WithCatalog(cat)
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			original, err := reviewQuery(ctx, c, tc.SQL)
			if err != nil {
				t.Fatalf("invalid test oracle: PostgreSQL rejected original %s: %v", tc.SQL, err)
			}
			checked, bindErr := pgguard.New().Check(tc.SQL, sqlguard.ModeRead, pol)
			dbResult, dbErr := reviewQuery(ctx, direct, tc.SQL)
			out, mcpErr := s.call(t, "execute_sql_readonly", map[string]any{"sql": tc.SQL})
			if !tc.Allowed {
				if bindErr == nil {
					t.Errorf("binder allowed denied %s: %s", tc.Denial, checked.SQL)
				} else if !strings.Contains(bindErr.Error(), tc.Denial) {
					t.Errorf("wrong binder rejection: %v", bindErr)
				}
				var pe *pgconn.PgError
				if !errors.As(dbErr, &pe) || pe.Code != "42501" {
					t.Errorf("column-grant layer: expected insufficient_privilege, got rows=%v error=%v", dbResult.Rows, dbErr)
				}
				if !strings.Contains(mcpErr, tc.Denial) {
					t.Errorf("MCP must reject denied %s; out=%v err=%q", tc.Denial, out, mcpErr)
				}
				// EXPLAIN must enforce the same inputs even without executing the query.
				_, explainErr := s.call(t, "explain_query", map[string]any{"sql": tc.SQL})
				if !strings.Contains(explainErr, tc.Denial) {
					t.Errorf("EXPLAIN must reject denied %s; err=%q", tc.Denial, explainErr)
				}
				return
			}
			if dbErr != nil {
				t.Errorf("direct role rejected safe original: %v", dbErr)
			} else if reviewRows(t, original.Rows, tc.Ordered) != reviewRows(t, dbResult.Rows, tc.Ordered) {
				t.Errorf("original restricted role results differ")
			}
			if bindErr != nil {
				t.Errorf("binder rejected safe query: %v", bindErr)
			} else {
				canonical, err := reviewQuery(ctx, c, checked.SQL)
				if err != nil {
					t.Errorf("canonical SQL fails although original returns %v: %s: %v", original.Rows, checked.SQL, err)
				} else {
					if !reflect.DeepEqual(original.Names, canonical.Names) {
						t.Errorf("output labels changed: original=%v canonical=%v; SQL=%s", original.Names, canonical.Names, checked.SQL)
					}
					if !reflect.DeepEqual(original.Types, canonical.Types) {
						t.Errorf("output types changed: original=%v canonical=%v; SQL=%s", original.Types, canonical.Types, checked.SQL)
					}
					if reviewRows(t, original.Rows, tc.Ordered) != reviewRows(t, canonical.Rows, tc.Ordered) {
						t.Errorf("canonical rows changed: original=%v canonical=%v; SQL=%s", original.Rows, canonical.Rows, checked.SQL)
					}
				}
			}
			if mcpErr != "" {
				t.Errorf("MCP rejected safe original: %s", mcpErr)
			} else if reviewRows(t, original.Rows, tc.Ordered) != reviewRows(t, rows(t, out), tc.Ordered) {
				t.Errorf("MCP rows changed: original=%v MCP=%v", original.Rows, rows(t, out))
			}
		})
	}
}
