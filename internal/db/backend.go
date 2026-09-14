// Package db defines the database backend contract. Backends own the
// session-level protections (read-only transactions or settings, statement
// timeouts, search_path pinning); guards own statement validation.
package db

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ThomasRooney/gram-restrictedsql-tunnel-mcp/internal/policy"
	"github.com/ThomasRooney/gram-restrictedsql-tunnel-mcp/internal/sqlguard"
)

// Column describes one result column.
type Column struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// Result is the outcome of a query or statement.
type Result struct {
	Columns      []Column      `json:"columns"`
	Rows         [][]any       `json:"rows"`
	RowsAffected int64         `json:"rows_affected"`
	Truncated    bool          `json:"truncated"`
	Duration     time.Duration `json:"-"`
}

// ExplainOptions controls explain_query.
type ExplainOptions struct {
	Analyze             bool
	HypotheticalIndexes []sqlguard.HypotheticalIndex
}

// Schema is a Postgres schema or a ClickHouse database.
type Schema struct {
	Name        string `json:"name"`
	Owner       string `json:"owner,omitempty"`
	Description string `json:"description,omitempty"`
}

// Object is a table, view, sequence, or extension.
type Object struct {
	Name        string `json:"name"`
	Type        string `json:"type"` // table | view | sequence | extension | materialized_view | dictionary
	Engine      string `json:"engine,omitempty"`
	RowEstimate *int64 `json:"row_estimate,omitempty"`
	SizeBytes   *int64 `json:"size_bytes,omitempty"`
}

// ColumnDetail describes one column of an object.
type ColumnDetail struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Nullable    bool   `json:"nullable"`
	Default     string `json:"default,omitempty"`
	Description string `json:"description,omitempty"`
}

// Constraint describes a table constraint.
type Constraint struct {
	Name       string `json:"name"`
	Type       string `json:"type"` // primary_key | foreign_key | unique | check | exclusion
	Definition string `json:"definition"`
}

// Index describes an index.
type Index struct {
	Name       string `json:"name"`
	Definition string `json:"definition"`
	SizeBytes  *int64 `json:"size_bytes,omitempty"`
}

// ObjectDetails is the full description of one object.
type ObjectDetails struct {
	Schema       string         `json:"schema"`
	Name         string         `json:"name"`
	Type         string         `json:"type"`
	Columns      []ColumnDetail `json:"columns"`
	Constraints  []Constraint   `json:"constraints"`
	Indexes      []Index        `json:"indexes"`
	SizeBytes    *int64         `json:"size_bytes,omitempty"`
	RowEstimate  *int64         `json:"row_estimate,omitempty"`
	Description  string         `json:"description,omitempty"`
	Engine       string         `json:"engine,omitempty"`
	SortingKey   string         `json:"sorting_key,omitempty"`
	PartitionKey string         `json:"partition_key,omitempty"`
}

// Backend is implemented once per dialect.
type Backend interface {
	Dialect() policy.Dialect
	// Ping checks connectivity; used by /readyz.
	Ping(ctx context.Context) error
	// TablesExist returns the subset of refs that do not exist.
	TablesExist(ctx context.Context, refs []policy.TableRef) (missing []policy.TableRef, err error)
	// Query runs canonical read-only SQL under the read-only session protections
	// and returns at most maxRows rows (Truncated set when more were available).
	Query(ctx context.Context, canonicalSQL string, maxRows int) (*Result, error)
	// Explain returns the plan as JSON when the dialect supports it (Postgres),
	// otherwise as text (ClickHouse). Exactly one of the two is non-empty.
	Explain(ctx context.Context, canonicalSQL string, opts ExplainOptions) (planJSON json.RawMessage, planText string, err error)
	ListSchemas(ctx context.Context) ([]Schema, error)
	ListObjects(ctx context.Context, schema, objectType string) ([]Object, error)
	ObjectDetails(ctx context.Context, ref policy.TableRef) (*ObjectDetails, error)
	Close() error
}

// Tx is one open write transaction pinned to a dedicated connection.
type Tx interface {
	// Exec runs canonical SQL inside the transaction. For statements that
	// return rows (SELECT, RETURNING) rows are collected up to maxRows.
	Exec(ctx context.Context, canonicalSQL string, maxRows int) (*Result, error)
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// TxBackend is implemented by backends that support write transactions
// (Postgres only in v1).
type TxBackend interface {
	Begin(ctx context.Context) (Tx, error)
}
