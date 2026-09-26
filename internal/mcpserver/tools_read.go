package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/speakeasy-api/gram-restricted-sql-mcp/internal/db"
	"github.com/speakeasy-api/gram-restricted-sql-mcp/internal/policy"
	"github.com/speakeasy-api/gram-restricted-sql-mcp/internal/sqlguard"
)

// ExecuteReadInput is the input of execute_sql_readonly.
type ExecuteReadInput struct {
	SQL     string `json:"sql" jsonschema:"one SELECT-like statement over permitted tables and columns"`
	MaxRows int    `json:"max_rows,omitempty" jsonschema:"maximum rows to return; capped by the server limit"`
}

func (s *server) registerReadTools(srv *mcp.Server) {
	description := "Run a single read-only SQL statement (SELECT, WITH, UNION, joins, aggregates, window functions) " +
		"against the allowlisted tables and return rows. Only tables in the read allowlist may appear anywhere in " +
		"the query, including subqueries and CTEs. Only a fixed set of builtin functions is permitted. Rows are capped by max_rows."
	if s.Policy.AnnotationMode() {
		description = "Query selectable columns discovered through get_object_details. Every column use, including filters, joins and ordering, must be permitted. Use explicit projections; wildcards and whole rows are rejected. Built-in count(*) is allowed only on tables with a selectable column. Only approved built-in functions are permitted. Rows are capped by max_rows."
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "execute_sql_readonly",
		Description: description,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, s.executeReadonly)
}

func (s *server) executeReadonly(ctx context.Context, _ *mcp.CallToolRequest, in ExecuteReadInput) (*mcp.CallToolResult, QueryOutput, error) {
	s, ctx, finish, admitErr := s.admitted(ctx)
	if admitErr != nil {
		return fail[QueryOutput](admitErr)
	}
	defer finish()

	const tool = "execute_sql_readonly"
	checked, err := s.check(ctx, tool, in.SQL, sqlguard.ModeRead)
	if err != nil {
		return fail[QueryOutput](err)
	}
	maxRows := s.capRows(in.MaxRows)
	ctx, cancel := s.callContext(ctx)
	defer cancel()
	start := time.Now()
	res, err := s.Backend.Query(ctx, checked.SQL, maxRows)
	if err != nil {
		s.Logger.DebugContext(ctx, "query failed", "tool", tool, "canonical_sql", checked.SQL, "duration", time.Since(start).String(), "error", err.Error())
		return fail[QueryOutput](fmt.Errorf("query failed: %w", err))
	}
	s.Logger.DebugContext(ctx, "query ok", "tool", tool, "canonical_sql", checked.SQL, "duration", time.Since(start).String(),
		"rows", len(res.Rows), "truncated", res.Truncated, "max_rows", maxRows)
	if err := finish(); err != nil {
		return fail[QueryOutput](err)
	}
	return nil, queryOutput(res), nil
}

// HypotheticalIndexInput describes one index for explain_query.
type HypotheticalIndexInput struct {
	Schema  string   `json:"schema,omitempty" jsonschema:"schema of the table; defaults to the server default schema"`
	Table   string   `json:"table" jsonschema:"table to index; must be in the read allowlist"`
	Columns []string `json:"columns" jsonschema:"plain column identifiers in index order"`
	Method  string   `json:"method,omitempty" jsonschema:"index method: btree (default), hash, gin, gist, brin"`
}

// ExplainInput is the input of explain_query.
type ExplainInput struct {
	SQL                 string                   `json:"sql" jsonschema:"one SELECT-like statement over allowlisted tables"`
	Analyze             bool                     `json:"analyze,omitempty" jsonschema:"execute the statement and include actual timings"`
	HypotheticalIndexes []HypotheticalIndexInput `json:"hypothetical_indexes,omitempty" jsonschema:"Postgres only: indexes to simulate with hypopg; cannot be combined with analyze"`
}

// ExplainOutput is the output of explain_query.
type ExplainOutput struct {
	Dialect string `json:"dialect" jsonschema:"postgres or clickhouse"`
	Plan    any    `json:"plan" jsonschema:"the plan: JSON on Postgres, text on ClickHouse"`
	Notes   string `json:"notes,omitempty" jsonschema:"additional context about how the plan was produced"`
}

func (s *server) registerExplainTool(srv *mcp.Server) {
	mcp.AddTool(srv, &mcp.Tool{
		Name: "explain_query",
		Description: "Return the query planner's execution plan for a read-only statement without running it (set " +
			"analyze=true to execute it and include actual timings). On Postgres you can pass hypothetical_indexes to " +
			"see how the plan would change if those indexes existed; this needs the hypopg extension and cannot be " +
			"combined with analyze.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, s.explain)
}

func (s *server) explain(ctx context.Context, _ *mcp.CallToolRequest, in ExplainInput) (*mcp.CallToolResult, ExplainOutput, error) {
	s, ctx, finish, admitErr := s.admitted(ctx)
	if admitErr != nil {
		return fail[ExplainOutput](admitErr)
	}
	defer finish()

	const tool = "explain_query"
	checked, err := s.check(ctx, tool, in.SQL, sqlguard.ModeRead)
	if err != nil {
		return fail[ExplainOutput](err)
	}
	opts := db.ExplainOptions{Analyze: in.Analyze}
	if len(in.HypotheticalIndexes) > 0 {
		if s.Policy.Dialect == policy.ClickHouse {
			return fail[ExplainOutput](errors.New("hypothetical indexes are not supported on clickhouse"))
		}
		if in.Analyze {
			return fail[ExplainOutput](errors.New("analyze and hypothetical_indexes are mutually exclusive"))
		}
		for _, h := range in.HypotheticalIndexes {
			idx, err := s.hypotheticalIndex(h)
			if err != nil {
				s.Logger.DebugContext(ctx, "hypothetical index rejected", "tool", tool, "table", h.Table, "error", err.Error())
				return fail[ExplainOutput](err)
			}
			opts.HypotheticalIndexes = append(opts.HypotheticalIndexes, idx)
		}
	}
	ctx, cancel := s.callContext(ctx)
	defer cancel()
	start := time.Now()
	planJSON, planText, err := s.Backend.Explain(ctx, checked.SQL, opts)
	if err != nil {
		s.Logger.DebugContext(ctx, "explain failed", "tool", tool, "canonical_sql", checked.SQL, "duration", time.Since(start).String(), "error", err.Error())
		return fail[ExplainOutput](fmt.Errorf("explain failed: %w", err))
	}
	s.Logger.DebugContext(ctx, "explain ok", "tool", tool, "canonical_sql", checked.SQL, "duration", time.Since(start).String(),
		"analyze", in.Analyze, "hypothetical_indexes", len(opts.HypotheticalIndexes))
	out := ExplainOutput{Dialect: string(s.Policy.Dialect)}
	if planJSON != nil {
		out.Plan = planJSON
	} else {
		out.Plan = planText
	}
	if len(opts.HypotheticalIndexes) > 0 {
		out.Notes = fmt.Sprintf("plan computed with %d hypothetical index(es) via hypopg", len(opts.HypotheticalIndexes))
	} else if in.Analyze {
		out.Notes = "statement was executed inside a read-only transaction to collect actual timings"
	}
	if err := finish(); err != nil {
		return fail[ExplainOutput](err)
	}
	return nil, out, nil
}

func (s *server) hypotheticalIndex(h HypotheticalIndexInput) (sqlguard.HypotheticalIndex, error) {
	name := h.Table
	if h.Schema != "" {
		name = h.Schema + "." + h.Table
	}
	ref, err := policy.ParseTableRef(name, s.Policy.DefaultSchema, s.Policy.Dialect)
	if err != nil {
		return sqlguard.HypotheticalIndex{}, sqlguard.Reject("hypothetical index table is invalid", err.Error())
	}
	if !s.Policy.CanRead(ref) {
		return sqlguard.HypotheticalIndex{}, sqlguard.Reject("hypothetical index table is not in the read allowlist", ref.String())
	}
	for _, column := range h.Columns {
		if s.Policy.AnnotationMode() && !s.Policy.CanReadColumn(ref, column) {
			return sqlguard.HypotheticalIndex{}, sqlguard.Reject(s.Policy.ColumnDenial(ref, column), ref.String()+"."+column)
		}
	}
	idx := sqlguard.HypotheticalIndex{Table: ref, Columns: h.Columns, Method: h.Method}
	if _, err := sqlguard.BuildIndexDDL(idx); err != nil {
		return sqlguard.HypotheticalIndex{}, err
	}
	return idx, nil
}
