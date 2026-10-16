// Package mcpserver exposes the SQL tools over MCP. Every statement passes
// through the dialect guard and only the canonical SQL reaches the backend.
package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/speakeasy-api/restricted-sql-mcp/internal/db"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/multidb"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/policy"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/sqlguard"
	"github.com/speakeasy-api/restricted-sql-mcp/internal/txn"
)

// Deps are the collaborators the tool handlers use.
type Deps struct {
	Policy  *policy.Policy
	Guard   sqlguard.Guard
	Backend db.Backend
	Txns    *txn.Registry // nil unless writes are enabled and the backend supports them
	Logger  *slog.Logger
	Version string
	// DefaultDatabase names the DSN's database; a database argument equal to
	// it (or empty) targets Policy and Backend. "" when the DSN names none.
	DefaultDatabase string
	// Databases serves further databases (--databases). When nil, the
	// database argument is not advertised and list_databases is absent.
	Databases *multidb.Manager
}

// callSlack is added to the statement timeout to bound a whole tool call,
// including connection setup, so a hung database cannot pin a handler.
const callSlack = 15 * time.Second

// rawSQLLogLimit caps raw SQL in debug logs.
const rawSQLLogLimit = 2000

type server struct {
	Deps
	// database is the database a request-scoped copy targets (see target).
	database string
}

// New builds the MCP server and registers the tools. Write tools are
// registered only when the policy enables writes.
func New(d Deps) *mcp.Server {
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	s := &server{Deps: d}
	srv := mcp.NewServer(&mcp.Implementation{Name: "restrictedsql-mcp", Version: d.Version}, &mcp.ServerOptions{
		Instructions: s.instructions(),
		Logger:       d.Logger,
	})
	s.registerReadTools(srv)
	s.registerMetaTools(srv)
	s.registerExplainTool(srv)
	if d.Policy.WritesEnabled {
		s.registerWriteTools(srv)
	}
	if d.Databases != nil {
		s.registerDatabaseTools(srv)
	}
	return srv
}

// target returns a request-scoped copy of s for the named database: its
// policy, its backend, and a logger that carries the database name. An
// empty name is the default database.
func (s *server) target(ctx context.Context, name string) (*server, error) {
	request := *s
	if s.Databases == nil {
		if name != "" && name != s.DefaultDatabase {
			return nil, fmt.Errorf("unknown database %q: this server serves only its configured database", name)
		}
		request.database = s.DefaultDatabase
	} else {
		inst, err := s.Databases.Get(ctx, name)
		if err != nil {
			s.Logger.DebugContext(ctx, "database rejected", "database", name, "error", err.Error())
			return nil, err
		}
		request.database = inst.Name
		request.Policy = inst.Policy
		request.Backend = inst.Backend
	}
	if request.database != "" {
		request.Logger = s.Logger.With("database", request.database)
	}
	return &request, nil
}

// inputSchema infers the input schema of T. Without --databases the
// database property is removed, so single-database servers advertise exactly
// the arguments they always had.
func (s *server) inputSchema(schema *jsonschema.Schema, err error) any {
	if err != nil || s.Databases != nil {
		return nil // let the SDK infer it (and report any error) as before
	}
	delete(schema.Properties, "database")
	return schema
}

func (s *server) instructions() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Restricted SQL access to a %s database. ", s.Policy.Dialect)
	fmt.Fprintf(&b, "Unqualified table names resolve to schema %q. ", s.Policy.DefaultSchema)
	if s.Policy.AnnotationMode() {
		b.WriteString("Column annotation mode: use get_object_details to discover selectable columns. Projection wildcards and whole rows are rejected; count(*) is allowed on queryable tables. ")
	} else {
		fmt.Fprintf(&b, "Readable tables: %s. ", strings.Join(refStrings(s.Policy.ReadTables), ", "))
	}
	if s.Policy.WritesEnabled {
		fmt.Fprintf(&b, "Writable tables (inside a transaction only): %s. ", strings.Join(refStrings(s.Policy.WriteTables), ", "))
	} else {
		b.WriteString("Writes are disabled. ")
	}
	fmt.Fprintf(&b, "Each call runs exactly one statement; rows are capped at %d.", s.Policy.MaxRows)
	if s.Databases != nil {
		fmt.Fprintf(&b, " Several databases of the same server are available: call list_databases and pass database to the read, metadata and begin_transaction tools (default %q). "+
			"Each database has its own allowlist, resolved from its own schemas; the tables above are the default database's. "+
			"A transaction stays in the database it was begun in.", s.Databases.Default())
	}
	return b.String()
}

func refStrings(m map[policy.TableRef]struct{}) []string {
	var out []string
	for r := range m {
		out = append(out, r.String())
	}
	sortStrings(out)
	return out
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// fail returns a tool error. A plain error is packed by the SDK into a
// CallToolResult with IsError set, so the agent sees the message.
func fail[Out any](err error) (*mcp.CallToolResult, Out, error) {
	var zero Out
	return nil, zero, err
}

// rejection normalizes guard failures: policy rejections keep their message,
// parse and internal errors are still reported as rejections (fail closed).
func rejection(err error) error {
	var rej *sqlguard.RejectError
	if errors.As(err, &rej) {
		return rej
	}
	return fmt.Errorf("sql rejected: %s", err.Error())
}

// capRows applies the server cap to a requested row limit.
func (s *server) capRows(requested int) int {
	if requested <= 0 || requested > s.Policy.MaxRows {
		return s.Policy.MaxRows
	}
	return requested
}

// callContext bounds a tool call.
func (s *server) callContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, s.Policy.StatementTimeout+callSlack)
}

// check runs the guard and the server-side table double check.
func (s *server) check(ctx context.Context, tool, raw string, mode sqlguard.Mode) (*sqlguard.Checked, error) {
	checked, err := s.Guard.Check(raw, mode, s.Policy)
	if err != nil {
		err = rejection(err)
		s.Logger.DebugContext(ctx, "sql rejected", "tool", tool, "mode", mode.String(), "raw_sql", truncate(raw), "error", err.Error())
		return nil, err
	}
	if s.Policy.AnnotationMode() {
		if s.Policy.Catalog == nil || checked.Generation != s.Policy.Catalog.Digest {
			return nil, sqlguard.Reject("catalog generation mismatch", "")
		}
		for ref, columns := range checked.Columns {
			for _, column := range columns {
				if reason := s.Policy.ColumnDenial(ref, column); reason != "" {
					return nil, sqlguard.Reject(reason, ref.String()+"."+column)
				}
			}
		}
	}
	for _, t := range checked.Tables {
		var ok bool
		switch mode {
		case sqlguard.ModeRead:
			ok = s.Policy.CanRead(t)
		case sqlguard.ModeWrite:
			ok = s.Policy.CanSelectInWrite(t)
		}
		if !ok {
			err := sqlguard.Reject("table is not in the allowlist", t.String())
			s.Logger.WarnContext(ctx, "guard returned a table outside the policy; rejecting", "tool", tool, "table", t.String())
			return nil, err
		}
	}
	if mode == sqlguard.ModeRead && checked.Kind != sqlguard.KindSelect {
		s.Logger.WarnContext(ctx, "guard returned a non-select in read mode; rejecting", "tool", tool, "kind", checked.Kind)
		return nil, sqlguard.Reject("only SELECT statements are allowed in read mode", string(checked.Kind))
	}
	s.Logger.DebugContext(ctx, "sql accepted", "tool", tool, "mode", mode.String(), "kind", checked.Kind,
		"raw_sql", truncate(raw), "canonical_sql", checked.SQL, "tables", refList(checked.Tables))
	return checked, nil
}

func refList(refs []policy.TableRef) []string {
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		out = append(out, r.String())
	}
	return out
}

func truncate(s string) string {
	if len(s) > rawSQLLogLimit {
		return s[:rawSQLLogLimit] + "…"
	}
	return s
}

// QueryOutput is the row payload shared by the read and write execute tools.
type QueryOutput struct {
	Columns    []db.Column `json:"columns" jsonschema:"result columns in order"`
	Rows       [][]any     `json:"rows" jsonschema:"result rows; each row is an array aligned with columns"`
	RowCount   int         `json:"row_count" jsonschema:"number of rows returned"`
	Truncated  bool        `json:"truncated" jsonschema:"true when more rows were available than max_rows"`
	DurationMS int64       `json:"duration_ms" jsonschema:"database execution time in milliseconds"`
}

func queryOutput(res *db.Result) QueryOutput {
	out := QueryOutput{
		Columns:    res.Columns,
		Rows:       res.Rows,
		RowCount:   len(res.Rows),
		Truncated:  res.Truncated,
		DurationMS: res.Duration.Milliseconds(),
	}
	if out.Columns == nil {
		out.Columns = []db.Column{}
	}
	if out.Rows == nil {
		out.Rows = [][]any{}
	}
	return out
}

// admitted uses a private server copy so concurrent requests never exchange policies.
func (s *server) admitted(ctx context.Context) (*server, context.Context, func() error, error) {
	if a, ok := s.Backend.(db.DataAdmission); ok {
		bounded, cancel := s.callContext(ctx)
		ctx, p, release, err := a.AcquireData(bounded)
		if err != nil {
			cancel()
			return nil, nil, nil, err
		}
		finish := func() error { err := release(); cancel(); return err }
		request := *s
		request.Policy = p
		return &request, ctx, finish, nil
	}
	return s, ctx, func() error { return nil }, nil
}
