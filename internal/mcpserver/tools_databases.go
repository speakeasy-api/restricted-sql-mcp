package mcpserver

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/speakeasy-api/restricted-sql-mcp/internal/multidb"
)

// ListDatabasesInput is the (empty) input of list_databases.
type ListDatabasesInput struct{}

// ListDatabasesOutput is the output of list_databases.
type ListDatabasesOutput struct {
	Databases []multidb.Info `json:"databases" jsonschema:"served databases, default first"`
}

func (s *server) registerDatabaseTools(srv *mcp.Server) {
	mcp.AddTool(srv, &mcp.Tool{
		Name: "list_databases",
		Description: "List the databases this server serves on its Postgres instance, re-reading the server's database list. " +
			"Pass a name as the database argument of the read, metadata and begin_transaction tools; omitting it uses the default database.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, s.listDatabases)
}

func (s *server) listDatabases(ctx context.Context, _ *mcp.CallToolRequest, _ ListDatabasesInput) (*mcp.CallToolResult, ListDatabasesOutput, error) {
	ctx, cancel := s.callContext(ctx)
	defer cancel()
	dbs, err := s.Databases.List(ctx)
	if err != nil {
		s.Logger.DebugContext(ctx, "list_databases failed", "error", err.Error())
		return fail[ListDatabasesOutput](fmt.Errorf("list_databases failed: %w", err))
	}
	s.Logger.DebugContext(ctx, "list_databases ok", "count", len(dbs))
	return nil, ListDatabasesOutput{Databases: dbs}, nil
}
