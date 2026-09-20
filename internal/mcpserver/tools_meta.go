package mcpserver

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/speakeasy-api/gram-restricted-sql-mcp/internal/db"
	"github.com/speakeasy-api/gram-restricted-sql-mcp/internal/policy"
)

// ListSchemasInput is the (empty) input of list_schemas.
type ListSchemasInput struct{}

// ListSchemasOutput is the output of list_schemas.
type ListSchemasOutput struct {
	Schemas []db.Schema `json:"schemas" jsonschema:"schemas (Postgres) or databases (ClickHouse)"`
}

// ListObjectsInput is the input of list_objects.
type ListObjectsInput struct {
	Schema     string `json:"schema" jsonschema:"schema (Postgres) or database (ClickHouse) to list"`
	ObjectType string `json:"object_type,omitempty" jsonschema:"filter: table, view, sequence, or extension; all when omitted"`
}

// ListObjectsOutput is the output of list_objects.
type ListObjectsOutput struct {
	Objects []db.Object `json:"objects" jsonschema:"objects in the schema"`
}

// ObjectDetailsInput is the input of get_object_details.
type ObjectDetailsInput struct {
	Schema string `json:"schema" jsonschema:"schema (Postgres) or database (ClickHouse) of the object"`
	Name   string `json:"name" jsonschema:"table or view name"`
}

func (s *server) registerMetaTools(srv *mcp.Server) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_schemas",
		Description: "List the schemas (Postgres) or databases (ClickHouse) present in the connected instance.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, s.listSchemas)
	mcp.AddTool(srv, &mcp.Tool{
		Name: "list_objects",
		Description: "List the tables, views, sequences, or extensions inside one schema, with row estimates and " +
			"sizes where the database exposes them.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, s.listObjects)
	mcp.AddTool(srv, &mcp.Tool{
		Name: "get_object_details",
		Description: "Describe one table or view: columns with types and defaults, constraints, indexes, storage " +
			"size, row estimate, and engine details on ClickHouse.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, s.objectDetails)
}

func (s *server) listSchemas(ctx context.Context, _ *mcp.CallToolRequest, _ ListSchemasInput) (*mcp.CallToolResult, ListSchemasOutput, error) {
	ctx, cancel := s.callContext(ctx)
	defer cancel()
	start := time.Now()
	schemas, err := s.Backend.ListSchemas(ctx)
	if err != nil {
		s.Logger.DebugContext(ctx, "list_schemas failed", "error", err.Error())
		return fail[ListSchemasOutput](fmt.Errorf("list_schemas failed: %w", err))
	}
	if schemas == nil {
		schemas = []db.Schema{}
	}
	s.Logger.DebugContext(ctx, "list_schemas ok", "count", len(schemas), "duration", time.Since(start).String())
	return nil, ListSchemasOutput{Schemas: schemas}, nil
}

func (s *server) listObjects(ctx context.Context, _ *mcp.CallToolRequest, in ListObjectsInput) (*mcp.CallToolResult, ListObjectsOutput, error) {
	switch in.ObjectType {
	case "", "table", "view", "sequence", "extension":
	default:
		return fail[ListObjectsOutput](fmt.Errorf("object_type %q is not supported (table, view, sequence, extension)", in.ObjectType))
	}
	if in.Schema == "" {
		return fail[ListObjectsOutput](fmt.Errorf("schema is required"))
	}
	ctx, cancel := s.callContext(ctx)
	defer cancel()
	start := time.Now()
	objects, err := s.Backend.ListObjects(ctx, in.Schema, in.ObjectType)
	if err != nil {
		s.Logger.DebugContext(ctx, "list_objects failed", "schema", in.Schema, "object_type", in.ObjectType, "error", err.Error())
		return fail[ListObjectsOutput](fmt.Errorf("list_objects failed: %w", err))
	}
	if objects == nil {
		objects = []db.Object{}
	}
	s.Logger.DebugContext(ctx, "list_objects ok", "schema", in.Schema, "object_type", in.ObjectType, "count", len(objects), "duration", time.Since(start).String())
	return nil, ListObjectsOutput{Objects: objects}, nil
}

func (s *server) objectDetails(ctx context.Context, _ *mcp.CallToolRequest, in ObjectDetailsInput) (*mcp.CallToolResult, db.ObjectDetails, error) {
	if in.Schema == "" || in.Name == "" {
		return fail[db.ObjectDetails](fmt.Errorf("schema and name are required"))
	}
	ref := policy.TableRef{Schema: in.Schema, Name: in.Name}
	ctx, cancel := s.callContext(ctx)
	defer cancel()
	start := time.Now()
	details, err := s.Backend.ObjectDetails(ctx, ref)
	if err != nil {
		s.Logger.DebugContext(ctx, "get_object_details failed", "object", ref.String(), "error", err.Error())
		return fail[db.ObjectDetails](fmt.Errorf("get_object_details failed: %w", err))
	}
	if details.Columns == nil {
		details.Columns = []db.ColumnDetail{}
	}
	if details.Constraints == nil {
		details.Constraints = []db.Constraint{}
	}
	if details.Indexes == nil {
		details.Indexes = []db.Index{}
	}
	s.Logger.DebugContext(ctx, "get_object_details ok", "object", ref.String(), "columns", len(details.Columns), "duration", time.Since(start).String())
	return nil, *details, nil
}
