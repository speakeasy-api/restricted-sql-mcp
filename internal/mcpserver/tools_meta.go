package mcpserver

import (
	"context"
	"fmt"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/speakeasy-api/gram-restricted-sql-mcp/internal/db"
	"github.com/speakeasy-api/gram-restricted-sql-mcp/internal/policy"
)

// ListSchemasInput is the input of list_schemas.
type ListSchemasInput struct {
	Database string `json:"database,omitempty" jsonschema:"database to run against; defaults to the server's default database (see list_databases)"`
}

// ListSchemasOutput is the output of list_schemas.
type ListSchemasOutput struct {
	Schemas []db.Schema `json:"schemas" jsonschema:"schemas (Postgres) or databases (ClickHouse)"`
}

// ListObjectsInput is the input of list_objects.
type ListObjectsInput struct {
	Schema     string `json:"schema" jsonschema:"schema (Postgres) or database (ClickHouse) to list"`
	ObjectType string `json:"object_type,omitempty" jsonschema:"filter: table, view, sequence, or extension; all when omitted"`
	Database   string `json:"database,omitempty" jsonschema:"database to run against; defaults to the server's default database (see list_databases)"`
}

// ListObjectsOutput is the output of list_objects.
type ListObjectsOutput struct {
	Objects []db.Object `json:"objects" jsonschema:"objects in the schema"`
}

// ObjectDetailsInput is the input of get_object_details.
type ObjectDetailsInput struct {
	Schema   string `json:"schema" jsonschema:"schema (Postgres) or database (ClickHouse) of the object"`
	Name     string `json:"name" jsonschema:"table or view name"`
	Database string `json:"database,omitempty" jsonschema:"database to run against; defaults to the server's default database (see list_databases)"`
}

func (s *server) registerMetaTools(srv *mcp.Server) {
	objectsDescription := "List the tables, views, sequences, or extensions inside one schema, with row estimates and sizes where the database exposes them."
	detailsDescription := "Describe one table or view: columns with types and defaults, constraints, indexes, storage size, row estimate, and engine details on ClickHouse."
	if s.Policy.AnnotationMode() {
		objectsDescription = "List application tables and views in a schema, including denied objects. Each access field gives queryability, selectable columns, denial reason, and catalog generation."
		detailsDescription = "Discover columns, types, structural constraints and foreign-key relationships for an application table or view. Each column's access field gives its tier, annotation status, selectability and denial reason. Raw comments and schema expressions are omitted."
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_schemas",
		Description: "List the schemas (Postgres) or databases (ClickHouse) present in the connected instance.",
		InputSchema: s.inputSchema(jsonschema.For[ListSchemasInput](nil)),
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, s.listSchemas)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_objects",
		Description: objectsDescription,
		InputSchema: s.inputSchema(jsonschema.For[ListObjectsInput](nil)),
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, s.listObjects)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "get_object_details",
		Description: detailsDescription,
		InputSchema: s.inputSchema(jsonschema.For[ObjectDetailsInput](nil)),
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, s.objectDetails)
}

func (s *server) listSchemas(ctx context.Context, _ *mcp.CallToolRequest, in ListSchemasInput) (*mcp.CallToolResult, ListSchemasOutput, error) {
	s, err := s.target(ctx, in.Database)
	if err != nil {
		return fail[ListSchemasOutput](err)
	}
	s, ctx, finish, admitErr := s.admitted(ctx)
	if admitErr != nil {
		return fail[ListSchemasOutput](admitErr)
	}
	defer finish()

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
	if err := finish(); err != nil {
		return fail[ListSchemasOutput](err)
	}
	return nil, ListSchemasOutput{Schemas: schemas}, nil
}

func (s *server) listObjects(ctx context.Context, _ *mcp.CallToolRequest, in ListObjectsInput) (*mcp.CallToolResult, ListObjectsOutput, error) {
	s, err := s.target(ctx, in.Database)
	if err != nil {
		return fail[ListObjectsOutput](err)
	}
	s, ctx, finish, admitErr := s.admitted(ctx)
	if admitErr != nil {
		return fail[ListObjectsOutput](admitErr)
	}
	defer finish()

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
	if err := finish(); err != nil {
		return fail[ListObjectsOutput](err)
	}
	return nil, ListObjectsOutput{Objects: objects}, nil
}

func (s *server) objectDetails(ctx context.Context, _ *mcp.CallToolRequest, in ObjectDetailsInput) (*mcp.CallToolResult, db.ObjectDetails, error) {
	s, err := s.target(ctx, in.Database)
	if err != nil {
		return fail[db.ObjectDetails](err)
	}
	s, ctx, finish, admitErr := s.admitted(ctx)
	if admitErr != nil {
		return fail[db.ObjectDetails](admitErr)
	}
	defer finish()

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
	if err := finish(); err != nil {
		return fail[db.ObjectDetails](err)
	}
	return nil, *details, nil
}
