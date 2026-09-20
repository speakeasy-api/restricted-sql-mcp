package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/speakeasy-api/gram-restricted-sql-mcp/internal/sqlguard"
)

// BeginInput is the (empty) input of begin_transaction.
type BeginInput struct{}

// BeginOutput is the output of begin_transaction.
type BeginOutput struct {
	TransactionID string `json:"transaction_id" jsonschema:"opaque id to pass to execute_sql_write, commit_transaction, rollback_transaction"`
	ExpiresAt     string `json:"expires_at" jsonschema:"RFC3339 time at which the transaction is rolled back if left idle"`
}

// ExecuteWriteInput is the input of execute_sql_write.
type ExecuteWriteInput struct {
	TransactionID string `json:"transaction_id" jsonschema:"id returned by begin_transaction"`
	SQL           string `json:"sql" jsonschema:"one INSERT, UPDATE, DELETE (RETURNING allowed) or SELECT"`
	MaxRows       int    `json:"max_rows,omitempty" jsonschema:"maximum rows to return; capped by the server limit"`
}

// ExecuteWriteOutput is the output of execute_sql_write.
type ExecuteWriteOutput struct {
	RowsAffected int64 `json:"rows_affected" jsonschema:"rows inserted, updated, or deleted"`
	QueryOutput
}

// TxInput identifies a transaction for commit and rollback.
type TxInput struct {
	TransactionID string `json:"transaction_id" jsonschema:"id returned by begin_transaction"`
}

// TxStatusOutput is the output of commit_transaction and rollback_transaction.
type TxStatusOutput struct {
	Status string `json:"status" jsonschema:"committed or rolled_back"`
}

var errNoTxBackend = errors.New("write transactions are not supported by this backend")

func (s *server) registerWriteTools(srv *mcp.Server) {
	mcp.AddTool(srv, &mcp.Tool{
		Name: "begin_transaction",
		Description: "Open a write transaction on a dedicated connection and return its transaction_id. Every write " +
			"must run inside a transaction so you can check rows_affected and re-select the changed rows before " +
			"committing. Idle transactions are rolled back automatically after the configured timeout.",
	}, s.beginTransaction)
	mcp.AddTool(srv, &mcp.Tool{
		Name: "execute_sql_write",
		Description: "Run one INSERT, UPDATE, DELETE (RETURNING allowed) or SELECT inside an open transaction. " +
			"Mutations may only target tables in the write allowlist; SELECTs and source tables may use the read and " +
			"write allowlists. Errors abort the transaction; roll it back and start again.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(true)},
	}, s.executeWrite)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "commit_transaction",
		Description: "Commit an open transaction and release its connection.",
	}, s.commitTransaction)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "rollback_transaction",
		Description: "Roll back an open transaction and release its connection.",
	}, s.rollbackTransaction)
}

func boolPtr(b bool) *bool { return &b }

func (s *server) beginTransaction(ctx context.Context, _ *mcp.CallToolRequest, _ BeginInput) (*mcp.CallToolResult, BeginOutput, error) {
	if s.Txns == nil {
		return fail[BeginOutput](errNoTxBackend)
	}
	ctx, cancel := s.callContext(ctx)
	defer cancel()
	id, expires, err := s.Txns.Begin(ctx)
	if err != nil {
		s.Logger.DebugContext(ctx, "begin_transaction failed", "error", err.Error())
		return fail[BeginOutput](fmt.Errorf("begin_transaction failed: %w", err))
	}
	return nil, BeginOutput{TransactionID: id, ExpiresAt: expires.UTC().Format(time.RFC3339)}, nil
}

func (s *server) executeWrite(ctx context.Context, _ *mcp.CallToolRequest, in ExecuteWriteInput) (*mcp.CallToolResult, ExecuteWriteOutput, error) {
	const tool = "execute_sql_write"
	if s.Txns == nil {
		return fail[ExecuteWriteOutput](errNoTxBackend)
	}
	if in.TransactionID == "" {
		return fail[ExecuteWriteOutput](errors.New("transaction_id is required"))
	}
	checked, err := s.check(ctx, tool, in.SQL, sqlguard.ModeWrite)
	if err != nil {
		return fail[ExecuteWriteOutput](err)
	}
	maxRows := s.capRows(in.MaxRows)
	ctx, cancel := s.callContext(ctx)
	defer cancel()
	start := time.Now()
	res, err := s.Txns.Exec(ctx, in.TransactionID, checked.SQL, maxRows)
	if err != nil {
		s.Logger.DebugContext(ctx, "write failed", "tool", tool, "transaction_id", in.TransactionID, "kind", checked.Kind,
			"canonical_sql", checked.SQL, "duration", time.Since(start).String(), "error", err.Error())
		return fail[ExecuteWriteOutput](fmt.Errorf("execute_sql_write failed: %w", err))
	}
	s.Logger.DebugContext(ctx, "write ok", "tool", tool, "transaction_id", in.TransactionID, "kind", checked.Kind,
		"canonical_sql", checked.SQL, "duration", time.Since(start).String(), "rows_affected", res.RowsAffected,
		"rows", len(res.Rows), "truncated", res.Truncated)
	return nil, ExecuteWriteOutput{RowsAffected: res.RowsAffected, QueryOutput: queryOutput(res)}, nil
}

func (s *server) commitTransaction(ctx context.Context, _ *mcp.CallToolRequest, in TxInput) (*mcp.CallToolResult, TxStatusOutput, error) {
	if s.Txns == nil {
		return fail[TxStatusOutput](errNoTxBackend)
	}
	ctx, cancel := s.callContext(ctx)
	defer cancel()
	if err := s.Txns.Commit(ctx, in.TransactionID); err != nil {
		s.Logger.DebugContext(ctx, "commit_transaction failed", "transaction_id", in.TransactionID, "error", err.Error())
		return fail[TxStatusOutput](fmt.Errorf("commit_transaction failed: %w", err))
	}
	return nil, TxStatusOutput{Status: "committed"}, nil
}

func (s *server) rollbackTransaction(ctx context.Context, _ *mcp.CallToolRequest, in TxInput) (*mcp.CallToolResult, TxStatusOutput, error) {
	if s.Txns == nil {
		return fail[TxStatusOutput](errNoTxBackend)
	}
	ctx, cancel := s.callContext(ctx)
	defer cancel()
	if err := s.Txns.Rollback(ctx, in.TransactionID); err != nil {
		s.Logger.DebugContext(ctx, "rollback_transaction failed", "transaction_id", in.TransactionID, "error", err.Error())
		return fail[TxStatusOutput](fmt.Errorf("rollback_transaction failed: %w", err))
	}
	return nil, TxStatusOutput{Status: "rolled_back"}, nil
}
