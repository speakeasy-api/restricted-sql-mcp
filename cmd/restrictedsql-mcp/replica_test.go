package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/speakeasy-api/restricted-sql-mcp/internal/tunnelidentity"
)

func TestTunnelDiscoveryCannotCallTools(t *testing.T) {
	srv := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	srv.AddReceivingMiddleware(authorizeTunnelMethods(slog.New(slog.DiscardHandler)))
	called := false
	srv.AddTool(&mcp.Tool{Name: "sql", InputSchema: map[string]any{"type": "object"}},
		func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			called = true
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}, nil
		})
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, &mcp.StreamableHTTPOptions{
		Stateless: true, JSONResponse: true,
	})
	call := func(claims *tunnelidentity.Claims) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sql","arguments":{}}}`))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "application/json, text/event-stream")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request.WithContext(context.WithValue(request.Context(), identityContextKey{}, claims)))
		return recorder
	}
	discovery := call(&tunnelidentity.Claims{AllowedMethods: json.RawMessage(`["tools/list"]`)})
	if called || !strings.Contains(discovery.Body.String(), "caller identity does not allow this method") {
		t.Fatalf("discovery reached tool or got wrong error: %s", discovery.Body.String())
	}
	runtime := call(&tunnelidentity.Claims{})
	if !called || !strings.Contains(runtime.Body.String(), "ok") {
		t.Fatalf("runtime assertion was not passed to tool: %s", runtime.Body.String())
	}
}
