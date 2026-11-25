package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/speakeasy-api/restricted-sql-mcp/internal/config"
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

type testTransport func(*http.Request) (*http.Response, error)

func (f testTransport) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestReplicaMCPAuthorizesOnlyConfiguredCaller(t *testing.T) {
	const issuer = "https://tunnel.dev.getgram.ai"
	const audience = "tunneled-mcp-server:replica"
	const org = "dev-organization"
	const kid = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kid": kid, "kty": "RSA", "alg": "RS256", "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	verifier := tunnelidentity.New(issuer, audience, org, testTransport(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != issuer+"/.well-known/jwks.json" {
			t.Errorf("JWKS fetched from %s", req.URL)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(jwks)))}, nil
	}))
	var callers []config.ReplicaPrincipal
	if err := json.Unmarshal([]byte(`[
		{"email":"engineer@example.com","databaseLogin":"included_reader"},
		{"gramUserID":"legacy","email":"legacy@example.com","databaseLogin":"legacy_reader"}
	]`), &callers); err != nil {
		t.Fatal(err)
	}
	servers := make(map[string]*mcp.Server, len(callers))
	for _, caller := range callers {
		srv := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "1"}, nil)
		srv.AddReceivingMiddleware(authorizeTunnelMethods(slog.New(slog.DiscardHandler)))
		srv.AddTool(&mcp.Tool{Name: "sql", InputSchema: map[string]any{"type": "object"}},
			func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: caller.DatabaseLogin}}}, nil
			})
		servers[caller.RoutingKey()] = srv
	}
	selectServer, authenticate := replicaCallerRouting(verifier.Verify, servers)
	handler := authenticate(mcp.NewStreamableHTTPHandler(selectServer, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true}))
	for _, tc := range []struct {
		name, issuer, subject, email string
		want                         int
		login                        string
	}{
		{"configured user", issuer, "user:included", "engineer@example.com", http.StatusOK, "included_reader"},
		{"same listed email and different user ID", issuer, "user:another", "Engineer@EXAMPLE.com", http.StatusOK, "included_reader"},
		{"unlisted email in the same domain", issuer, "user:included", "unlisted@example.com", http.StatusForbidden, ""},
		{"missing email", issuer, "user:included", "", http.StatusForbidden, ""},
		{"api key", issuer, "api_key:included", "engineer@example.com", http.StatusForbidden, ""},
		{"agent", issuer, "agent:included", "engineer@example.com", http.StatusForbidden, ""},
		{"empty user ID", issuer, "user:", "engineer@example.com", http.StatusForbidden, ""},
		{"production assertion", "https://tunnel.speakeasy.com", "user:included", "engineer@example.com", http.StatusForbidden, ""},
		{"legacy ID with no email", issuer, "user:legacy", "", http.StatusOK, "legacy_reader"},
		{"legacy ID with changed email", issuer, "user:legacy", "new-address@example.com", http.StatusOK, "legacy_reader"},
		{"legacy row's informational email", issuer, "user:other", "legacy@example.com", http.StatusForbidden, ""},
		{"conflicting ID and email entries", issuer, "user:legacy", "engineer@example.com", http.StatusForbidden, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now()
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"iss": tc.issuer, "aud": audience, "sub": tc.subject, "email": tc.email, "organization_id": org,
				"version": 1, "jti": "test-assertion", "iat": now.Unix(), "exp": now.Add(30 * time.Second).Unix(),
			})
			token.Header["typ"], token.Header["kid"] = "speakeasy-identity+jwt", kid
			signed, err := token.SignedString(key)
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(
				`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sql","arguments":{}}}`))
			req.Header.Set(tunnelidentity.Header, signed)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != tc.want || (tc.login != "" && !strings.Contains(res.Body.String(), tc.login)) {
				t.Fatalf("status = %d, body = %s; want %d", res.Code, res.Body.String(), tc.want)
			}
		})
	}
}
