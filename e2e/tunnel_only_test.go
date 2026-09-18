package e2e

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestPostgresTunnelOnlyRefusesDirectAccess proves --tunnel-only closes the
// loopback listener to everything except the in-process tunnel agent: a
// direct POST to /mcp (with or without a guessed token) is refused with 401,
// while the same requests through the gateway succeed, health stays open,
// and the per-boot token never appears in the logs.
func TestPostgresTunnelOnlyRefusesDirectAccess(t *testing.T) {
	g := newFakeGateway(t)
	s := bootServer(t, ServerOpts{
		ExtraArgs: []string{"--tunnel", "--tunnel-only"},
		Env:       []string{"TUNNEL_GATEWAY_URL=" + g.url(), "TUNNEL_KEY=e2e-tunnel-key", "TUNNEL_SERVICE_VERSION=e2e-1"},
		NoClient:  true,
	})
	sess, _ := g.waitSession(t)
	if body := waitReadyz(t, s.URL, 200, 10*time.Second); !strings.Contains(body, `"ready":true`) {
		t.Fatalf("/readyz: %s", body)
	}

	initialize := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"direct","version":"0"}}}`
	direct := func(rawQuery string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, s.URL+"/mcp"+rawQuery, strings.NewReader(initialize))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("direct request: %v", err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	for _, q := range []string{"", "?tunnel_token=", "?tunnel_token=0000000000000000000000000000000000000000000000000000000000000000", "?tunnel_token=guess"} {
		code, body := direct(q)
		if code != http.StatusUnauthorized || !strings.Contains(body, "direct access refused") {
			t.Fatalf("direct /mcp%s: want 401 refused, got %d %s", q, code, body)
		}
	}
	if code, _ := httpGet(t, s.URL+"/healthz"); code != 200 {
		t.Fatalf("/healthz = %d", code)
	}

	// The same initialize through the tunnel is accepted and tools work.
	req, _ := http.NewRequest(http.MethodPost, "http://tunnel/", strings.NewReader(initialize))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, respBody := g.roundTrip(t, sess, req)
	if resp.StatusCode != 200 || !strings.Contains(respBody, "restrictedsql-mcp") {
		t.Fatalf("initialize through tunnel: %d %s", resp.StatusCode, respBody)
	}
	sessionID := resp.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		t.Fatalf("no Mcp-Session-Id through the tunnel; headers %v", resp.Header)
	}
	req, _ = http.NewRequest(http.MethodPost, "http://tunnel/", strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Session-Id", sessionID)
	g.roundTrip(t, sess, req)
	call := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute_sql_readonly","arguments":{"sql":"SELECT count(*) AS n FROM allowed_orders"}}}`
	req, _ = http.NewRequest(http.MethodPost, "http://tunnel/", strings.NewReader(call))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Session-Id", sessionID)
	resp, respBody = g.roundTrip(t, sess, req)
	if resp.StatusCode != 200 || !strings.Contains(respBody, `"row_count":1`) {
		t.Fatalf("tools/call through tunnel: %d %s", resp.StatusCode, respBody)
	}

	// A session id obtained through the tunnel does not unlock direct access.
	req, _ = http.NewRequest(http.MethodPost, s.URL+"/mcp", strings.NewReader(call))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Session-Id", sessionID)
	dresp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("direct request with session id: %v", err)
	}
	dresp.Body.Close()
	if dresp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("direct /mcp with tunnel session id: want 401, got %d", dresp.StatusCode)
	}

	if logs := s.Logs.String(); strings.Contains(logs, "tunnel_token=") {
		t.Fatalf("tunnel token leaked into logs")
	}
	if !strings.Contains(s.Logs.String(), "tunnel-only mode") {
		t.Fatalf("tunnel-only mode not logged\n%s", s.Logs.String())
	}
}

// TestCommonTunnelOnlyFlagValidation checks the flag cannot be used without
// the tunnel or with the stdio transport.
func TestCommonTunnelOnlyFlagValidation(t *testing.T) {
	base := []string{"--dialect", "postgres", "--dsn", pgDSN(), "--read-tables", "allowed_orders"}
	cases := map[string][]string{
		"requires --tunnel":         append(append([]string{}, base...), "--tunnel-only"),
		"requires --transport http": append(append([]string{}, base...), "--tunnel", "--tunnel-only", "--transport", "stdio"),
	}
	for want, args := range cases {
		code, stderr := bootServerExpectExit(t, args)
		if code != 2 || !strings.Contains(stderr, want) {
			t.Fatalf("args %v: want exit 2 containing %q, got %d %q", args, want, code, stderr)
		}
	}
}
