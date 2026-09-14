package e2e

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
)

// fakeGateway accepts the tunnel agent's websocket, speaks yamux as the
// client side (the agent is the yamux server) and hands each session to the
// test so it can push HTTP exchanges through the tunnel.
type fakeGateway struct {
	srv      *httptest.Server
	sessions chan *yamux.Session
	headers  chan http.Header
}

func newFakeGateway(t *testing.T) *fakeGateway {
	t.Helper()
	g := &fakeGateway{sessions: make(chan *yamux.Session, 4), headers: make(chan http.Header, 4)}
	g.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.headers <- r.Header.Clone()
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			t.Logf("websocket accept: %v", err)
			return
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		conn := websocket.NetConn(ctx, ws, websocket.MessageBinary)
		cfg := yamux.DefaultConfig()
		cfg.LogOutput = io.Discard
		sess, err := yamux.Client(conn, cfg)
		if err != nil {
			t.Logf("yamux client: %v", err)
			return
		}
		g.sessions <- sess
		<-sess.CloseChan()
	}))
	t.Cleanup(g.srv.Close)
	return g
}

func (g *fakeGateway) url() string {
	return "ws://" + strings.TrimPrefix(g.srv.URL, "http://") + "/"
}

func (g *fakeGateway) waitSession(t *testing.T) (*yamux.Session, http.Header) {
	t.Helper()
	select {
	case sess := <-g.sessions:
		return sess, <-g.headers
	case <-time.After(20 * time.Second):
		t.Fatalf("tunnel agent did not connect to the fake gateway")
		return nil, nil
	}
}

// roundTrip sends one HTTP request through a fresh yamux substream.
func (g *fakeGateway) roundTrip(t *testing.T, sess *yamux.Session, req *http.Request) (*http.Response, string) {
	t.Helper()
	stream, err := sess.Open()
	if err != nil {
		t.Fatalf("open substream: %v", err)
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(20 * time.Second))
	if err := req.Write(stream); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(stream), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

// TestPostgresTunnelProxiesToLocalMCP boots the server with --tunnel against
// a fake gateway and proves the agent authenticates with the configured key,
// proxies gateway requests to the local /mcp endpoint, reconnects when the
// session drops, reports its state on /readyz, and stops on SIGTERM.
func TestPostgresTunnelProxiesToLocalMCP(t *testing.T) {
	g := newFakeGateway(t)
	s := bootServer(t, ServerOpts{
		ExtraArgs: []string{"--tunnel"},
		Env:       []string{"TUNNEL_GATEWAY_URL=" + g.url(), "TUNNEL_KEY=e2e-tunnel-key", "TUNNEL_SERVICE_VERSION=e2e-1"},
	})
	sess, hdr := g.waitSession(t)
	if got := hdr.Get("Authorization"); got != "Bearer e2e-tunnel-key" {
		t.Fatalf("Authorization = %q", got)
	}
	if got := hdr.Get("X-Gram-Tunnel-Service-Version"); got != "e2e-1" {
		t.Fatalf("service version header = %q", got)
	}
	meta := map[string]string{}
	if err := json.Unmarshal([]byte(hdr.Get("X-Gram-Tunnel-Service-Metadata")), &meta); err != nil || meta["dialect"] != "postgres" || meta["write_tools"] != "false" {
		t.Fatalf("metadata header = %q (%v)", hdr.Get("X-Gram-Tunnel-Service-Metadata"), err)
	}
	body := waitReadyz(t, s.URL, 200, 10*time.Second)
	if !strings.Contains(body, `"tunnel":"connected"`) {
		t.Fatalf("/readyz while connected: %s", body)
	}

	initialize := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"gateway","version":"0"}}}`
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
	req, _ = http.NewRequest(http.MethodGet, "http://tunnel/_tunnel/other", nil)
	if resp, _ := g.roundTrip(t, sess, req); resp.StatusCode != 404 {
		t.Fatalf("control path proxied: %d", resp.StatusCode)
	}

	// Drop the session: the agent must reconnect with backoff.
	_ = sess.Close()
	sess2, _ := g.waitSession(t)
	body = waitReadyz(t, s.URL, 200, 10*time.Second)
	if !strings.Contains(body, `"tunnel":"connected"`) {
		t.Fatalf("/readyz after reconnect: %s", body)
	}
	if len(s.logLines("tunnel agent reconnecting")) == 0 {
		t.Fatalf("no reconnect logged\n%s", s.Logs.String())
	}
	_ = sess2

	start := time.Now()
	if code := s.signalAndWait(t, syscall.SIGTERM, 10*time.Second); code != 0 {
		t.Fatalf("exit code %d", code)
	}
	t.Logf("exited %s after SIGTERM with the tunnel connected", time.Since(start).Round(time.Millisecond))
	if len(s.logLines("tunnel agent stopped")) == 0 {
		t.Fatalf("tunnel agent stop not logged\n%s", s.Logs.String())
	}
}

// TestPostgresTunnelUnreachableGatewayKeepsServing checks a gateway that is
// down never blocks readiness or the local listener and that shutdown stays
// prompt while the agent is backing off.
func TestPostgresTunnelUnreachableGatewayKeepsServing(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	s := bootServer(t, ServerOpts{
		ExtraArgs: []string{"--tunnel"},
		Env:       []string{"TUNNEL_GATEWAY_URL=ws://" + addr + "/", "TUNNEL_KEY=e2e-tunnel-key"},
	})
	body := waitReadyz(t, s.URL, 200, 10*time.Second)
	if !strings.Contains(body, `"tunnel":"connecting"`) {
		t.Fatalf("/readyz with unreachable gateway: %s", body)
	}
	s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT 1"})
	deadline := time.Now().Add(10 * time.Second)
	for len(s.logLines("tunnel agent session ended")) == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("agent never reported the failed dial\n%s", s.Logs.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	if code := s.signalAndWait(t, syscall.SIGTERM, 10*time.Second); code != 0 {
		t.Fatalf("exit code %d", code)
	}
}
