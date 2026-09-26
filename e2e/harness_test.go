// Package e2e drives the real restrictedsql-mcp binary against Docker
// databases through the MCP client. Run with E2E=1; see the Makefile.
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// binaryPath is the binary built once in TestMain.
var binaryPath string

func TestMain(m *testing.M) {
	if os.Getenv("E2E") != "1" {
		fmt.Println("E2E=1 not set; skipping e2e tests")
		os.Exit(0)
	}
	dir, err := os.MkdirTemp("", "restrictedsql-e2e-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "mkdtemp:", err)
		os.Exit(1)
	}
	binaryPath = filepath.Join(dir, "restrictedsql-mcp")
	build := exec.Command("go", "build", "-o", binaryPath, "../cmd/restrictedsql-mcp")
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "go build failed:", err)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// ServerOpts configures one booted server process.
type ServerOpts struct {
	Dialect     string   // "postgres" | "clickhouse"
	DSN         string   // default from pgDSN()/chDSN() by dialect
	ReadTables  []string // default: allowed_orders, allowed_customers
	WriteTables []string
	Writes      bool // adds --dangerously-add-write-tools
	ExtraArgs   []string
	Env         []string // extra KEY=VALUE pairs for the process environment
	ExpectReady *bool    // nil → wait for 200 on /readyz; false → wait for 503
	// AnyReadiness accepts whatever /readyz answers; use it for tests that
	// only need the MCP endpoint (tool listing) and not a live database.
	AnyReadiness bool
	// NoClient skips the direct MCP client connection to /mcp; use it when
	// the server is booted with --tunnel-only and direct access must fail.
	NoClient bool
}

// Server is a running binary with a connected MCP client session.
type Server struct {
	URL     string
	Session *mcp.ClientSession
	Logs    *syncBuffer
	cmd     *exec.Cmd
	exited  chan struct{} // closed once the process has been waited for
	waitErr error
}

// syncBuffer is a bytes.Buffer safe for concurrent writes from the
// subprocess pipes and reads from the test.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func boolPtr(b bool) *bool { return &b }

func pgDSN() string {
	if v := os.Getenv("E2E_PG_DSN"); v != "" {
		return v
	}
	return "postgres://postgres:postgres@127.0.0.1:" + envOr("E2E_PG_PORT", "55433") + "/app?sslmode=disable"
}

func chDSN() string {
	if v := os.Getenv("E2E_CH_DSN"); v != "" {
		return v
	}
	return "clickhouse://default:@127.0.0.1:" + envOr("E2E_CH_NATIVE_PORT", "59000") + "/app"
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

func (o ServerOpts) args(listen string) []string {
	dsn := o.DSN
	if dsn == "" {
		if o.Dialect == "clickhouse" {
			dsn = chDSN()
		} else {
			dsn = pgDSN()
		}
	}
	read := o.ReadTables
	if read == nil {
		read = []string{"allowed_orders", "allowed_customers"}
	}
	args := []string{
		"--dialect", o.Dialect,
		"--dsn", dsn,
		"--read-tables", strings.Join(read, ","),
		"--transport", "http",
		"--listen", listen,
		"--log-level", "debug",
	}
	if len(o.WriteTables) > 0 {
		args = append(args, "--write-tables", strings.Join(o.WriteTables, ","))
	}
	if o.Writes {
		args = append(args, "--dangerously-add-write-tools")
	}
	return append(args, o.ExtraArgs...)
}

// bootServer starts the binary with the given options, waits for the
// expected readiness state, and connects an MCP client. The process is
// killed at test cleanup and its logs are printed if the test failed.
func bootServer(t *testing.T, o ServerOpts) *Server {
	t.Helper()
	if o.Dialect == "" {
		o.Dialect = "postgres"
	}
	listen := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	logs := &syncBuffer{}
	cmd := exec.Command(binaryPath, o.args(listen)...)
	cmd.Stdout = logs
	cmd.Stderr = logs
	cmd.Env = append(os.Environ(), o.Env...)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	s := &Server{URL: "http://" + listen, Logs: logs, cmd: cmd, exited: make(chan struct{})}
	go func() {
		s.waitErr = cmd.Wait()
		close(s.exited)
	}()
	t.Cleanup(func() {
		if s.Session != nil {
			_ = s.Session.Close()
		}
		if strings.Contains(strings.Join(o.ExtraArgs, " "), "--columns-from-annotations") {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-s.exited:
			case <-time.After(5 * time.Second):
				_ = cmd.Process.Kill()
				<-s.exited
			}
		} else {
			_ = cmd.Process.Kill()
			<-s.exited
		}
		if t.Failed() {
			t.Logf("server logs (%s):\n%s", strings.Join(cmd.Args[1:], " "), logs.String())
		}
	})

	want := http.StatusOK
	if o.ExpectReady != nil && !*o.ExpectReady {
		want = http.StatusServiceUnavailable
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		status, body := tryGet(s.URL + "/readyz")
		if status == want || (o.AnyReadiness && status != 0) {
			break
		}
		select {
		case <-s.exited:
			t.Fatalf("server exited before reaching /readyz=%d (last %d %q)\nlogs:\n%s", want, status, body, logs.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not reach /readyz=%d within 30s (last %d %q)\nlogs:\n%s", want, status, body, logs.String())
		}
		time.Sleep(100 * time.Millisecond)
	}

	if o.NoClient {
		return s
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "0"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: s.URL + "/mcp"}, nil)
	if err != nil {
		t.Fatalf("mcp connect: %v\nlogs:\n%s", err, logs.String())
	}
	s.Session = session
	return s
}

// bootServerExpectExit runs the binary with raw args and returns its exit
// code and stderr. It fails the test if the process is still running after 10s.
func bootServerExpectExit(t *testing.T, args []string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binaryPath, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = io.Discard
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("server did not exit within 10s for args %v", args)
	}
	if err == nil {
		return 0, stderr.String()
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), stderr.String()
	}
	t.Fatalf("run server: %v", err)
	return -1, ""
}

// call invokes a tool. errText is non-empty iff the result is a tool error.
// out is the parsed structuredContent, falling back to the first text block
// parsed as JSON.
func (s *Server) call(t *testing.T, tool string, args map[string]any) (map[string]any, string) {
	t.Helper()
	if args == nil {
		args = map[string]any{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	res, err := s.Session.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("call %s: protocol error: %v", tool, err)
	}
	if res.IsError {
		return nil, firstText(res)
	}
	out := map[string]any{}
	if res.StructuredContent != nil {
		raw, err := json.Marshal(res.StructuredContent)
		if err != nil {
			t.Fatalf("call %s: marshal structuredContent: %v", tool, err)
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("call %s: structuredContent is not an object: %v", tool, err)
		}
		return out, ""
	}
	text := firstText(res)
	if text == "" {
		return out, ""
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("call %s: text content is not JSON: %v\n%s", tool, err, text)
	}
	return out, ""
}

func firstText(res *mcp.CallToolResult) string {
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			return tc.Text
		}
	}
	if res.IsError {
		return "tool error without text content"
	}
	return ""
}

// mustCall fails the test if the tool returns an error.
func (s *Server) mustCall(t *testing.T, tool string, args map[string]any) map[string]any {
	t.Helper()
	out, errText := s.call(t, tool, args)
	if errText != "" {
		t.Fatalf("call %s %v: unexpected tool error: %s", tool, args, errText)
	}
	return out
}

// mustReject fails the test unless the tool returns an error containing the
// given substring (case-insensitive).
func (s *Server) mustReject(t *testing.T, tool string, args map[string]any, contains string) {
	t.Helper()
	_, errText := s.call(t, tool, args)
	if errText == "" {
		t.Fatalf("call %s %v: expected an error containing %q, got success", tool, args, contains)
	}
	if !strings.Contains(strings.ToLower(errText), strings.ToLower(contains)) {
		t.Fatalf("call %s %v: error %q does not contain %q", tool, args, errText, contains)
	}
}

// toolNames returns the sorted tool names advertised by the server.
func (s *Server) toolNames(t *testing.T) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := s.Session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	var names []string
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
	}
	sort.Strings(names)
	return names
}

func tryGet(url string) (int, string) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// httpGet performs a GET and returns status and body.
func httpGet(t *testing.T, url string) (int, string) {
	t.Helper()
	status, body := tryGet(url)
	if status == 0 {
		t.Fatalf("GET %s: %s", url, body)
	}
	return status, body
}

// rows extracts the "rows" array from an execute result.
func rows(t *testing.T, out map[string]any) [][]any {
	t.Helper()
	raw, ok := out["rows"].([]any)
	if !ok {
		t.Fatalf("result has no rows array: %v", out)
	}
	var res [][]any
	for _, r := range raw {
		row, ok := r.([]any)
		if !ok {
			t.Fatalf("row is not an array: %v", r)
		}
		res = append(res, row)
	}
	return res
}

// columnNames extracts the column names from an execute result.
func columnNames(t *testing.T, out map[string]any) []string {
	t.Helper()
	raw, ok := out["columns"].([]any)
	if !ok {
		t.Fatalf("result has no columns array: %v", out)
	}
	var names []string
	for _, c := range raw {
		m, ok := c.(map[string]any)
		if !ok {
			t.Fatalf("column is not an object: %v", c)
		}
		names = append(names, fmt.Sprint(m["name"]))
	}
	return names
}

// num reads a JSON number from a result as float64.
func num(t *testing.T, out map[string]any, key string) float64 {
	t.Helper()
	f, ok := out[key].(float64)
	if !ok {
		t.Fatalf("result[%q] is not a number: %v (%T)", key, out[key], out[key])
	}
	return f
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
