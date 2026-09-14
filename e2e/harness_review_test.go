package e2e

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// probeAppName is the application_name of the test's own direct Postgres
// connection so it never counts itself when inspecting pg_stat_activity.
const probeAppName = "e2e-probe"

// dsnWithApp returns the Postgres DSN with application_name set so the
// server's backends can be told apart in pg_stat_activity.
func dsnWithApp(app string) string {
	dsn := pgDSN()
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "application_name=" + app
}

// pgProbe opens a direct pgx connection to the e2e database.
func pgProbe(t *testing.T) *pgx.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsnWithApp(probeAppName))
	if err != nil {
		t.Fatalf("direct postgres connection: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = conn.Close(ctx)
	})
	return conn
}

// backends counts the server's connections in pg_stat_activity, and how
// many of them are inside a transaction (idle in transaction or active).
func backends(t *testing.T, conn *pgx.Conn, app string) (total, inTx int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := conn.QueryRow(ctx, `
SELECT count(*), count(*) FILTER (WHERE state <> 'idle')
FROM pg_stat_activity WHERE application_name = $1`, app).Scan(&total, &inTx)
	if err != nil {
		t.Fatalf("pg_stat_activity: %v", err)
	}
	return total, inTx
}

// waitNoTx fails unless every backend of app leaves its transaction within
// the timeout. Released connections may stay in the pool idle, so only the
// in-transaction count is expected to return to zero.
func waitNoTx(t *testing.T, conn *pgx.Conn, app string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		total, inTx := backends(t, conn, app)
		if inTx == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d backends for %s still in a transaction after %s", inTx, total, app, timeout)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// waitGone fails unless every backend of app is gone within the timeout.
func waitGone(t *testing.T, conn *pgx.Conn, app string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		total, _ := backends(t, conn, app)
		if total == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d backends for %s still connected after %s", total, app, timeout)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func scalar(t *testing.T, conn *pgx.Conn, sql string, args ...any) int64 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var n int64
	if err := conn.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func execSQL(t *testing.T, conn *pgx.Conn, sql string, args ...any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := conn.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// signalAndWait sends sig to the server and returns its exit code, failing
// if it is still running after timeout.
func (s *Server) signalAndWait(t *testing.T, sig syscall.Signal, timeout time.Duration) int {
	t.Helper()
	if err := s.cmd.Process.Signal(sig); err != nil {
		t.Fatalf("signal %v: %v", sig, err)
	}
	select {
	case <-s.exited:
	case <-time.After(timeout):
		t.Fatalf("server still running %s after %v\nlogs:\n%s", timeout, sig, s.Logs.String())
	}
	if s.waitErr == nil {
		return 0
	}
	if ee, ok := s.waitErr.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	t.Fatalf("wait: %v", s.waitErr)
	return -1
}

// logLines returns the server's JSON log lines containing substr.
func (s *Server) logLines(substr string) []string {
	var out []string
	for _, line := range strings.Split(s.Logs.String(), "\n") {
		if strings.Contains(line, substr) {
			out = append(out, line)
		}
	}
	return out
}

func pgContainer() string {
	return envOr("E2E_PG_CONTAINER", "e2e-postgres-1")
}

// pausePostgres freezes the Postgres container and returns an idempotent
// unpause function, which is also run at cleanup so a failing test never
// leaves the shared stack paused.
func pausePostgres(t *testing.T) func() {
	t.Helper()
	var once sync.Once
	unpause := func() {
		once.Do(func() {
			out, err := exec.Command("docker", "unpause", pgContainer()).CombinedOutput()
			if err != nil {
				t.Logf("docker unpause %s: %v: %s", pgContainer(), err, out)
			}
		})
	}
	t.Cleanup(unpause)
	if out, err := exec.Command("docker", "pause", pgContainer()).CombinedOutput(); err != nil {
		t.Fatalf("docker pause %s: %v: %s", pgContainer(), err, out)
	}
	return unpause
}

// runServerCaptureAll runs the binary with raw args and env until it exits
// (or the timeout), returning the exit code and everything it printed.
func runServerCaptureAll(t *testing.T, args, env []string, timeout time.Duration) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, binaryPath, args...)
	cmd.Env = append(os.Environ(), env...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("server did not exit within %s for args %v\n%s", timeout, args, out.String())
	}
	if err == nil {
		return 0, out.String()
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), out.String()
	}
	t.Fatalf("run server: %v", err)
	return -1, ""
}

// waitReadyz polls /readyz until it answers want or the timeout passes.
func waitReadyz(t *testing.T, url string, want int, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		status, body := tryGet(url + "/readyz")
		if status == want {
			return body
		}
		if time.Now().After(deadline) {
			t.Fatalf("/readyz did not answer %d within %s (last %d %q)", want, timeout, status, body)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func uniqueName(prefix string) string {
	return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano()%1_000_000_000)
}
