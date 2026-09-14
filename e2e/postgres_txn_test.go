package e2e

import (
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// writeServerApp boots a write-enabled server whose Postgres backends carry
// the given application_name.
func writeServerApp(t *testing.T, app string, extra ...string) *Server {
	t.Helper()
	return bootServer(t, ServerOpts{DSN: dsnWithApp(app), WriteTables: []string{"allowed_audit"}, Writes: true, ExtraArgs: extra})
}

// TestPostgresTxConnectionsReleasedOnEveryPath drives each way a write
// transaction can end and checks pg_stat_activity: no backend may stay in a
// transaction, and repeating each path more times than the pool holds
// connections must never block on an exhausted pool.
func TestPostgresTxConnectionsReleasedOnEveryPath(t *testing.T) {
	probe := pgProbe(t)
	app := uniqueName("e2e_txpaths")
	s := writeServerApp(t, app, "--statement-timeout", "1s")
	const rounds = 20

	t.Run("exec error then rollback", func(t *testing.T) {
		for i := 0; i < rounds; i++ {
			id := beginTx(t, s)
			s.mustReject(t, "execute_sql_write", map[string]any{"transaction_id": id, "sql": "SELECT 1/0"}, "division by zero")
			s.mustCall(t, "rollback_transaction", map[string]any{"transaction_id": id})
		}
		waitNoTx(t, probe, app, 3*time.Second)
	})
	t.Run("commit error on aborted transaction", func(t *testing.T) {
		for i := 0; i < rounds; i++ {
			id := beginTx(t, s)
			s.mustReject(t, "execute_sql_write", map[string]any{"transaction_id": id, "sql": "SELECT 1/0"}, "division by zero")
			s.mustReject(t, "commit_transaction", map[string]any{"transaction_id": id}, "aborted")
		}
		waitNoTx(t, probe, app, 3*time.Second)
	})
	t.Run("statement timeout inside transaction", func(t *testing.T) {
		id := beginTx(t, s)
		s.mustCall(t, "execute_sql_write", map[string]any{"transaction_id": id, "sql": "INSERT INTO allowed_audit (note) VALUES ('timeout')"})
		start := time.Now()
		s.mustReject(t, "execute_sql_write", map[string]any{"transaction_id": id, "sql": slowQuery}, "canceling statement due to statement timeout")
		if d := time.Since(start); d > 10*time.Second {
			t.Fatalf("statement timeout took %s", d)
		}
		s.mustReject(t, "execute_sql_write", map[string]any{"transaction_id": id, "sql": "SELECT 1"}, "current transaction is aborted")
		s.mustCall(t, "rollback_transaction", map[string]any{"transaction_id": id})
		waitNoTx(t, probe, app, 3*time.Second)
		if n := scalar(t, probe, "SELECT count(*) FROM allowed_audit WHERE note = 'timeout'"); n != 0 {
			t.Fatalf("timed-out transaction left %d rows", n)
		}
	})
	t.Run("commit and rollback after commit", func(t *testing.T) {
		for i := 0; i < rounds; i++ {
			id := beginTx(t, s)
			s.mustCall(t, "commit_transaction", map[string]any{"transaction_id": id})
			s.mustReject(t, "rollback_transaction", map[string]any{"transaction_id": id}, "unknown or expired")
		}
		waitNoTx(t, probe, app, 3*time.Second)
	})
	total, _ := backends(t, probe, app)
	if total > 16 {
		t.Fatalf("server holds %d backends after the cycles; connections are leaking", total)
	}
}

// TestPostgresTxBeginFailureAfterAcquireReleasesConnection makes the
// session setup after BEGIN fail (statement_timeout beyond Postgres's range)
// so Begin errors after the connection was acquired. Repeating it more times
// than the pool size proves the connection is released each time.
func TestPostgresTxBeginFailureAfterAcquireReleasesConnection(t *testing.T) {
	probe := pgProbe(t)
	app := uniqueName("e2e_txbeginfail")
	s := writeServerApp(t, app, "--statement-timeout", "30000h")
	for i := 0; i < 40; i++ {
		start := time.Now()
		s.mustReject(t, "begin_transaction", nil, "statement_timeout")
		if d := time.Since(start); d > 5*time.Second {
			t.Fatalf("begin_transaction #%d took %s; the pool is blocked on leaked connections", i, d)
		}
	}
	waitNoTx(t, probe, app, 3*time.Second)
	if total, _ := backends(t, probe, app); total > 16 {
		t.Fatalf("server holds %d backends; connections leaked by failed Begin", total)
	}
}

// TestPostgresTxContextDeadlineDuringExec freezes the database while a
// statement is in flight so the tool call hits the server-side call deadline
// (statement_timeout + 15s). The dead connection must be discarded, the id
// invalidated, and the server usable again once the database is back.
func TestPostgresTxContextDeadlineDuringExec(t *testing.T) {
	probe := pgProbe(t)
	app := uniqueName("e2e_txdeadline")
	s := writeServerApp(t, app, "--statement-timeout", "1s")
	id := beginTx(t, s)
	s.mustCall(t, "execute_sql_write", map[string]any{"transaction_id": id, "sql": "INSERT INTO allowed_audit (note) VALUES ('deadline')"})

	unpause := pausePostgres(t)
	start := time.Now()
	_, errText := s.call(t, "execute_sql_write", map[string]any{"transaction_id": id, "sql": "SELECT count(*) FROM allowed_audit"})
	elapsed := time.Since(start)
	unpause()
	if errText == "" {
		t.Fatalf("exec against a frozen database succeeded")
	}
	if elapsed > 30*time.Second {
		t.Fatalf("exec against a frozen database took %s; the call deadline did not fire", elapsed)
	}
	t.Logf("exec on frozen db failed after %s: %s", elapsed.Round(time.Millisecond), errText)

	waitReadyz(t, s.URL, 200, 30*time.Second)
	// The dead connection means the server already discarded the
	// transaction, so rollback reports success rather than a broken pipe.
	s.mustCall(t, "rollback_transaction", map[string]any{"transaction_id": id})
	s.mustReject(t, "execute_sql_write", map[string]any{"transaction_id": id, "sql": "SELECT 1"}, "unknown or expired")
	waitNoTx(t, probe, app, 10*time.Second)
	if n := scalar(t, probe, "SELECT count(*) FROM allowed_audit WHERE note = 'deadline'"); n != 0 {
		t.Fatalf("interrupted transaction left %d rows", n)
	}
	id2 := beginTx(t, s)
	if got := auditCount(t, s, id2); got != 0 {
		t.Fatalf("audit count after recovery = %v", got)
	}
	s.mustCall(t, "rollback_transaction", map[string]any{"transaction_id": id2})
}

// TestPostgresTxReaperRaces runs begin/exec/rollback loops in parallel with
// a fast reaper, straddling the idle deadline on purpose. Every outcome must
// be either success or "unknown or expired"; nothing may hang, panic, or
// leave a backend in a transaction.
func TestPostgresTxReaperRaces(t *testing.T) {
	probe := pgProbe(t)
	app := uniqueName("e2e_reaper")
	s := writeServerApp(t, app, "--txn-idle-timeout", "1s", "--max-open-txns", "16")

	var wg sync.WaitGroup
	errs := make(chan string, 1000)
	for g := 0; g < 6; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(g)))
			for i := 0; i < 8; i++ {
				out, errText := s.call(t, "begin_transaction", nil)
				if errText != "" {
					errs <- "begin: " + errText
					continue
				}
				id, _ := out["transaction_id"].(string)
				time.Sleep(time.Duration(700+rng.Intn(600)) * time.Millisecond)
				_, errText = s.call(t, "execute_sql_write", map[string]any{"transaction_id": id, "sql": "SELECT count(*) FROM allowed_audit"})
				switch {
				case errText == "":
					if _, rb := s.call(t, "rollback_transaction", map[string]any{"transaction_id": id}); rb != "" {
						errs <- "rollback after successful exec: " + rb
					}
				case strings.Contains(errText, "unknown or expired"):
				default:
					errs <- "exec: " + errText
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Errorf("unexpected outcome: %s", e)
	}

	// Double rollback from two goroutines: exactly one wins.
	for i := 0; i < 10; i++ {
		id := beginTx(t, s)
		results := make(chan string, 2)
		for j := 0; j < 2; j++ {
			go func() {
				_, errText := s.call(t, "rollback_transaction", map[string]any{"transaction_id": id})
				results <- errText
			}()
		}
		a, b := <-results, <-results
		ok := (a == "" && strings.Contains(b, "unknown or expired")) || (b == "" && strings.Contains(a, "unknown or expired"))
		if !ok {
			t.Fatalf("double rollback outcomes: %q / %q", a, b)
		}
	}

	if lines := s.logLines("panic"); len(lines) > 0 {
		t.Fatalf("server logged a panic:\n%s", strings.Join(lines, "\n"))
	}
	waitNoTx(t, probe, app, 5*time.Second)
	id := beginTx(t, s)
	s.mustCall(t, "rollback_transaction", map[string]any{"transaction_id": id})
}

// TestPostgresWriteToolsAfterCommitAndRollback checks that a finished id is
// rejected by every write tool, whichever way it finished.
func TestPostgresWriteToolsAfterCommitAndRollback(t *testing.T) {
	s := writeServer(t)
	for _, finish := range []string{"commit_transaction", "rollback_transaction"} {
		id := beginTx(t, s)
		s.mustCall(t, "execute_sql_write", map[string]any{"transaction_id": id, "sql": "SELECT 1"})
		s.mustCall(t, finish, map[string]any{"transaction_id": id})
		s.mustReject(t, "execute_sql_write", map[string]any{"transaction_id": id, "sql": "SELECT 1"}, "unknown or expired")
		s.mustReject(t, "commit_transaction", map[string]any{"transaction_id": id}, "unknown or expired")
		s.mustReject(t, "rollback_transaction", map[string]any{"transaction_id": id}, "unknown or expired")
	}
}

// TestPostgresWriteConcurrentCallsOnOneTransaction fires parallel writes at
// one transaction id, then races commit, rollback and a select against each
// other. The connection is never shared between calls, so all writes land
// and exactly one terminal call wins.
func TestPostgresWriteConcurrentCallsOnOneTransaction(t *testing.T) {
	probe := pgProbe(t)
	app := uniqueName("e2e_concurrent")
	s := writeServerApp(t, app)
	note := uniqueName("concurrent")
	t.Cleanup(func() { execSQL(t, probe, "DELETE FROM allowed_audit WHERE note = $1", note) })

	id := beginTx(t, s)
	const writers = 16
	var wg sync.WaitGroup
	errs := make(chan string, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errText := s.call(t, "execute_sql_write", map[string]any{"transaction_id": id, "sql": fmt.Sprintf("INSERT INTO allowed_audit (note) VALUES ('%s')", note)})
			if errText != "" {
				errs <- errText
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Errorf("concurrent insert failed: %s", e)
	}
	out := s.mustCall(t, "execute_sql_write", map[string]any{"transaction_id": id, "sql": fmt.Sprintf("SELECT count(*) FROM allowed_audit WHERE note = '%s'", note)})
	if got := rows(t, out)[0][0]; got != float64(writers) {
		t.Fatalf("rows inside transaction = %v, want %d", got, writers)
	}

	type outcome struct{ tool, err string }
	results := make(chan outcome, 3)
	for _, tool := range []string{"commit_transaction", "rollback_transaction", "execute_sql_write"} {
		go func(tool string) {
			args := map[string]any{"transaction_id": id}
			if tool == "execute_sql_write" {
				args["sql"] = "SELECT 1"
			}
			_, errText := s.call(t, tool, args)
			results <- outcome{tool, errText}
		}(tool)
	}
	winner := ""
	for i := 0; i < 3; i++ {
		r := <-results
		switch {
		case r.err == "" && r.tool != "execute_sql_write":
			if winner != "" {
				t.Fatalf("both %s and %s succeeded", winner, r.tool)
			}
			winner = r.tool
		case r.err == "":
		case strings.Contains(r.err, "unknown or expired"):
		default:
			t.Fatalf("%s: unexpected error %q", r.tool, r.err)
		}
	}
	if winner == "" {
		t.Fatalf("neither commit nor rollback succeeded")
	}
	waitNoTx(t, probe, app, 5*time.Second)
	want := int64(0)
	if winner == "commit_transaction" {
		want = writers
	}
	if n := scalar(t, probe, "SELECT count(*) FROM allowed_audit WHERE note = $1", note); n != want {
		t.Fatalf("%s won but %d rows are visible, want %d", winner, n, want)
	}
}

// TestPostgresTxPoolNotStarvedByOpenTransactions opens more transactions
// than the default pool size allows; reads and readiness must keep working
// because the pool is sized above --max-open-txns.
func TestPostgresTxPoolNotStarvedByOpenTransactions(t *testing.T) {
	app := uniqueName("e2e_poolsize")
	s := writeServerApp(t, app, "--max-open-txns", "20")
	var ids []string
	for i := 0; i < 20; i++ {
		start := time.Now()
		ids = append(ids, beginTx(t, s))
		if d := time.Since(start); d > 5*time.Second {
			t.Fatalf("begin #%d took %s; the pool is exhausted", i, d)
		}
	}
	s.mustReject(t, "begin_transaction", nil, "too many")
	start := time.Now()
	status, body := httpGet(t, s.URL+"/readyz")
	if status != 200 {
		t.Fatalf("/readyz = %d %s with 20 open transactions (after %s)", status, body, time.Since(start))
	}
	start = time.Now()
	s.mustCall(t, "execute_sql_readonly", map[string]any{"sql": "SELECT 1"})
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("read query took %s with 20 open transactions", d)
	}
	for _, id := range ids {
		s.mustCall(t, "rollback_transaction", map[string]any{"transaction_id": id})
	}
}

// TestPostgresShutdownRollsBackOpenTransactions sends SIGTERM with two
// transactions holding uncommitted rows. The process must exit 0 within the
// grace period, roll both back, and leave no backend behind.
func TestPostgresShutdownRollsBackOpenTransactions(t *testing.T) {
	probe := pgProbe(t)
	app := uniqueName("e2e_shutdown")
	s := writeServerApp(t, app)
	note := uniqueName("shutdown")
	var ids []string
	for i := 0; i < 2; i++ {
		id := beginTx(t, s)
		s.mustCall(t, "execute_sql_write", map[string]any{"transaction_id": id, "sql": fmt.Sprintf("INSERT INTO allowed_audit (note) VALUES ('%s')", note)})
		ids = append(ids, id)
	}
	if _, inTx := backends(t, probe, app); inTx != 2 {
		t.Fatalf("expected 2 backends in a transaction, got %d", inTx)
	}
	start := time.Now()
	if code := s.signalAndWait(t, syscall.SIGTERM, 10*time.Second); code != 0 {
		t.Fatalf("exit code after SIGTERM = %d\nlogs:\n%s", code, s.Logs.String())
	}
	t.Logf("exited %s after SIGTERM", time.Since(start).Round(time.Millisecond))
	if lines := s.logLines(`"msg":"txn.closed"`); len(lines) != 2 {
		t.Fatalf("expected 2 txn.closed log lines, got %d\nlogs:\n%s", len(lines), s.Logs.String())
	}
	waitGone(t, probe, app, 5*time.Second)
	if n := scalar(t, probe, "SELECT count(*) FROM allowed_audit WHERE note = $1", note); n != 0 {
		t.Fatalf("%d rows survived shutdown", n)
	}
	if status, _ := tryGet(s.URL + "/healthz"); status != 0 {
		t.Fatalf("/healthz still answers %d after exit", status)
	}
}

// TestPostgresShutdownWithFrozenDatabase checks that SIGTERM still exits
// within the grace period when the database does not answer the rollback.
func TestPostgresShutdownWithFrozenDatabase(t *testing.T) {
	probe := pgProbe(t)
	app := uniqueName("e2e_frozenshutdown")
	s := writeServerApp(t, app)
	note := uniqueName("frozen")
	id := beginTx(t, s)
	s.mustCall(t, "execute_sql_write", map[string]any{"transaction_id": id, "sql": fmt.Sprintf("INSERT INTO allowed_audit (note) VALUES ('%s')", note)})

	unpause := pausePostgres(t)
	start := time.Now()
	code := s.signalAndWait(t, syscall.SIGTERM, 25*time.Second)
	elapsed := time.Since(start)
	unpause()
	t.Logf("exit code %d after %s with a frozen database", code, elapsed.Round(time.Millisecond))
	if elapsed > 10*time.Second {
		t.Fatalf("shutdown took %s with a frozen database, over the 10s grace period", elapsed)
	}
	if len(s.logLines(`"msg":"txn.closed"`)) != 1 {
		t.Fatalf("expected the open transaction to be closed at shutdown\nlogs:\n%s", s.Logs.String())
	}
	waitGone(t, probe, app, 30*time.Second)
	if n := scalar(t, probe, "SELECT count(*) FROM allowed_audit WHERE note = $1", note); n != 0 {
		t.Fatalf("%d rows survived shutdown", n)
	}
}

// slowQuery is a cross join large enough to exceed a 1s statement timeout.
const slowQuery = `SELECT count(*) FROM allowed_orders a, allowed_orders b, allowed_orders c, allowed_orders d,
allowed_orders e, allowed_orders f, allowed_orders g, allowed_orders h, allowed_orders i, allowed_orders j,
allowed_orders k, allowed_orders l`
