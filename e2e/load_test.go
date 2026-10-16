package e2e

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestPostgresLoad drives many concurrent MCP clients at one server serving a
// main database and several further ones, with connection-level security and
// writes on. Reads must all succeed (they queue for a pooled connection);
// the only accepted failure is begin_transaction at the --max-open-txns cap.
// Postgres connections must stay within docs/connection-model.md's bound,
// /readyz must stay 200, and idle connections must be shed afterwards.
//
// Opt-in: E2E=1 E2E_LOAD=1. E2E_LOAD_AGENTS (1000), E2E_LOAD_DBS (10) and
// E2E_LOAD_SECONDS (60) size it.
func TestPostgresLoad(t *testing.T) {
	if os.Getenv("E2E_LOAD") == "" {
		t.Skip("set E2E_LOAD=1 to run the load test")
	}
	agents, extraDBs, seconds := envInt("E2E_LOAD_AGENTS", 1000), envInt("E2E_LOAD_DBS", 10), envInt("E2E_LOAD_SECONDS", 60)
	const (
		poolMaxConns   = 16
		dbPoolMaxConns = 4
		maxOpenTxns    = 8
		schema         = "load"
	)
	ctx := context.Background()
	su := superuserConn(t)
	stamp := time.Now().UnixNano()
	prefix := fmt.Sprintf("e2e_load_%d_", stamp)
	bootstrap := fmt.Sprintf("bootstrap_load_%d", stamp)
	rolePrefix := fmt.Sprintf("rsqlload%d", stamp%1000000)
	databases := []string{prefix + "main"}
	for i := 0; i < extraDBs; i++ {
		databases = append(databases, fmt.Sprintf("%spr_%d", prefix, i))
	}

	exec := func(c *pgx.Conn, sql string) {
		t.Helper()
		if _, err := c.Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	exec(su, "CREATE ROLE "+bootstrap+" LOGIN CREATEROLE NOSUPERUSER PASSWORD 'bootstrap-pw'")
	t.Cleanup(func() {
		rows, err := su.Query(ctx, "SELECT rolname FROM pg_roles WHERE rolname LIKE $1", rolePrefix+"%")
		if err == nil {
			roles, _ := pgx.CollectRows(rows, pgx.RowTo[string])
			for _, role := range append(roles, bootstrap) {
				_, _ = su.Exec(ctx, "DROP ROLE IF EXISTS "+pgx.Identifier{role}.Sanitize())
			}
		}
	})
	t.Cleanup(func() {
		for _, database := range databases {
			_, _ = su.Exec(ctx, "DROP DATABASE IF EXISTS "+database+" WITH (FORCE)")
		}
	})
	for _, database := range databases {
		exec(su, "CREATE DATABASE "+database)
		c, err := pgx.Connect(ctx, dsnForDatabase(t, database))
		if err != nil {
			t.Fatal(err)
		}
		for _, sql := range []string{
			"CREATE SCHEMA " + schema,
			"CREATE TABLE " + schema + ".items (id integer PRIMARY KEY, label text NOT NULL)",
			"INSERT INTO " + schema + ".items SELECT g, 'item-' || g FROM generate_series(1, 1000) g",
			"GRANT USAGE ON SCHEMA " + schema + " TO " + bootstrap + " WITH GRANT OPTION",
			"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA " + schema + " TO " + bootstrap + " WITH GRANT OPTION",
		} {
			exec(c, sql)
		}
		_ = c.Close(ctx)
	}

	u, err := url.Parse(dsnForDatabase(t, databases[0]))
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(bootstrap, "bootstrap-pw")
	s := bootServer(t, ServerOpts{
		Dialect:     "postgres",
		DSN:         u.String(),
		ReadTables:  []string{schema + ".*"},
		WriteTables: []string{schema + ".*"},
		Writes:      true,
		NoClient:    true,
		ExtraArgs: []string{"--default-schema", schema, "--connection-level-security",
			"--security-role-prefix", rolePrefix, "--databases", "^" + prefix + "pr_",
			"--pool-max-conns", strconv.Itoa(poolMaxConns), "--database-pool-max-conns", strconv.Itoa(dbPoolMaxConns),
			"--max-open-txns", strconv.Itoa(maxOpenTxns), "--log-level", "info"},
	})

	// The server's connections are those of its provisioned roles and the
	// bootstrap role; the superuser and other tests are not counted.
	serverConns := func() int {
		var n int
		err := su.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE usename = $1 OR usename LIKE $2`,
			bootstrap, rolePrefix+"%").Scan(&n)
		if err != nil {
			t.Errorf("count connections: %v", err)
		}
		return n
	}
	// docs/connection-model.md: 1 (probe) + P + T + p × N, plus transients
	// (one listing, one bootstrap connection per database being opened).
	bound := 1 + poolMaxConns + maxOpenTxns + dbPoolMaxConns*extraDBs + 1 + extraDBs

	// Breakdown of the server's connections by kind, for the peak sample.
	breakdown := func() string {
		rows, err := su.Query(ctx, `SELECT CASE WHEN usename = $1 THEN 'bootstrap'
	WHEN usename LIKE '%\_rw' THEN 'rw' ELSE 'ro' END AS kind, state, count(*)
FROM pg_stat_activity WHERE usename = $1 OR usename LIKE $2 GROUP BY 1, 2 ORDER BY 1, 2`, bootstrap, rolePrefix+"%")
		if err != nil {
			return err.Error()
		}
		var parts []string
		for rows.Next() {
			var kind string
			var state *string
			var n int
			if err := rows.Scan(&kind, &state, &n); err != nil {
				return err.Error()
			}
			st := "?"
			if state != nil {
				st = *state
			}
			parts = append(parts, fmt.Sprintf("%s/%s=%d", kind, st, n))
		}
		return strings.Join(parts, " ")
	}
	var peakBreakdown atomic.Value
	peakBreakdown.Store("")
	var (
		peakConns, readyzFailures, samples atomic.Int64
		stopSampling                       = make(chan struct{})
		samplerDone                        = make(chan struct{})
	)
	go func() {
		defer close(samplerDone)
		tick := time.NewTicker(250 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stopSampling:
				return
			case <-tick.C:
				if n := int64(serverConns()); n > peakConns.Load() {
					peakConns.Store(n)
					peakBreakdown.Store(breakdown())
				}
				if code, body := tryGet(s.URL + "/readyz"); code != 200 {
					readyzFailures.Add(1)
					t.Logf("readyz %d: %s", code, body)
				}
				samples.Add(1)
			}
		}
	}()

	type tally struct {
		calls, unexpected, txnCapped, txns atomic.Int64
		maxLatency                         atomic.Int64
	}
	var tl tally
	var errMu sync.Mutex
	errSamples := map[string]int{}
	record := func(tool, errText string, d time.Duration) {
		tl.calls.Add(1)
		if ms := d.Milliseconds(); ms > tl.maxLatency.Load() {
			tl.maxLatency.Store(ms)
		}
		if errText == "" {
			return
		}
		if tool == "begin_transaction" && strings.Contains(errText, "too many open transactions") {
			tl.txnCapped.Add(1)
			return
		}
		tl.unexpected.Add(1)
		key := tool + ": " + errText
		if len(key) > 200 {
			key = key[:200]
		}
		errMu.Lock()
		errSamples[key]++
		errMu.Unlock()
	}

	// One keep-alive transport for all agents, as a gateway would hold, with
	// at most 256 connections: every in-flight HTTP/1.1 request needs its own
	// TCP connection, and a thousand concurrent dials overflow macOS's listen
	// backlog (kern.ipc.somaxconn, 128) with resets. Requests beyond 256
	// queue in the client, as they would behind the tunnel.
	httpClient := &http.Client{Transport: &http.Transport{MaxConnsPerHost: 256, MaxIdleConnsPerHost: 256, IdleConnTimeout: time.Minute}}
	deadline := time.Now().Add(time.Duration(seconds) * time.Second)
	var wg sync.WaitGroup
	start := time.Now()
	for a := 0; a < agents; a++ {
		wg.Add(1)
		go func(a int) {
			defer wg.Done()
			// Ramp up over the first five seconds.
			time.Sleep(time.Duration(a) * 5 * time.Second / time.Duration(agents))
			cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			client := mcp.NewClient(&mcp.Implementation{Name: fmt.Sprintf("load-%d", a), Version: "0"}, nil)
			session, err := client.Connect(cctx, &mcp.StreamableClientTransport{Endpoint: s.URL + "/mcp", HTTPClient: httpClient, DisableStandaloneSSE: true}, nil)
			cancel()
			if err != nil {
				record("connect", err.Error(), 0)
				return
			}
			defer session.Close()
			rng := rand.New(rand.NewPCG(uint64(a), uint64(stamp)))
			call := func(tool string, args map[string]any) (*mcp.CallToolResult, string) {
				cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
				defer cancel()
				t0 := time.Now()
				res, err := session.CallTool(cctx, &mcp.CallToolParams{Name: tool, Arguments: args})
				errText := ""
				switch {
				case err != nil:
					errText = "protocol: " + err.Error()
				case res.IsError:
					errText = firstText(res)
				}
				record(tool, errText, time.Since(t0))
				return res, errText
			}
			for time.Now().Before(deadline) {
				database := ""
				if i := rng.IntN(extraDBs + 1); i > 0 {
					database = databases[i]
				}
				withDB := func(args map[string]any) map[string]any {
					if database != "" {
						args["database"] = database
					}
					return args
				}
				switch r := rng.IntN(100); {
				case r < 70:
					call("execute_sql_readonly", withDB(map[string]any{
						"sql": fmt.Sprintf("SELECT id, label FROM items WHERE id BETWEEN %d AND %d ORDER BY id", rng.IntN(900)+1, rng.IntN(900)+100)}))
				case r < 80:
					call("list_objects", withDB(map[string]any{"schema": schema}))
				case r < 85:
					call("get_object_details", withDB(map[string]any{"schema": schema, "name": "items"}))
				case r < 90:
					call("list_databases", map[string]any{})
				default:
					res, errText := call("begin_transaction", withDB(map[string]any{}))
					if errText != "" {
						continue
					}
					tl.txns.Add(1)
					id := fmt.Sprint(res.StructuredContent.(map[string]any)["transaction_id"])
					call("execute_sql_write", map[string]any{"transaction_id": id,
						"sql": fmt.Sprintf("UPDATE items SET label = label WHERE id = %d", rng.IntN(1000)+1)})
					call("rollback_transaction", map[string]any{"transaction_id": id})
				}
			}
		}(a)
	}
	wg.Wait()
	elapsed := time.Since(start)
	close(stopSampling)
	<-samplerDone

	t.Logf("agents=%d databases=1+%d duration=%s calls=%d (%.0f/s) txns=%d txn_capped=%d unexpected=%d max_latency=%dms",
		agents, extraDBs, elapsed.Round(time.Second), tl.calls.Load(), float64(tl.calls.Load())/elapsed.Seconds(),
		tl.txns.Load(), tl.txnCapped.Load(), tl.unexpected.Load(), tl.maxLatency.Load())
	t.Logf("peak server connections=%d (bound %d) [%s], readyz failures=%d of %d samples", peakConns.Load(), bound, peakBreakdown.Load(), readyzFailures.Load(), samples.Load())
	for k, n := range errSamples {
		t.Logf("unexpected error x%d: %s", n, k)
	}
	if tl.unexpected.Load() > 0 {
		t.Errorf("%d unexpected errors; every call but begin_transaction at the cap must succeed", tl.unexpected.Load())
	}
	if tl.txns.Load() == 0 {
		t.Errorf("no transaction ever began")
	}
	if peak := peakConns.Load(); peak > int64(bound) {
		t.Errorf("peak server connections %d exceed the bound %d", peak, bound)
	}
	if readyzFailures.Load() > 0 {
		t.Errorf("/readyz failed %d times under load", readyzFailures.Load())
	}

	// Idle connections are closed after a minute (pgx checks every minute);
	// what remains is the probe connection and one per database still inside
	// the column-refresh window.
	settled := 1 + extraDBs + 2
	settleBy := time.Now().Add(3 * time.Minute)
	for {
		n := serverConns()
		if n <= settled {
			t.Logf("connections settled to %d after the load (limit %d)", n, settled)
			break
		}
		if time.Now().After(settleBy) {
			t.Errorf("connections still %d three minutes after the load, want <= %d", n, settled)
			break
		}
		time.Sleep(5 * time.Second)
	}
}

func envInt(key string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil && v > 0 {
		return v
	}
	return def
}
