# Server review report (Task R3)

Branch: `review-server` (off `main` at `5e534be`). Scope: `internal/mcpserver`,
`internal/txn`, `internal/health`, `internal/tunnel`, `internal/db/postgres/tx.go`,
`cmd/`. Every concern below is backed by an e2e test that runs the real binary
against the shared Docker stack; `make vet` and `make e2e` are green
(all Postgres, ClickHouse and Common suites, about 65s).

New test files: `e2e/postgres_txn_test.go`, `e2e/postgres_server_test.go`,
`e2e/tunnel_test.go`, plus helpers in `e2e/harness_review_test.go`
(direct pgx probe tagged with `application_name`, pg_stat_activity counters,
SIGTERM-and-wait, `docker pause` with unpause at cleanup, extra environment).

## Concerns checked

| # | Concern | Result | Test | Commit |
|---|---|---|---|---|
| 1 | Tx connection release: Exec error, then rollback | ok | `TestPostgresTxConnectionsReleasedOnEveryPath/exec_error_then_rollback` | — |
| 2 | Tx connection release: Commit error (aborted transaction) | ok | `.../commit_error_on_aborted_transaction` | — |
| 3 | Tx connection release: Rollback error / rollback after commit | ok | `.../commit_and_rollback_after_commit` | — |
| 4 | Tx connection release: Begin failure after Acquire | ok (session setup fails with `--statement-timeout 30000h`; 40 attempts never block the 16-connection pool) | `TestPostgresTxBeginFailureAfterAcquireReleasesConnection` | — |
| 5 | Tx connection release: context cancellation mid-statement | **fixed** – the call deadline (statement_timeout + 15s) closes the pgx connection; rollback of the dead connection returned `ROLLBACK: conn closed`; COMMIT/ROLLBACK also ran under the caller's context so a cancelled commit had an unknown outcome. Terminal statements now use their own 5s timeout; rollback on a lost connection reports success, commit reports "not committed". | `TestPostgresTxContextDeadlineDuringExec` (docker pause) | `c42684c` |
| 6 | Statement timeout inside a write transaction | ok (`canceling statement due to statement timeout`, transaction aborted, rollback releases the connection, no rows survive) | `.../statement_timeout_inside_transaction` | — |
| 7 | Reaper races: begin during reap, exec racing reap, double rollback | ok (6 goroutines × 8 cycles straddling a 1s idle deadline: every outcome is success or `unknown or expired`; concurrent double rollback has exactly one winner; no panics; no backend left in a transaction) | `TestPostgresTxReaperRaces` | — |
| 8 | execute_sql_write / commit / rollback after commit and after rollback | ok (`unknown or expired` from all three) | `TestPostgresWriteToolsAfterCommitAndRollback` | — |
| 9 | Concurrent calls on one transaction id | ok (16 parallel inserts all land on the single connection; commit vs rollback vs select race has exactly one terminal winner and the database state matches the winner) | `TestPostgresWriteConcurrentCallsOnOneTransaction` | — |
| 10 | Pool starvation by open transactions | **fixed** – with `--max-open-txns 20` the 17th `begin_transaction` blocked on `Acquire` for the full 45s call deadline and `/readyz` and reads could not get a connection. Pool is now at least `max-open-txns + 8` connections. | `TestPostgresTxPoolNotStarvedByOpenTransactions` | `21ec1ef` |
| 11 | `/readyz` when the database hangs (`docker pause`) | ok (three probes each answer 503 `db ping failed: ... deadline exceeded` within the 3s probe timeout; `/healthz` stays 200; readiness and queries recover after unpause) | `TestPostgresReadyzWhenDatabaseFrozen` | — |
| 12 | Graceful shutdown (SIGTERM) rolls back open transactions | ok (exit 0 in ~2ms, two `txn.closed` log lines, rows gone, no backend left) | `TestPostgresShutdownRollsBackOpenTransactions` | — |
| 13 | Shutdown bounded when the database hangs | **fixed** – took 20s: rollbacks were sequential (5s each) and `pool.Close` waited up to 15s for pgx's cancel request to the frozen server. Rollbacks now run in parallel, pool close is abandoned after 2s, and signal handling is restored after the first signal so a second SIGTERM/SIGINT kills a stalled process. Exit now ~7s. | `TestPostgresShutdownWithFrozenDatabase` | `88da1b4` |
| 14 | `max_rows` at 0, negative, above and at the cap | ok (`--max-rows 3`: 0, -1, -1000000, 100, absent → 3 rows truncated; 2 → 2; exact-cap result not truncated; both execute tools) | `TestPostgresMaxRowsBounds` | — |
| 15 | Error text never leaks the DSN or password | ok (a dedicated role with a unique password, a wrong password and a tunnel key; ~25 texts from rejected/failed queries, aborted commit, missing objects, hypopg errors, statement timeout, unreachable port, auth failure, invalid DSN exit, tunnel dial failure, `/readyz` bodies and all log lines contain none of them; pgx redacts the password in DSN parse errors) | `TestPostgresNoSecretInErrorsOrLogs` | — |
| 16 | Readiness re-evaluated after a missing table is created | ok (503 naming `public.<table>` → 200 after `CREATE TABLE` → queryable → 503 after `DROP`) | `TestPostgresReadyzRecoversWhenTableCreated` | — |
| 17 | Large values round-trip (bytea, jsonb, arrays, text) | **fixed** – 1MB bytea, 100k-element jsonb array, 10k-element text[], jsonb[], NULL elements, empty arrays and 100k-character text round-trip; but `ARRAY[ARRAY[1,2],ARRAY[3,4]]` arrived flattened as `[1,2,3,4]` because pgx decodes arrays into a flat `[]any`. Array columns are now scanned with their dimensions and nested. | `TestPostgresLargeValuesRoundTrip` | `a20af2a` |
| 18 | `explain_query` with `analyze` on write statements | ok (INSERT/UPDATE/DELETE, data-modifying CTE, and SELECT on a write-only table are rejected with and without `analyze`; row count unchanged; analyze on a SELECT returns a JSON plan) | `TestPostgresExplainRejectsWriteStatements` | — |
| 19 | tools/list descriptions and JSON schemas | ok (all 9 tools: description present, `type: object` input schema, `required` exactly `sql` / `transaction_id,sql` / `transaction_id` / `schema` / `schema,name`, optional fields present with descriptions, output schema present; a missing required field is a tool error) | `TestPostgresToolSchemas` | — |
| 20 | Tunnel runner: `LocalMCPURL` and proxying | **fixed** – a fake gateway in the test (websocket + yamux client) verifies the bearer key, service version and metadata headers, and sends `initialize`, `notifications/initialized` and `tools/call` through the agent to `/mcp` (200, `restrictedsql-mcp`, `row_count:1`); control paths return 404. Wiring was correct for the default loopback listen; `--listen 0.0.0.0:…`/`:…` produced a URL with that host, now normalised to `127.0.0.1`. | `TestPostgresTunnelProxiesToLocalMCP` | `f77cda0` |
| 21 | Tunnel runner: state and shutdown | ok (`/readyz` reports `connected` while a session is up and `connecting` after it drops or when the gateway is unreachable; the agent reconnects with backoff; SIGTERM exits in ~3ms with `tunnel agent stopped` logged; an unreachable gateway never blocks readiness or the listener) | `TestPostgresTunnelProxiesToLocalMCP`, `TestPostgresTunnelUnreachableGatewayKeepsServing` | — |

Commits `c13a13a`, `7798987`, `94bd4a3`, `c7bbdbb` add the harness helpers and
the tests; `go.mod` now lists `coder/websocket` and `hashicorp/yamux` as direct
dependencies (already in the graph via the gram agent) for the fake gateway.

## Reviewed and left unchanged

- `internal/mcpserver`: guard rejections happen before the transaction is
  touched; the server-side table double check and read-mode kind check are
  redundant with the guards but harmless; `capRows` handles every out-of-range
  value; every handler is bounded by `statement_timeout + 15s`.
- `internal/txn`: per-entry mutex serialises calls on one id; `reap` uses
  `TryLock` so an in-flight call is never reaped; `finish` marks the entry
  closed and removes it before running the terminal statement, so late callers
  see `unknown or expired`.
- `internal/health`: the 3s probe timeout is honoured by pgx (deadline on the
  socket, connection discarded).
- `cmd/`: unparsable DSN exits 1 (from `run`) rather than 2; the message is
  redacted by pgx. Left as is since it is not a flag error.

## Remaining risks

- Tool-call contexts are detached from the HTTP request (go-sdk keeps the
  session context), so a client that disconnects or SIGTERM does not cancel an
  in-flight statement; it runs until `statement_timeout`. Shutdown waits for
  in-flight write statements (up to `statement_timeout`) before rolling their
  transaction back, then 5s for rollback and 2s for the pool.
- The context-cancellation path in `Tx.Exec` is reachable only through the call
  deadline (statement_timeout + 15s) against a database that stops answering;
  the test pauses the container for ~16s to reach it.
- A frozen database still leaves pgx's asynchronous cancel-request goroutines
  (15s) behind at shutdown; the process exits without waiting for them.
- The pool has no explicit `connect_timeout` unless the DSN sets one; dial
  attempts are bounded only by the calling context (3s for `/readyz`,
  `statement_timeout + 15s` for tools).
- The tunnel agent's state is derived from its log messages
  (`tunnel agent connected` / `session ended` / `reconnecting`); a change of
  wording upstream would leave `/readyz` reporting `connecting` (it never gates
  readiness).
- `--listen 0.0.0.0` normalisation is code-reviewed only; the e2e suite binds
  loopback to avoid exposing a test port on the host network.
- The secret-leak test creates the role `e2e_leakprobe` in the shared e2e
  database (idempotent) and leaves it in place.
