# Stream C report — server, harness, deploy

Branch: `stream-c-server`. Tasks C1–C6 are done; C7 (wiring the real
guards/backends and deleting the stubs) is left to the primary as planned.

## Done

| Task | Commit | Contents |
|------|--------|----------|
| C1 | `feat(config): flag parsing and policy construction` | `internal/config`, first `cmd/restrictedsql-mcp/main.go` |
| C2 | `test(e2e): compose stack, seed data, harness, smoke tests` | `e2e/docker-compose.yml`, `e2e/postgres/{Dockerfile,init.sql}`, `e2e/clickhouse/init.sql`, `e2e/harness_test.go`, `e2e/corpus_test.go`, `e2e/smoke_test.go`, `Makefile` |
| C3 | `feat(txn): transaction registry with idle reaper` | `internal/txn/registry.go` |
| C4 | `feat(mcp): server and tool handlers` | `internal/mcpserver/{server,tools_read,tools_meta,tools_write}.go`, `internal/sqlguard/stub`, `internal/db/stub` |
| C5 | `feat: boot wiring, health endpoints, tunnel runner` | `internal/health`, `internal/tunnel`, full `main.go` |
| C6 | `docs: README, Dockerfile, k8s manifest` | `deploy/Dockerfile`, `deploy/k8s.yaml`, `README.md` |

Wiring point for A and B: `selectDialect` in `cmd/restrictedsql-mcp/main.go`
has one stub line per dialect, each preceded by a comment naming the
replacement (`pgguard.New()` / `pgbackend.New(ctx, cfg.DSN, pol, logger)` and
`chguard.New()` / `chbackend.New(...)`). Write tools are registered whenever
`--dangerously-add-write-tools` is set; the registry is created only when the
backend implements `db.TxBackend`, otherwise the write tools return
"write transactions are not supported by this backend".

## What passes (stub guard/backend, `make e2e`)

- `TestCommonBootRejectsBadFlags` (13 cases, all exit 2 naming the flag)
- `TestCommonHelpExitsZero`
- `TestPostgresReadyzFalseWhenDBUnreachable` (503, reason contains `ping`, DSN not leaked)
- `TestPostgresToolListWithoutWriteFlag` (exactly the 5 read tools)
- `TestPostgresToolListWithWriteFlag` (5 read + 4 write tools)
- `TestClickHouseToolList`, `TestClickHouseWriteFlagRejectedAtBoot`
- `go test ./...` without `E2E=1` exits immediately; `make vet` (gofmt + go vet) is clean.

## Unrun / failing until A and B merge

- `TestPostgresHealthzReadyz`, `TestClickHouseHealthzReadyz`: the stub `Ping`
  always fails, so `/readyz` never reaches 200.
- `TestPostgresReadyzFalseWhenTableMissing`, `TestClickHouseReadyzFalseWhenTableMissing`:
  `/readyz` is 503 but the reason is "db ping failed: backend not implemented"
  instead of "missing tables: public.nope".
- Every tool call through the stubs returns `sql rejected: no guard for dialect`
  or `backend not implemented`; the dialect suites belong to A3 and B3.
- Tunnel runner: compiled and wired, not exercised end to end (no gateway
  credentials in this environment). State is derived from the agent's own log
  messages ("tunnel agent connected" → connected; "session ended" /
  "reconnecting" → connecting) because the agent exposes no state API.
- `deploy/k8s.yaml` was not applied to a cluster. `docker build -f deploy/Dockerfile`
  succeeds (116 MB image) and `docker run --rm restrictedsql-mcp:dev --help`
  prints the usage.

## Decisions and deviations from the plan

- **Postgres host port is 55433, not 55432.** 55432 on this machine is held by
  an unrelated container (`reflow-local-postgres`, up for days) which I did not
  stop. Compose, Makefile, harness (`pgDSN()`), and README all default to 55433
  and honour `E2E_PG_PORT` / `E2E_PG_DSN`. ClickHouse stays on 59000/58123.
  Streams A and B pick this up automatically through the harness; anyone
  running `psql` by hand must use 55433.
- `config.ParseFlags` takes a third `version` argument (needed for
  `TUNNEL_SERVICE_VERSION` fallback) and `Config` carries
  `TunnelGatewayURL`, `TunnelKey`, `TunnelServiceVersion` read from the
  environment. `health.New` takes a logger as a fourth argument.
- Tool errors are returned as plain Go errors from the typed handlers. In
  go-sdk v1.8.0 a non-`jsonrpc.Error` error from a `ToolHandlerFor` is packed
  into `CallToolResult{IsError:true}` (verified in `mcp/tool.go`), so the plan's
  note that Go errors become protocol errors does not apply to this version.
- Guard errors that are not `*sqlguard.RejectError` (parse failures, internal
  errors) are still reported to the agent as `sql rejected: <error>` so every
  rejection contains "rejected" and the server fails closed.
- Each tool call is bounded by `statement_timeout + 15s` at the server so a
  hung connection cannot pin a handler; backends still own the DB-side timeout.
- `execute_sql_readonly`/`explain_query` double-check `Checked.Tables` against
  `CanRead` and that `Kind == select`; `execute_sql_write` double-checks against
  `CanSelectInWrite`.
- With `--transport stdio`, logs go to stderr (stdout is the protocol) and
  `--tunnel` is ignored with a warning, since the agent proxies to the HTTP
  listener.
- `e2e.ServerOpts.AnyReadiness` was added so tool-list tests can boot without a
  live database; `ExpectReady` keeps the plan's semantics.
- Extra corpus: `bypassCorpusWritePostgres` (write-mode rejections with
  W={allowed_audit}) for stream A's write tests; `SELECT $1` (bind parameter)
  added to the Postgres bypass list; empty/whitespace input added to the common
  bypass list.
- `deploy/Dockerfile` has no `# syntax=` directive (it forced a registry pull
  that failed here); BuildKit cache mounts work without it on current Docker.

## Contract changes

None. `internal/policy/policy.go`, `internal/sqlguard/guard.go`,
`internal/db/backend.go`, and the function allowlists are untouched.

## Dependencies added

`github.com/modelcontextprotocol/go-sdk v1.8.0` and
`github.com/speakeasy-api/gram` (pseudo-version of 2026-09-14, for
`tunnel/agent`; it pulls `coder/websocket` and `hashicorp/yamux` transitively).
No others.

## Open issues

- GitHub over SSH and Docker Hub were intermittently unreachable during this
  session; pushes and the image build were retried until they went through.
  `origin/stream-c-server` holds every task commit.
- The corpus keeps the spec's `SELECT * FROM allowed_orders /* comment */ ; --`
  as a bypass entry; stream A's guard must reject the trailing `;` (e.g. via
  `stmt_len`/multiple-statement detection) or move it to the positive corpus
  with a spec amendment.
- `TestPostgresReadyzFalseWhenDBUnreachable` passes trivially with the stub;
  it becomes meaningful once `pgbackend` is wired.
- R3 review items (connection leaks in `Tx`, reaper races, `docker pause`
  behaviour, shutdown rolling back open transactions) are scheduled for phase 2.
