# Restricted SQL MCP Server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `restrictedsql-mcp`, a Go MCP server that exposes allowlisted-table SQL access to Postgres or ClickHouse through a fail-closed AST validator, with e2e tests against Docker databases.

**Architecture:** Raw SQL → dialect parser → fail-closed allowlist visitor → deparse to canonical SQL → backend executes under session-level protections. MCP tools (go-sdk, Streamable HTTP on loopback) sit on top; a Gram tunnel agent is the only ingress. Three independent streams: **A** Postgres guard+backend, **B** ClickHouse guard+backend, **C** server, transactions, health, tunnel, e2e harness, deploy. The shared contracts in `internal/policy`, `internal/sqlguard/guard.go`, `internal/db/backend.go` are already committed and are the only coupling between streams. Do not change them without noting it in your final report.

**Tech Stack:** Go 1.27, `github.com/modelcontextprotocol/go-sdk` v1.8.0, `github.com/pganalyze/pg_query_go/v6` v6.2.2 (cgo), `github.com/AfterShip/clickhouse-sql-parser` v0.5.6, `github.com/jackc/pgx/v5` v5.11.0, `github.com/ClickHouse/clickhouse-go/v2` v2.48.0, `github.com/speakeasy-api/gram/tunnel/agent`, Docker Compose.

**Spec:** `docs/superpowers/specs/2026-09-14-restricted-sql-mcp-design.md` — read it fully before starting; it is the authority on tool contracts and policy rules.

## Global Constraints

- Module path `github.com/ThomasRooney/gram-restrictedsql-tunnel-mcp`; `go 1.27.0` in go.mod.
- No unit tests. The only tests are e2e tests in `e2e/`, gated by `E2E=1`, driven through the real binary and the MCP client. Add `slog` debug logging wherever it helps diagnose a failing e2e test.
- Dependencies limited to the list in the Tech Stack. Standard library for everything else (`flag`, `log/slog`, `net/http`, `os/exec`).
- Every SQL statement sent to a database must be the canonical deparsed SQL from a `sqlguard.Checked`, never raw input (metadata queries written by us in the backend are the exception).
- Fail closed: unknown AST node, function, cast type, or table → `*sqlguard.RejectError`.
- `gofmt` clean, `go vet ./...` clean, no `TODO` left in code.
- Commit after every task with a conventional message; push your stream branch when the stream is complete.
- Stream branches: `stream-a-postgres`, `stream-b-clickhouse`, `stream-c-server`. Rebase onto `main` before pushing.

## File Structure

```
cmd/restrictedsql-mcp/main.go              (C) flags → config → boot
cmd/sqlguard-check/main.go                 (A creates, B extends) debug CLI: print canonical SQL or rejection
internal/config/config.go                  (C) Config, ParseFlags, Validate, BuildPolicy
internal/policy/*.go                       committed contracts + allowlists (A/B may extend lists)
internal/sqlguard/guard.go                 committed contract
internal/sqlguard/postgres/guard.go        (A) pg_query_go visitor + deparse
internal/sqlguard/postgres/nodes.go        (A) per-node handlers
internal/sqlguard/clickhouse/guard.go      (B) AfterShip visitor + deparse
internal/sqlguard/clickhouse/nodes.go      (B) per-node handlers
internal/db/backend.go                     committed contract
internal/db/postgres/backend.go            (A) pgx pool, Query, Explain, TablesExist, Ping
internal/db/postgres/catalog.go            (A) ListSchemas, ListObjects, ObjectDetails
internal/db/postgres/tx.go                 (A) Begin/Tx
internal/db/clickhouse/backend.go          (B) clickhouse-go conn, Query, Explain, TablesExist, Ping
internal/db/clickhouse/catalog.go          (B) system.* introspection
internal/txn/registry.go                   (C) transaction registry + reaper
internal/mcpserver/server.go               (C) NewServer, tool registration
internal/mcpserver/tools_read.go           (C) execute_sql_readonly, explain_query
internal/mcpserver/tools_meta.go           (C) list_schemas, list_objects, get_object_details
internal/mcpserver/tools_write.go          (C) begin/execute/commit/rollback
internal/health/health.go                  (C) /healthz /readyz
internal/tunnel/tunnel.go                  (C) gram agent wrapper
e2e/docker-compose.yml                     (C)
e2e/postgres/Dockerfile, e2e/postgres/init.sql   (C)
e2e/clickhouse/init.sql                    (C)
e2e/harness_test.go                        (C) TestMain, bootServer, call helpers
e2e/smoke_test.go                          (C) boot, tools/list, health
e2e/corpus_test.go                         (C) shared bypass + positive corpus tables (data only)
e2e/postgres_read_test.go … postgres_write_test.go (A)
e2e/clickhouse_read_test.go … (B)
deploy/Dockerfile, deploy/k8s.yaml         (C)
Makefile                                   (C)
README.md                                  (C)
```

---

# Stream C — server, harness, deploy (do first: A and B run their tests through this)

### Task C1: Config and flag parsing

**Files:**
- Create: `internal/config/config.go`
- Create: `cmd/restrictedsql-mcp/main.go` (flag parsing only for now; exits 2 on invalid)

**Interfaces:**
- Produces:
```go
package config
type Config struct {
    Dialect          policy.Dialect
    DSN              string
    ReadTables       []string
    WriteTables      []string
    WritesEnabled    bool
    DefaultSchema    string
    Transport        string // "http" | "stdio"
    Listen           string // "127.0.0.1:8080"
    MaxRows          int
    StatementTimeout time.Duration
    TxnIdleTimeout   time.Duration
    MaxOpenTxns      int
    Tunnel           bool
    LogLevel         string
    Version          string
}
func ParseFlags(args []string, getenv func(string) string) (*Config, error) // uses flag.NewFlagSet; DSN falls back to DATABASE_URL
func (c *Config) BuildPolicy() (*policy.Policy, error)                     // parses table names via policy.ParseTableRef
```
- `ParseFlags` errors (returned, printed by main, exit 2): unknown dialect; empty DSN; no `--read-tables`; unparsable table; `--dangerously-add-write-tools` with dialect clickhouse (`"write tools are not supported on clickhouse"`); `--dangerously-add-write-tools` without `--write-tables`; `--tunnel` without `TUNNEL_GATEWAY_URL` or `TUNNEL_KEY`; transport not http|stdio.
- Default schema: postgres → `public`; clickhouse → database path of the DSN if present, else `default`. Parse the DSN with `net/url` to extract the path.

- [ ] **Step 1: Write `internal/config/config.go`** with the struct, flag definitions matching spec §3 verbatim, and `Validate`. Flag names: `--dialect --dsn --read-tables --write-tables --dangerously-add-write-tools --default-schema --transport --listen --max-rows --statement-timeout --txn-idle-timeout --max-open-txns --tunnel --log-level`.
- [ ] **Step 2: Write `cmd/restrictedsql-mcp/main.go`** that calls `ParseFlags(os.Args[1:], os.Getenv)`, prints the error to stderr and exits 2 on failure, then (for now) prints the resolved policy at info level and exits 0. Set `Version` from a `var version = "dev"` overridable with `-ldflags -X main.version=...`.
- [ ] **Step 3: Verify**: `go run ./cmd/restrictedsql-mcp --dialect clickhouse --dsn x --read-tables a --dangerously-add-write-tools; echo $?` → prints the error, exit 2. `go run ./cmd/restrictedsql-mcp --dialect postgres --dsn postgres://x --read-tables public.a,b` → exit 0.
- [ ] **Step 4: Commit** `feat(config): flag parsing and policy construction`.

### Task C2: e2e infrastructure (compose, seed, harness)

**Files:**
- Create: `e2e/docker-compose.yml`, `e2e/postgres/Dockerfile`, `e2e/postgres/init.sql`, `e2e/clickhouse/init.sql`
- Create: `e2e/harness_test.go`, `e2e/corpus_test.go`
- Create: `Makefile`

**Interfaces:**
- Produces (package `e2e`, all in `_test.go` files):
```go
type ServerOpts struct {
    Dialect      string   // "postgres" | "clickhouse"
    DSN          string   // default from pgDSN()/chDSN() by dialect
    ReadTables   []string // default: []string{"allowed_orders","allowed_customers"}
    WriteTables  []string
    Writes       bool     // adds --dangerously-add-write-tools
    ExtraArgs    []string
    ExpectReady  *bool    // nil → wait for 200 on /readyz; false → wait for 503
}
type Server struct {
    URL     string             // http://127.0.0.1:<port>
    Session *mcp.ClientSession // connected go-sdk client
    Logs    *bytes.Buffer      // subprocess stdout+stderr (JSON logs, --log-level debug)
}
func bootServer(t *testing.T, o ServerOpts) *Server          // registers t.Cleanup to kill and print Logs on failure
func bootServerExpectExit(t *testing.T, args []string) (exitCode int, stderr string) // for bad-flag tests
func (s *Server) call(t *testing.T, tool string, args map[string]any) (out map[string]any, errText string)
    // errText non-empty iff result.IsError; out is the parsed StructuredContent (or first text content as JSON)
func (s *Server) mustCall(t *testing.T, tool string, args map[string]any) map[string]any // fails test on errText
func (s *Server) mustReject(t *testing.T, tool string, args map[string]any, contains string) // fails unless errText contains substring
func (s *Server) toolNames(t *testing.T) []string
func pgDSN() string   // env E2E_PG_DSN else "postgres://postgres:postgres@127.0.0.1:55432/app?sslmode=disable"
func chDSN() string   // env E2E_CH_DSN else "clickhouse://default:@127.0.0.1:59000/app"
func httpGet(t *testing.T, url string) (status int, body string)
// corpus_test.go
var bypassCorpusCommon []string     // spec §6 entries valid in both dialects
var bypassCorpusPostgres []string   // pg-only entries
var bypassCorpusClickHouse []string // ch-only entries
var positiveCorpusCommon []string   // must be accepted by both in read mode
```
- `TestMain`: if `os.Getenv("E2E") != "1"` → `os.Exit(0)` after printing "E2E=1 not set; skipping". Otherwise `go build -o <tmp>/restrictedsql-mcp ../cmd/restrictedsql-mcp` once; store path in a package var.
- `bootServer`: pick a free port with `net.Listen("tcp","127.0.0.1:0")`, close it, start the binary with `--transport http --listen 127.0.0.1:<port> --log-level debug` plus opts; poll `/readyz` every 100ms up to 30s for the expected status; connect `mcp.NewClient(&mcp.Implementation{Name:"e2e",Version:"0"}, nil).Connect(ctx, &mcp.StreamableClientTransport{Endpoint: URL+"/mcp"}, nil)`.
- Compose: service `postgres` built from `e2e/postgres/Dockerfile` (`FROM postgres:17`, `RUN apt-get update && apt-get install -y --no-install-recommends postgresql-17-hypopg && rm -rf /var/lib/apt/lists/*`), env `POSTGRES_PASSWORD=postgres POSTGRES_DB=app`, port `55432:5432`, healthcheck `pg_isready -U postgres`; service `clickhouse` image `clickhouse/clickhouse-server:25.8`, env `CLICKHOUSE_DB=app CLICKHOUSE_USER=default CLICKHOUSE_PASSWORD= CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1`, ports `59000:9000` and `58123:8123`, healthcheck `wget -qO- http://localhost:8123/ping`, ulimits nofile 262144. Mount init SQL into `/docker-entrypoint-initdb.d/`.
- Seed (both DBs, database `app`):
  - `allowed_orders(id, customer_id, amount, status, created_at)` 5 rows
  - `allowed_customers(id, name, email)` 3 rows
  - `allowed_audit(id, note, created_at)` empty (Postgres: `id serial primary key`, `created_at timestamptz default now()`)
  - `forbidden_secrets(id, secret)` 1 row
  - Postgres also: `CREATE EXTENSION IF NOT EXISTS hypopg;`, an index `allowed_orders_customer_idx ON allowed_orders(customer_id)`, a foreign key `allowed_orders.customer_id → allowed_customers.id`, `COMMENT ON TABLE allowed_orders IS 'Orders'`, a view `allowed_orders_v AS SELECT id, amount FROM allowed_orders`, a sequence `allowed_seq`.
  - ClickHouse: `ENGINE = MergeTree ORDER BY id` for each; a view `allowed_orders_v`.
- Makefile targets: `build`, `vet`, `e2e-up` (`docker compose -f e2e/docker-compose.yml up -d --build --wait`), `e2e-down`, `e2e` (`e2e-up` then `E2E=1 go test ./e2e/... -count=1 -v -timeout 20m`), `e2e-pg` and `e2e-ch` (same with `-run 'Postgres|Common'` / `-run 'ClickHouse|Common'`).

- [ ] **Step 1: Write compose, Dockerfile, seed SQL.** Bring it up: `make e2e-up`. Verify `psql "$(pgDSN)" -c '\dt'` shows the 4 tables and `SELECT * FROM pg_extension WHERE extname='hypopg'` returns a row; `curl 'http://127.0.0.1:58123/?query=SHOW%20TABLES%20FROM%20app'` lists the tables.
- [ ] **Step 2: Write `e2e/harness_test.go` and `e2e/corpus_test.go`** (corpus copied from spec §6, split by dialect validity; positive corpus: at least 12 statements — joins between allowed tables, CTE, aggregate with GROUP BY/HAVING, window function, ORDER BY/LIMIT/OFFSET, subquery in WHERE over allowed table, UNION of two allowed selects, CASE, COALESCE, cast to int/text, `count(*)`).
- [ ] **Step 3: Write `e2e/smoke_test.go`**: `TestCommonBootRejectsBadFlags` (each bad-flag case from C1 exits 2 with a message mentioning the flag), `TestPostgresHealthzReadyz` (boot → `/healthz` 200; `/readyz` 200 JSON `ready:true`), `TestPostgresReadyzFalseWhenTableMissing` (`ReadTables: []string{"nope"}`, `ExpectReady: false` → 503 body contains `nope`), `TestPostgresToolListWithoutWriteFlag` (tool names are exactly the 5 read tools), `TestPostgresToolListWithWriteFlag` (5 + 4 write tools), same two tool-list tests for ClickHouse (`Writes:true` on ClickHouse is a boot failure covered by the bad-flag test).
- [ ] **Step 4: Run `make e2e`** — these tests will fail until C3–C6 exist; that is expected. Keep them; they are the acceptance tests for the stream.
- [ ] **Step 5: Commit** `test(e2e): compose stack, seed data, harness, smoke tests`.

### Task C3: Transaction registry

**Files:**
- Create: `internal/txn/registry.go`

**Interfaces:**
- Produces:
```go
package txn
type Registry struct{ /* mu, entries map[string]*entry, backend db.TxBackend, idle time.Duration, max int, logger */ }
func New(backend db.TxBackend, idle time.Duration, max int, logger *slog.Logger) *Registry
func (r *Registry) Begin(ctx context.Context) (id string, expiresAt time.Time, err error) // ErrTooMany when len(entries) >= max
func (r *Registry) Exec(ctx context.Context, id, canonicalSQL string, maxRows int) (*db.Result, error) // touches lastUsed; ErrUnknown for bad id
func (r *Registry) Commit(ctx context.Context, id string) error
func (r *Registry) Rollback(ctx context.Context, id string) error
func (r *Registry) RunReaper(ctx context.Context) // every idle/4 (min 1s): rollback + delete entries idle > idle; log each
func (r *Registry) Close()                       // rollback everything
var ErrUnknown = errors.New("unknown or expired transaction_id")
var ErrTooMany = errors.New("too many open transactions")
```
- IDs: 16 random bytes from `crypto/rand`, hex. Each entry has its own mutex so two calls on the same id serialize and calls on different ids do not block each other. `expiresAt = lastUsed + idle`, extended on every Exec.

- [ ] **Step 1: Implement** as specified, logging `txn.begin`, `txn.exec`, `txn.commit`, `txn.rollback`, `txn.reaped` at debug with `transaction_id`.
- [ ] **Step 2: `go vet ./...`**, commit `feat(txn): transaction registry with idle reaper`.

### Task C4: MCP server and tools

**Files:**
- Create: `internal/mcpserver/server.go`, `tools_read.go`, `tools_meta.go`, `tools_write.go`

**Interfaces:**
- Consumes: `sqlguard.Guard`, `db.Backend`, `db.TxBackend` (type-asserted from Backend), `txn.Registry`, `policy.Policy`.
- Produces:
```go
package mcpserver
type Deps struct {
    Policy   *policy.Policy
    Guard    sqlguard.Guard
    Backend  db.Backend
    Txns     *txn.Registry // nil unless writes enabled
    Logger   *slog.Logger
    Version  string
}
func New(d Deps) *mcp.Server // registers tools; write tools only when d.Policy.WritesEnabled
```
- Tool registration with go-sdk v1.8.0: `mcp.NewServer(&mcp.Implementation{Name: "restrictedsql-mcp", Version: d.Version}, nil)` then `mcp.AddTool(server, &mcp.Tool{Name: ..., Description: ...}, handler)` where handler is `func(ctx context.Context, req *mcp.CallToolRequest, in InputStruct) (*mcp.CallToolResult, OutputStruct, error)`. Input/output structs carry `json:"..."` tags and `jsonschema:"..."` descriptions; the SDK derives schemas. Return rejections as `&mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, Out{}, nil` — never as a Go error (a Go error becomes a protocol error, not a tool error). Check the exact signatures in `$(go env GOMODCACHE)/github.com/modelcontextprotocol/go-sdk@v1.8.0/mcp/` before writing.
- Tool descriptions (reworded from the spec, agent-facing):
  - `execute_sql_readonly`: "Run a single read-only SQL statement (SELECT, WITH, UNION, joins, aggregates, window functions) against the allowlisted tables and return rows. Only tables in the read allowlist may appear anywhere in the query, including subqueries and CTEs. Only a fixed set of builtin functions is permitted. Rows are capped by max_rows."
  - `list_schemas`: "List the schemas (Postgres) or databases (ClickHouse) present in the connected instance."
  - `list_objects`: "List the tables, views, sequences, or extensions inside one schema, with row estimates and sizes where the database exposes them."
  - `get_object_details`: "Describe one table or view: columns with types and defaults, constraints, indexes, storage size, row estimate, and engine details on ClickHouse."
  - `explain_query`: "Return the query planner's execution plan for a read-only statement without running it (set analyze=true to execute it and include actual timings). On Postgres you can pass hypothetical_indexes to see how the plan would change if those indexes existed; this needs the hypopg extension and cannot be combined with analyze."
  - `begin_transaction`: "Open a write transaction on a dedicated connection and return its transaction_id. Every write must run inside a transaction so you can check rows_affected and re-select the changed rows before committing. Idle transactions are rolled back automatically after the configured timeout."
  - `execute_sql_write`: "Run one INSERT, UPDATE, DELETE (RETURNING allowed) or SELECT inside an open transaction. Mutations may only target tables in the write allowlist; SELECTs and source tables may use the read and write allowlists. Errors abort the transaction; roll it back and start again."
  - `commit_transaction`: "Commit an open transaction and release its connection."
  - `rollback_transaction`: "Roll back an open transaction and release its connection."
- Input/output structs exactly per spec §4. `duration_ms` is an int64 from `Result.Duration.Milliseconds()`.
- Row cap: `maxRows = min(in.MaxRows if > 0, policy.MaxRows)`.
- `explain_query`: guard in `ModeRead`; if `len(HypotheticalIndexes) > 0 && Analyze` → reject "analyze and hypothetical_indexes are mutually exclusive"; each hypothetical index table is resolved with `policy.ParseTableRef(schema+"."+table or table, DefaultSchema, dialect)` and must satisfy `Policy.CanRead`; on ClickHouse any hypothetical index → error "hypothetical indexes are not supported on clickhouse". Output `{"dialect","plan"}` where `plan` is the raw JSON when `planJSON != nil`, else the text string.
- Write tools: guard in `ModeWrite`; for `KindSelect` any tables must pass `CanSelectInWrite`; for mutations the guard already enforced targets ∈ W (stream A implements that inside the guard; the server double-checks `Checked.Tables` against `CanSelectInWrite` as belt and braces).
- Log at debug for every call: tool, raw sql (truncated to 2000 chars), canonical sql, tables, duration, rows, error.

- [ ] **Step 1: Write `server.go`** with `New`, shared helpers `toolError(err) *mcp.CallToolResult`, `capRows`, and registration order: read, meta, explain, then write if enabled.
- [ ] **Step 2: Write `tools_read.go`, `tools_meta.go`, `tools_write.go`.**
- [ ] **Step 3: Temporary wiring check**: until streams A/B land, write `internal/sqlguard/stub/stub.go` (`Check` returns `sqlguard.Reject("no guard for dialect", string(pol.Dialect))`) and `internal/db/stub/stub.go` (every method returns `errors.New("backend not implemented")`, `Ping` returns an error so `/readyz` is 503). Main selects real implementations when they exist; for now both dialects map to the stubs. Delete both stub packages in Task C7 once A and B are merged.
- [ ] **Step 4: `go vet ./...`**, commit `feat(mcp): server and tool handlers`.

### Task C5: Health, tunnel, boot wiring

**Files:**
- Create: `internal/health/health.go`, `internal/tunnel/tunnel.go`
- Modify: `cmd/restrictedsql-mcp/main.go`

**Interfaces:**
- Produces:
```go
package health
type Checker struct{ /* backend db.Backend, tables []policy.TableRef, tunnelState func() string, timeout time.Duration */ }
func New(b db.Backend, tables []policy.TableRef, tunnelState func() string) *Checker
func (c *Checker) Healthz(w http.ResponseWriter, r *http.Request) // 200 {"status":"ok"}
func (c *Checker) Readyz(w http.ResponseWriter, r *http.Request)  // 200 {"ready":true,"tunnel":...} or 503 {"ready":false,"reason":"...","tunnel":...}; 3s timeout; reason examples: "db ping failed: ...", "missing tables: public.nope"
package tunnel
type Runner struct{ /* agent *agent.Agent, state atomic.Value */ }
func New(cfg Config, logger *slog.Logger) (*Runner, error) // Config{GatewayURL, APIKey, LocalMCPURL, ServiceVersion string; Metadata map[string]string}
func (r *Runner) Run(ctx context.Context) error             // wraps agent.Run; sets state "running" then "stopped"
func (r *Runner) State() string                             // "disabled" when nil receiver
```
- main boot order: parse flags → logger (JSON, level from flag) → policy → backend by dialect (postgres: `pgbackend.New(ctx, dsn, policy)`; clickhouse: `chbackend.New(ctx, dsn, policy)`; both constructors must not fail on an unreachable DB — they configure a pool/conn lazily and log a warning) → guard by dialect → registry if writes → `mcpserver.New` → HTTP mux: `/mcp` = `mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)`, `/healthz`, `/readyz` → listen; or `server.Run(ctx, &mcp.StdioTransport{})` when `--transport stdio` (health endpoints then unavailable; log that) → tunnel runner goroutine if `--tunnel` (`LocalMCPURL = "http://" + listen + "/mcp"`, metadata `{"dialect": ..., "read_tables": "...", "write_tools": "true|false"}`) → reaper goroutine → signal handling (SIGINT/SIGTERM → shutdown HTTP with 10s grace, `Registry.Close()`, `Backend.Close()`).
- Log at info on boot: version, dialect, listen, read tables, write tables, writes enabled, tunnel enabled. Never log the DSN.

- [ ] **Step 1: Implement health and tunnel packages.**
- [ ] **Step 2: Finish `main.go` wiring** as above.
- [ ] **Step 3: Run `make e2e`** — with stubs, `TestCommonBootRejectsBadFlags` and `TestPostgresReadyzFalseWhenTableMissing`-style 503 checks pass; tool-list tests pass (tools are registered regardless of backend); `TestPostgresHealthzReadyz` fails until stream A merges. Record which pass in the commit message.
- [ ] **Step 4: Commit** `feat: boot wiring, health endpoints, tunnel runner`.

### Task C6: Dockerfile, k8s manifest, README

**Files:**
- Create: `deploy/Dockerfile`, `deploy/k8s.yaml`, `README.md`

- [ ] **Step 1: `deploy/Dockerfile`**: stage 1 `golang:1.27-bookworm`, `apt-get install -y gcc libc6-dev`, `CGO_ENABLED=1 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/restrictedsql-mcp ./cmd/restrictedsql-mcp`; stage 2 `debian:bookworm-slim` with `ca-certificates`, non-root `USER 65532:65532`, `COPY --from=build /out/restrictedsql-mcp /restrictedsql-mcp`, `ENTRYPOINT ["/restrictedsql-mcp"]`. Verify `docker build -f deploy/Dockerfile -t restrictedsql-mcp:dev .` succeeds and `docker run --rm restrictedsql-mcp:dev --help` prints usage.
- [ ] **Step 2: `deploy/k8s.yaml`**: Deployment (1 replica, `args` with `--dialect`, `--read-tables`, `--listen 127.0.0.1:8080`, `--tunnel`; env `DATABASE_URL`, `TUNNEL_GATEWAY_URL`, `TUNNEL_KEY` from a Secret `restrictedsql-mcp`; `livenessProbe` GET `/healthz`, `readinessProbe` and `startupProbe` GET `/readyz` on `containerPort 8080`; `securityContext` runAsNonRoot, readOnlyRootFilesystem; resources requests/limits), no Service, no Ingress. Note in a comment that probes must target the loopback listener via `httpGet` on the pod's own port; if kubelet cannot reach 127.0.0.1 in your CNI, set `--listen 0.0.0.0:8080` and rely on NetworkPolicy to deny ingress.
- [ ] **Step 3: README.md**: purpose, security model (parse → allowlist → deparse; session protections; recommend a restricted DB role as a second layer), all flags, tool reference (copy from spec §4), transaction workflow example, e2e instructions (`make e2e`), deployment notes, ClickHouse limitations (no writes, no hypothetical indexes).
- [ ] **Step 4: Commit** `docs: README, Dockerfile, k8s manifest`; push `stream-c-server`.

### Task C7 (primary, after A and B merge): integration

- [ ] Delete `internal/sqlguard/stub` and `internal/db/stub`; wire real guards/backends in main.
- [ ] `make e2e` green for all suites. Fix integration issues. Commit `chore: wire real backends, remove stubs`.

---

# Stream A — Postgres guard and backend

### Task A1: Postgres guard

**Files:**
- Create: `internal/sqlguard/postgres/guard.go`, `internal/sqlguard/postgres/nodes.go`
- Create: `cmd/sqlguard-check/main.go`

**Interfaces:**
- Produces:
```go
package pgguard // directory internal/sqlguard/postgres
func New() sqlguard.Guard
```
- Parsing: `pg_query.Parse(raw)` → `*pg_query.ParseResult`. Reject if `len(Stmts) != 1`. The statement is `Stmts[0].Stmt` (`*pg_query.Node`). After validation and rewriting, deparse with `pg_query.Deparse(result)`.
- Visitor design: one function `walk(n *pg_query.Node, ctx *visitCtx) error` with a type switch over `n.Node` concrete oneof wrappers (`*pg_query.Node_SelectStmt`, `*pg_query.Node_RangeVar`, …). The `default:` case returns `sqlguard.Reject("unsupported syntax", fmt.Sprintf("%T", n.Node))`. Every allowed case explicitly walks every child field of that struct (list the fields; do not use reflection). `visitCtx` carries the mode, policy, a stack of CTE name scopes, the set of referenced tables, and the current relation role (`roleSource`, `roleMutationTarget`).
- Allowed nodes and the rules for each:
  - `SelectStmt`: reject if `IntoClause != nil` (SELECT INTO), `len(LockingClause) > 0` (FOR UPDATE/SHARE). Walk `WithClause`, `DistinctClause`, `TargetList`, `FromClause`, `WhereClause`, `GroupClause`, `HavingClause`, `WindowClause`, `ValuesLists`, `SortClause`, `LimitOffset`, `LimitCount`, `Larg`, `Rarg` (set operations).
  - `WithClause` / `CommonTableExpr`: push the CTE name into scope before walking sibling CTEs when `Recursive`, else after. The CTE query (`Ctequery`) in read mode must be a `SelectStmt`; in write mode it may also be Insert/Update/Delete (mutation rules apply).
  - `RangeVar`: reject `Catalogname != ""`. Resolve `schemaname` (empty → `pol.DefaultSchema`) and `relname` to a `policy.TableRef`. If the name is unqualified and matches a CTE in scope, allow and do not qualify. Otherwise apply the role check: source in read mode → `CanRead`; source in write mode → `CanSelectInWrite`; mutation target → `CanMutate`. On success set `rv.Schemaname = ref.Schema` (this is what fully qualifies the deparsed SQL) and record the table. Reject `pg_catalog.*`/`information_schema.*` unless allowlisted (falls out of the allowlist check).
  - `RangeSubselect`, `JoinExpr` (walk `Larg`, `Rarg`, `Quals`, `UsingClause`), `Alias`, `ResTarget`, `ColumnRef`, `A_Star`, `A_Const`, `A_Expr` (reject if `len(Name) != 1`, i.e. `OPERATOR(schema.op)`), `BoolExpr`, `NullTest`, `BooleanTest`, `CaseExpr`, `CaseWhen`, `CoalesceExpr`, `MinMaxExpr`, `SubLink` (walk `Subselect` and `Testexpr`), `A_ArrayExpr`, `A_Indirection`, `A_Indices`, `RowExpr`, `SortBy`, `WindowDef`, `GroupingSet`, `NamedArgExpr`, `SQLValueFunction`, `List`, `String`, `Integer`, `Float`, `Boolean`, `Null`, `BitString`.
  - `FuncCall`: `Funcname` must be `[name]` or `["pg_catalog", name]`; `policy.AllowedFunction(policy.Postgres, name)` must hold; walk `Args`, `AggOrder`, `AggFilter`, `Over`. Reject `FuncVariadic`? No — allow. Reject `AggWithinGroup`? Allow (percentile_cont uses it).
  - `TypeCast` / `TypeName`: the type name list is `[name]` or `["pg_catalog", name]`; look up `policy.AllowedCastType(policy.Postgres, name)`. The parser emits internal names for builtins (`int4`, `int8`, `float8`, `bpchar`, `varchar`, `bool`, `numeric`, `timestamptz`, `interval`, `time`, `timetz`, `date`) — add those to `postgresCastTypes` in `internal/policy/functions_postgres.go` if missing. Reject `ArrayBounds` deeper than one level? Allow arrays (`int[]`): `ArrayBounds` is fine.
  - Write mode only: `InsertStmt` (walk `Relation` as mutation target, `Cols`, `SelectStmt` as source, `OnConflictClause` (its `Action` may be nothing/update; walk `TargetList`, `WhereClause`, `Infer`), `ReturningList`, `WithClause`), `UpdateStmt` (`Relation` target, `TargetList`, `WhereClause`, `FromClause` sources, `ReturningList`, `WithClause`), `DeleteStmt` (`Relation` target, `UsingClause` sources, `WhereClause`, `ReturningList`, `WithClause`), `InferClause`, `OnConflictClause`, `MultiAssignRef`, `SetToDefault`.
  - Explicitly rejected even though the parser accepts them: `ParamRef` ("bind parameters are not supported"), `RangeFunction` ("table functions are not allowed"), `RangeTableSample`, `RangeTableFunc`, `XmlExpr`, `XmlSerialize`, `CollateClause`, `LockingClause`, `IntoClause`, `MergeStmt`, `ExplainStmt`, every DDL/utility statement, `CopyStmt`, `VariableSetStmt`, `VariableShowStmt`, `TransactionStmt`, `JsonTable`, `JsonObjectConstructor` and friends (allow later if needed).
- `StmtKind` from the top node. In `ModeRead` only `SelectStmt` is allowed at the top and inside CTEs.
- `cmd/sqlguard-check/main.go`: flags `--dialect --default-schema --read-tables --write-tables --mode read|write`, positional SQL; prints `OK <kind> tables=[...]` and the canonical SQL, or `REJECTED: <error>`; exit 1 on rejection. Stream B adds the clickhouse case.

- [ ] **Step 1: Read the pg_query_go API** in `$(go env GOMODCACHE)/github.com/pganalyze/pg_query_go/v6@v6.2.2/pg_query.pb.go` for the exact field names of the nodes above. `go get github.com/pganalyze/pg_query_go/v6@v6.2.2` first (cgo build takes a few minutes the first time; that is expected).
- [ ] **Step 2: Implement guard.go and nodes.go.**
- [ ] **Step 3: Implement `cmd/sqlguard-check`** and use it to check every entry of the bypass corpus (spec §6, common + postgres) is rejected and every positive corpus entry is accepted with fully qualified output, e.g. `go run ./cmd/sqlguard-check --dialect postgres --read-tables allowed_orders,allowed_customers "SELECT count(*) FROM allowed_orders o JOIN allowed_customers c ON c.id=o.customer_id"` → `OK select tables=[public.allowed_customers public.allowed_orders]` and `SELECT count(*) FROM public.allowed_orders o JOIN public.allowed_customers c ON c.id = o.customer_id`.
- [ ] **Step 4: Commit** `feat(pgguard): postgres AST guard with deparse`.

### Task A2: Postgres backend

**Files:**
- Create: `internal/db/postgres/backend.go`, `catalog.go`, `tx.go`

**Interfaces:**
- Produces:
```go
package pgbackend // directory internal/db/postgres
func New(ctx context.Context, dsn string, pol *policy.Policy, logger *slog.Logger) (*Backend, error) // pgxpool with lazy connect; never fails on unreachable DB
// *Backend implements db.Backend and db.TxBackend
```
- `Query`: acquire conn; `BEGIN READ ONLY`; `SET LOCAL statement_timeout = <ms>`; `SET LOCAL search_path = <quoted default schema>`; run the SQL with `conn.Query`; collect up to `maxRows+1` rows (`Truncated = len > maxRows`, then trim); `ROLLBACK`; release. Column types from `FieldDescriptions()` via `conn.TypeMap().TypeForOID(oid).Name` (fallback `oid:<n>`). Convert values with `pgx` default decoding to `any`; `[16]byte` UUIDs → string, `pgtype.Numeric` → string, times → RFC3339.
- `Explain`: same read-only session; when hypothetical indexes are given: for each, `sqlguard.BuildIndexDDL(h)` then `SELECT * FROM hypopg_create_hypothetical_index($1)`; if that errors with `function hypopg_create_hypothetical_index(unknown) does not exist` return `errors.New("hypopg extension is not installed")`. Then `EXPLAIN (FORMAT JSON, VERBOSE, COSTS[, ANALYZE, BUFFERS]) <sql>`; the single row/column is the JSON plan; `SELECT hypopg_reset()` in a `defer` when hypopg was used; then ROLLBACK.
- `TablesExist`: one query `SELECT n.nspname, c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind IN ('r','v','m','p','f') AND (n.nspname, c.relname) IN (...)` and diff.
- `catalog.go`:
  - `ListSchemas`: `pg_namespace` joined to `pg_roles` for owner and `obj_description(oid,'pg_namespace')`; exclude `pg_toast` and `pg_temp_%`.
  - `ListObjects(schema, type)`: table → `relkind IN ('r','p')` with `pg_stat_user_tables.n_live_tup`-style estimate from `pg_class.reltuples` and `pg_total_relation_size`; view → `relkind IN ('v','m')` (type `view` / `materialized_view`); sequence → `relkind = 'S'`; extension → `pg_extension` joined to `pg_namespace` on `extnamespace`; empty type → all of the above.
  - `ObjectDetails`: columns from `pg_attribute`/`pg_attrdef`/`col_description`; constraints from `pg_constraint` with `pg_get_constraintdef`; indexes from `pg_indexes` plus `pg_relation_size(indexrelid)`; size `pg_total_relation_size`; `reltuples`; `obj_description`. Return `sql.ErrNoRows`-style `errors.New("object not found: schema.name")` when missing.
- `tx.go`: `Begin` acquires a dedicated `*pgxpool.Conn`, `BEGIN`, `SET LOCAL statement_timeout`, `SET LOCAL search_path`; `Exec` uses `conn.Query` for everything and reads `CommandTag().RowsAffected()` after draining rows; `Commit`/`Rollback` release the conn (always release even on error).

- [ ] **Step 1: Implement backend.go, catalog.go, tx.go.**
- [ ] **Step 2: Commit** `feat(pgbackend): pgx backend, catalog introspection, transactions`.

### Task A3: Postgres e2e tests

**Files:**
- Create: `e2e/postgres_read_test.go`, `e2e/postgres_meta_test.go`, `e2e/postgres_explain_test.go`, `e2e/postgres_write_test.go`
- Modify: `cmd/restrictedsql-mcp/main.go` (wire `pgguard.New()` and `pgbackend.New` for dialect postgres — coordinate: if stream C's stub wiring is present, replace the postgres branch only)

- [ ] **Step 1: `postgres_read_test.go`**: `TestPostgresReadBasic` (`SELECT id, amount FROM allowed_orders ORDER BY id` → 5 rows, columns `id`/`amount`, `truncated:false`); `TestPostgresReadTruncation` (`max_rows: 2` → 2 rows, `truncated:true`); `TestPostgresReadJoinAndAggregate`; `TestPostgresReadPositiveCorpus` (each of `positiveCorpusCommon` succeeds); `TestPostgresBypassCorpus` (each of `bypassCorpusCommon + bypassCorpusPostgres` is rejected; error text contains `rejected`); `TestPostgresReadRejectsWriteVerbs`; `TestPostgresReadStatementTimeout` (boot with `--statement-timeout 500ms`, `SELECT count(*) FROM allowed_orders a, allowed_orders b, allowed_orders c, allowed_orders d, allowed_orders e, allowed_orders f, allowed_orders g` cross join large enough — if it completes too fast, use a recursive CTE counting to 10 million — expect an error mentioning `canceling statement`); `TestPostgresReadOnlyWhenTableNotReadable` (boot with `ReadTables: ["allowed_customers"]`, query `allowed_orders` → rejected naming `public.allowed_orders`).
- [ ] **Step 2: `postgres_meta_test.go`**: `list_schemas` contains `public`; `list_objects public table` contains all four tables (including `forbidden_secrets` — full catalog visibility is intended) with a positive `size_bytes`; `list_objects public view` contains `allowed_orders_v`; `sequence` contains `allowed_seq`; `extension` contains `hypopg`; `get_object_details public allowed_orders` has the 5 columns, a `primary_key` and a `foreign_key` constraint, the `allowed_orders_customer_idx` index, description `Orders`; unknown object → error `not found`.
- [ ] **Step 3: `postgres_explain_test.go`**: plain explain returns `plan` as a JSON array whose first element has `Plan`; `analyze:true` plan includes `Actual Rows`; `hypothetical_indexes:[{table:"allowed_orders",columns:["status"]}]` with `WHERE status = 'paid'` returns a plan containing `<` (hypopg index names look like `<12345>btree_allowed_orders_status`); analyze + hypothetical → rejected `mutually exclusive`; hypothetical index on `forbidden_secrets` → rejected; explain of a bypass-corpus statement → rejected.
- [ ] **Step 4: `postgres_write_test.go`** (boot with `WriteTables: ["allowed_audit"]`, `Writes: true`): begin → `INSERT INTO allowed_audit (note) VALUES ('x') RETURNING id` → `rows_affected 1`, one row → `SELECT count(*) FROM allowed_audit` inside the txn shows 1 → rollback → `execute_sql_readonly`-style select via a second boot with `ReadTables: ["allowed_audit"]` shows 0 (or simply select in a new txn); begin → insert → commit → visible; `UPDATE allowed_orders ...` in the txn → rejected (not in write set); `INSERT INTO allowed_audit SELECT ... FROM forbidden_secrets` → rejected; `SELECT * FROM allowed_orders` inside the txn → allowed (read set); unknown `transaction_id` → error `unknown or expired`; boot with `--max-open-txns 1` → second begin errors `too many`; boot with `--txn-idle-timeout 2s` → begin, sleep 3s, exec → error `unknown or expired`; an error inside the txn (insert violating NOT NULL, e.g. `INSERT INTO allowed_audit (id, note) VALUES (NULL, 'x')`) leaves subsequent exec failing with `current transaction is aborted` until rollback; write tools absent from `toolNames` when `Writes:false`.
- [ ] **Step 5: Run `make e2e-pg`** until green. Commit `test(e2e): postgres suites`; push `stream-a-postgres`.

---

# Stream B — ClickHouse guard and backend

### Task B1: ClickHouse guard

**Files:**
- Create: `internal/sqlguard/clickhouse/guard.go`, `internal/sqlguard/clickhouse/nodes.go`
- Modify: `cmd/sqlguard-check/main.go` (add the clickhouse dialect; create the file with the same flags if stream A has not landed yet — whichever lands second merges)

**Interfaces:**
- Produces:
```go
package chguard // directory internal/sqlguard/clickhouse
func New() sqlguard.Guard
```
- Parsing: `parser.NewParser(raw).ParseStmts()` → `[]parser.Expr`; reject unless exactly one. Deparse with the node's `String()` after rewriting table identifiers to `database.table`.
- Visitor: a type switch over the concrete AST types in `github.com/AfterShip/clickhouse-sql-parser/parser` (read `parser/ast.go` for the full list). `default:` → `sqlguard.Reject("unsupported syntax", fmt.Sprintf("%T", node))`. Walk every child field explicitly.
- Rules:
  - Top level: `*parser.SelectQuery` only (ModeWrite is never used on ClickHouse; return a rejection "write mode is not supported on clickhouse" if asked).
  - `SelectQuery`: reject when `Settings != nil`, `Format != nil`, `IntoOutfile` (check the exact field names) is set; walk `With`, `Top`, `SelectItems`, `From`, `ArrayJoin`, `Window`, `Prewhere`, `Where`, `GroupBy`, `Having`, `OrderBy`, `LimitBy`, `Limit`, `UnionAll`/`Except`/`Intersect` sub-selects.
  - `TableIdentifier`: resolve `Database` (empty → `pol.DefaultSchema`) and `Table`; if unqualified and a CTE name in scope → allow unqualified; else must satisfy `CanRead`; set `Database` on the node so `String()` emits `db.table`; record the table.
  - `TableFunctionExpr` (numbers, url, file, s3, remote, merge, cluster, input, generateRandom, …) → reject "table functions are not allowed".
  - `FunctionExpr`: `policy.AllowedFunction(policy.ClickHouse, name)` (lowercased); walk params. Lambda expressions (`x -> ...`) inside `arrayMap`/`arrayFilter` are allowed; walk their bodies.
  - `CastExpr` / `CAST(x AS T)` and `::` : type name via `policy.AllowedCastType(policy.ClickHouse, base)` where base strips `Nullable(...)`/`LowCardinality(...)`/`Array(...)` wrappers recursively and checks each.
  - Subqueries in FROM/IN/EXISTS, JOINs (all join kinds, `USING`, `ON`), `WITH` CTEs (both `WITH x AS (SELECT …)` and `WITH expr AS name` forms), `ARRAY JOIN`, `PREWHERE`, `SAMPLE` → reject SAMPLE, `FINAL` → allow, window definitions → allow, `LIMIT … BY` → allow, `INTERPOLATE`/`WITH FILL` → allow, `SETTINGS` anywhere → reject, `FORMAT` → reject, `INTO OUTFILE` → reject.
  - Identifiers referencing `system.*` are rejected by the allowlist unless allowlisted.
- `StmtKind` is always `KindSelect`.

- [ ] **Step 1: `go get github.com/AfterShip/clickhouse-sql-parser@v0.5.6`** and read `parser/ast.go` for node types and `String()` behaviour.
- [ ] **Step 2: Implement guard.go and nodes.go.**
- [ ] **Step 3: Run `cmd/sqlguard-check --dialect clickhouse`** over the bypass corpus (common + clickhouse) and positive corpus; every bypass entry rejected, every positive entry accepted with `app.allowed_orders`-style qualification.
- [ ] **Step 4: Commit** `feat(chguard): clickhouse AST guard with deparse`.

### Task B2: ClickHouse backend

**Files:**
- Create: `internal/db/clickhouse/backend.go`, `catalog.go`

**Interfaces:**
- Produces:
```go
package chbackend // directory internal/db/clickhouse
func New(ctx context.Context, dsn string, pol *policy.Policy, logger *slog.Logger) (*Backend, error) // clickhouse.Open with native protocol; never fails on unreachable DB
// *Backend implements db.Backend (not db.TxBackend)
```
- `Query`: `clickhouse.WithSettings(ctx, clickhouse.Settings{"readonly": 1, "max_execution_time": <seconds>, "max_result_rows": maxRows+1, "result_overflow_mode": "break"})`; `conn.Query(ctx, sql)`; read up to `maxRows+1` rows; `Truncated` when more; column types from `rows.ColumnTypes()[i].DatabaseTypeName()`. Scan into `[]any` built from `ColumnTypes()[i].ScanType()` via `reflect.New`; convert `time.Time` → RFC3339, `uuid.UUID`-like → string, `*big.Int`/`decimal.Decimal` → string.
- `Explain`: `EXPLAIN PLAN indexes = 1 <sql>` (or `EXPLAIN PIPELINE <sql>` when `Analyze`), concatenate the single `explain` column rows with newlines into `planText`. Hypothetical indexes → `errors.New("hypothetical indexes are not supported on clickhouse")` (the server rejects earlier; keep the backend check too).
- `TablesExist`: `SELECT database, name FROM system.tables WHERE (database, name) IN (...)`.
- `catalog.go`: `ListSchemas` from `system.databases` (name, engine as description); `ListObjects` from `system.tables` filtered by `database` with `engine`, `total_rows`, `total_bytes`, type mapping (`View`/`MaterializedView` → view/materialized_view, `Dictionary` → dictionary, everything else → table); `sequence`/`extension` → empty; `ObjectDetails` from `system.columns` (name, type, default_expression, comment, nullable when type starts with `Nullable(`), `system.tables` (engine, sorting_key, partition_key, total_rows, total_bytes, comment), skipping indexes from `system.data_skipping_indices` as `Index{Name, Definition: type_full + " GRANULARITY " + granularity}`; constraints empty.

- [ ] **Step 1: Implement backend.go and catalog.go.**
- [ ] **Step 2: Commit** `feat(chbackend): clickhouse backend and introspection`.

### Task B3: ClickHouse e2e tests

**Files:**
- Create: `e2e/clickhouse_read_test.go`, `e2e/clickhouse_meta_test.go`, `e2e/clickhouse_explain_test.go`
- Modify: `cmd/restrictedsql-mcp/main.go` (wire `chguard.New()` and `chbackend.New` for dialect clickhouse)

- [ ] **Step 1: `clickhouse_read_test.go`**: `TestClickHouseReadBasic`, `TestClickHouseReadTruncation`, `TestClickHouseReadJoinAndAggregate` (use `uniq`, `toStartOfDay`), `TestClickHouseReadPositiveCorpus`, `TestClickHouseBypassCorpus` (common + clickhouse), `TestClickHouseReadStatementTimeout` (`--statement-timeout 1s`, `SELECT count() FROM allowed_orders a, allowed_orders b, allowed_orders c, allowed_orders d, allowed_orders e, allowed_orders f, allowed_orders g, allowed_orders h, allowed_orders i, allowed_orders j` cross join or `SELECT sum(number) FROM numbers(...)` is not allowed, so use the cross join → error mentioning `Timeout exceeded`), `TestClickHouseReadOnlyWhenTableNotReadable`, `TestClickHouseWriteFlagRejectedAtBoot` (exit 2).
- [ ] **Step 2: `clickhouse_meta_test.go`**: `list_schemas` contains `app` and `system`; `list_objects app table` contains the four tables with `engine` `MergeTree`; `view` contains `allowed_orders_v`; `sequence`/`extension` empty; `get_object_details app allowed_orders` has 5 columns, `engine` MergeTree, `sorting_key` `id`.
- [ ] **Step 3: `clickhouse_explain_test.go`**: plain explain returns non-empty `plan` text containing `ReadFromMergeTree`; `analyze:true` contains `Pipeline` or `Source`; hypothetical index → error `not supported on clickhouse`; bypass statement → rejected.
- [ ] **Step 4: Run `make e2e-ch`** until green. Commit `test(e2e): clickhouse suites`; push `stream-b-clickhouse`.

---

# Phase 2 (after merge) — adversarial cross-review

### Task R1 (account that built stream B): attack the Postgres guard
- Read `internal/sqlguard/postgres/` with the goal of finding any input that reaches a non-allowlisted table, calls a non-allowlisted function, or changes state. Ideas: `WITH` shadowing an allowlisted name with a forbidden body; recursive CTE referencing forbidden tables; `LATERAL`; `ROWS FROM`; `TABLE forbidden_secrets`; `SELECT * FROM allowed_orders, forbidden_secrets AS allowed_customers`; `ONLY`; `"Public"."allowed_orders"` quoting tricks; casts via `CAST(x AS regclass)`; `pg_catalog."pg_sleep"`; `xmlserialize`; `json_table`; `COLLATE`; `AT TIME ZONE`; operators `OPERATOR(pg_catalog.+)`; `IS DISTINCT FROM`; array subscripts; `ANY (SELECT … FROM forbidden)`; `VALUES` lists; `GROUPING SETS`; window `OVER (…)` with subqueries; `SELECT … FETCH FIRST … WITH TIES`; dollar-quoted strings; unicode escapes `U&"…"`; nested comments; a CTE named like an allowlisted table in write mode with an INSERT body. Add every finding as a case to `bypassCorpusPostgres` (rejected) or `positiveCorpusCommon`, fix the guard, run `make e2e-pg`. Commit `test(e2e): postgres adversarial cases` (+ `fix(pgguard): …` per fix).

### Task R2 (account that built stream A): attack the ClickHouse guard
- Same for `internal/sqlguard/clickhouse/`: `SELECT * FROM merge('app','.*')`, `remote(...)`, `cluster(...)`, `numbers(10)`, `generateRandom`, `input(...)`, `values(...)`, `system.tables`, `SETTINGS` in subqueries, `FORMAT` in subqueries, `INTO OUTFILE`, `SELECT ... FROM allowed_orders SAMPLE 0.1`, `arrayJoin` with functions, lambdas calling forbidden functions (`arrayMap(x -> sleep(1), [1])`), `dictGet`, `currentUser()`, `hostName()`, `getSetting('...')`, `file(...)`, `url(...)`, `s3(...)`, `executable(...)`, `sleepEachRow`, `throwIf`, `CAST(... AS ...)` to `Object('json')`, backtick vs double-quote identifiers, `app.forbidden_secrets` via `FROM (SELECT * FROM app.forbidden_secrets)`, `WITH forbidden_secrets AS (SELECT 1) SELECT * FROM forbidden_secrets` (allowed: CTE shadow), `WITH (SELECT secret FROM forbidden_secrets) AS s SELECT s` (rejected), `EXISTS (SELECT * FROM forbidden_secrets)`, `IN forbidden_secrets` (bare table in IN), `GLOBAL IN`, `JOIN` with table function on the right, `ARRAY JOIN` over a subquery on a forbidden table. Add cases to `bypassCorpusClickHouse` / `positiveCorpusCommon`, fix, run `make e2e-ch`. Commit `test(e2e): clickhouse adversarial cases` (+ fixes).

### Task R3 (account that built stream C): server review
- Review `internal/mcpserver`, `internal/txn`, `internal/health`, `cmd/` for: connection leaks on every error path in `Tx`; reaper races; `execute_sql_write` after commit; concurrent calls on one transaction id; `/readyz` timeout behaviour when the DB hangs (simulate with `docker pause`); graceful shutdown rolling back open transactions; `max_rows` handling at 0 and above the cap; error text never leaking the DSN. Add e2e cases for each into `e2e/smoke_test.go` / `postgres_write_test.go`; fix; commit.

### Task R4 (primary): final verification
- `make vet && make e2e` green; `docker build -f deploy/Dockerfile .` succeeds; README matches behaviour; tag `v0.1.0`.
