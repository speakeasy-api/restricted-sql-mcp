# Restricted SQL MCP Server — Design

Date: 2026-09-14
Repo: github.com/speakeasy-api/restricted-sql-mcp (private, no license)
Binary: `restrictedsql-mcp`
Language: Go 1.27 (gram tunnel agent requires 1.27)

## 1. Goal

An MCP server that gives an agent SQL access to a Postgres or ClickHouse database,
restricted to an explicit allowlist of tables and a safe subset of SQL. Every SQL
statement received over MCP is parsed into an AST, validated against the policy,
and re-serialized (deparsed) from the AST. The database only ever receives the
canonical deparsed form, never the raw input.

Primary use case: let an agent inspect data and debug why a query is slow
(introspection + explain) with no risk of touching anything outside the allowlist.

Non-goals for v1: authentication (handled by the Gram tunnel layer), per-user
role mapping, bind parameters, MERGE/COPY/DDL of any kind, ClickHouse writes.

## 2. Approach

Chosen: **AST allowlist validator + deparse**.

- Parse with a dialect-specific parser. Postgres: `github.com/pganalyze/pg_query_go/v6`
  (cgo wrapper of libpg_query, i.e. the real Postgres grammar, so no
  parser-differential bypass). ClickHouse: `github.com/AfterShip/clickhouse-sql-parser`
  (pure Go).
- Walk the AST with a **fail-closed** visitor: every node type must be in an explicit
  allowlist for the statement mode, otherwise reject with the node type named.
- Deparse from the AST and send only the canonical SQL. Any syntax the parser did not
  model cannot survive the round trip.
- Defense in depth at the session level: Postgres read tool runs in
  `BEGIN READ ONLY` with `statement_timeout` and `search_path` pinned; ClickHouse read
  tool runs with `readonly=1`, `max_execution_time`, `max_result_rows`.

Rejected alternatives:
- DB-side enforcement only (roles/grants): cannot restrict verbs or functions
  finely, cannot enforce on ClickHouse, depends on DB config outside this repo.
  Recommended as an extra layer in deployment docs, not as the mechanism.
- Regex/tokenizer denylist: not sound.

## 3. CLI and boot

```
restrictedsql-mcp \
  --dialect postgres|clickhouse          (required)
  --dsn <url>                            (or env DATABASE_URL; required)
  --read-tables schema.t1,schema.t2      (required, at least one)
  --write-tables schema.t3               (optional; used only with write tools)
  --dangerously-add-write-tools          (registers the 4 write tools; Postgres only)
  --default-schema public                (schema used to resolve unqualified names;
                                          CH default: database from DSN, else "default")
  --transport http|stdio                 (default http)
  --listen 127.0.0.1:8080                (http transport; MCP at /mcp, health at /healthz /readyz)
  --max-rows 1000                        (server cap on rows returned per call)
  --statement-timeout 30s
  --txn-idle-timeout 2m                  (write txn auto-rollback after idle)
  --max-open-txns 8
  --tunnel                               (start gram tunnel agent; requires TUNNEL_GATEWAY_URL,
                                          TUNNEL_KEY; TUNNEL_SERVICE_VERSION defaults to build version)
  --tunnel-only                          (refuse /mcp requests that did not come through the in-process
                                          tunnel agent; requires --tunnel and --transport http)
  --log-level info|debug
```

Boot semantics:
- Invalid flags (unknown dialect, no read tables, unparsable table name, write tools on
  ClickHouse, `--tunnel` without env, `--tunnel-only` without `--tunnel` or with
  stdio) exit 2 with a clear message.
- `--tunnel-only`: a per-boot random token is pinned on the agent's local MCP URL
  query; `/mcp` returns 401 to any request without it and strips it before the MCP
  handler. Health endpoints stay open.
- DB unreachable or allowlisted tables missing does **not** fail boot. The server
  starts, `/readyz` reports not-ready with the reason, and readiness is re-evaluated
  on each probe. This matches "booting just boots; health/init probes validate".
- Listener binds only the configured address (default loopback). There is no
  inbound path except via the tunnel agent, which dials out to Gram and proxies to
  `http://<listen>/mcp`.

Health:
- `GET /healthz` → 200 always once the process is serving (liveness).
- `GET /readyz` → 200 if DB ping succeeds and all allowlisted tables exist; else 503
  with JSON `{"ready":false,"reason":"..."}`. Tunnel connection state is reported in
  the body (`"tunnel":"connected|connecting|disabled"`) but does not gate readiness.

Logging: `log/slog` JSON to stdout. At `debug`: raw SQL, canonical SQL, referenced
tables, rejection reason and node, timings, transaction lifecycle events.

## 4. Tools

All tools take and return JSON. Errors are returned as MCP tool errors
(`isError: true`) with a stable, human-readable message; rejections include the
reason and offending node/table/function name so the agent can self-correct.

### Read tools (always registered)

`execute_sql_readonly`
- Input: `{ "sql": string, "max_rows"?: int }`
- Runs one SELECT-like statement against read-allowlisted tables only.
- Output: `{ "columns": [{name,type}], "rows": [[...]], "row_count": int,
  "truncated": bool, "duration_ms": int }`
- `max_rows` is capped at `--max-rows`. Truncation is detected by fetching cap+1 rows.

`list_schemas`
- Input: `{}`
- Lists every schema (Postgres) or database (ClickHouse) visible to the connection.
  Full catalog visibility was chosen deliberately: only execution is restricted.
- Output: `{ "schemas": [{ "name", "owner"?, "description"? }] }`

`list_objects`
- Input: `{ "schema": string, "object_type"?: "table"|"view"|"sequence"|"extension" }`
- Lists objects in a schema. On ClickHouse, `sequence` and `extension` return empty.
- Output: `{ "objects": [{ "name", "type", "row_estimate"?, "size_bytes"?, "engine"? }] }`

`get_object_details`
- Input: `{ "schema": string, "name": string }`
- Output: `{ "type", "columns": [{name,type,nullable,default,description}],
  "constraints": [{name,type,definition}], "indexes": [{name,definition,size_bytes?}],
  "size_bytes"?, "row_estimate"?, "description"?, "engine"?, "sorting_key"?,
  "partition_key"? }`

`explain_query`
- Input: `{ "sql": string, "analyze"?: bool,
  "hypothetical_indexes"?: [{ "schema"?, "table", "columns": [string], "method"?: "btree"|"hash"|"gin"|"gist"|"brin" }] }`
- The SQL goes through the same read-mode guard as `execute_sql_readonly`.
- Postgres: `EXPLAIN (FORMAT JSON, VERBOSE, COSTS, [ANALYZE, BUFFERS])` inside a
  READ ONLY transaction. Hypothetical indexes use the `hypopg` extension:
  the server builds `CREATE INDEX ON schema.table USING method (cols)` itself from the
  structured input (table must be read-allowlisted, columns must be plain identifiers),
  calls `hypopg_create_hypothetical_index(...)`, explains, then `hypopg_reset()`.
  If hypopg is not installed the tool returns an error saying so; `analyze` and
  hypothetical indexes are mutually exclusive.
- ClickHouse: `EXPLAIN PLAN indexes=1` (or `EXPLAIN PIPELINE` when `analyze` is true).
  Hypothetical indexes return an unsupported error.
- Output: `{ "dialect", "plan": <json or text>, "notes"?: string }`

### Write tools (registered only with `--dangerously-add-write-tools`; Postgres only)

Writes are only possible inside an explicit transaction so the agent can inspect the
effect (e.g. rows affected, a SELECT of the changed rows) before committing.

`begin_transaction`
- Input: `{}` → Output: `{ "transaction_id": string, "expires_at": RFC3339 }`
- Pins a dedicated connection, `BEGIN`. Fails if `--max-open-txns` reached.

`execute_sql_write`
- Input: `{ "transaction_id": string, "sql": string, "max_rows"?: int }`
- Accepts INSERT / UPDATE / DELETE (with RETURNING) whose target table is
  write-allowlisted, and SELECT statements over read ∪ write allowlisted tables
  (for validation inside the transaction). Source tables of INSERT…SELECT, UPDATE…FROM,
  DELETE…USING and subqueries must be in read ∪ write.
- Output: `{ "rows_affected": int, "columns", "rows", "row_count", "truncated", "duration_ms" }`
- Any error inside the transaction leaves it in the aborted state, as Postgres does;
  the agent must roll back.

`commit_transaction` / `rollback_transaction`
- Input: `{ "transaction_id": string }` → Output: `{ "status": "committed"|"rolled_back" }`
- Releases the connection. Unknown or expired ids return an error.

Transactions idle longer than `--txn-idle-timeout` are rolled back by a reaper and
the id is invalidated. Transactions are process-local (a single replica).

## 5. SQL policy (both dialects)

Definitions:
- `TableRef{Schema, Name}`. Unqualified names resolve to `--default-schema`.
  Postgres identifiers are normalized the way Postgres does (unquoted → lowercase,
  quoted → verbatim). ClickHouse identifiers are case-sensitive and kept verbatim.
- Read set R = `--read-tables`. Write set W = `--write-tables`.

Rules applied by the guard:
1. Exactly one statement. Empty input, multiple statements, or trailing statements
   are rejected.
2. Statement kinds. Read mode: `SELECT` (including `WITH`, set operations, subqueries,
   joins, `GROUP BY/HAVING`, window functions, `ORDER BY/LIMIT/OFFSET`, `VALUES` as a
   subquery). Write mode: read-mode statements plus `INSERT`, `UPDATE`, `DELETE`.
   Everything else is rejected: DDL, `TRUNCATE`, `MERGE`, `COPY`, `SET`, `SHOW`,
   `LOCK`, `CALL`, `DO`, `EXPLAIN` (use the tool), `PREPARE/EXECUTE`, `LISTEN/NOTIFY`,
   `GRANT/REVOKE`, `VACUUM/ANALYZE`, `SELECT … INTO`, `SELECT … FOR UPDATE/SHARE`,
   ClickHouse `INSERT … SELECT FROM <table function>`, `SETTINGS`, `FORMAT`,
   `INTO OUTFILE`, `SYSTEM`, `OPTIMIZE`, `KILL`, `ATTACH/DETACH`, `EXCHANGE/RENAME`.
3. Table references. Every relation in `FROM`, `JOIN`, subqueries, CTE bodies,
   `INSERT INTO`, `UPDATE`, `DELETE FROM`, `USING`, and `INSERT … SELECT` must resolve
   to R (read mode) or R ∪ W (SELECT in write mode) or W (mutation target).
   CTE names introduced by the statement are local relations and are allowed to be
   referenced. Table functions (`generate_series`, `unnest` in FROM, ClickHouse
   `numbers`, `url`, `file`, `s3`, `remote`, `merge`, …) are rejected. `pg_catalog`,
   `information_schema` and ClickHouse `system` tables are only reachable if
   explicitly allowlisted.
4. Functions. Only functions in the per-dialect allowlist may be called, matched by
   lowercased name with no schema qualifier (a schema-qualified function call is
   rejected). The allowlist covers aggregates (`count, sum, avg, min, max,
   array_agg, string_agg, bool_and, bool_or, …`), window functions (`row_number,
   rank, dense_rank, lag, lead, first_value, last_value, ntile`), scalar string,
   math, date/time, JSON accessors, `coalesce, nullif, greatest, least`, and their
   ClickHouse equivalents (`toDate, toStartOfDay, toString, uniq, quantile,
   groupArray, …`). `arrayJoin` is allowed. A rejected function is named in the error.
   Not allowed (examples): `pg_sleep`, `pg_read_file`, `lo_*`, `dblink*`,
   `pg_terminate_backend`, `set_config`, `current_setting`, `query_to_xml`,
   `pg_advisory_lock`, `nextval/setval`, any `pg_*`/`hypopg_*` function, ClickHouse
   `url`, `file`, `s3`, `remote`, `executable`, `dictGet*`, `sleep`, `throwIf`.
   The lists live in `internal/policy/functions_postgres.go` and
   `internal/policy/functions_clickhouse.go`.
5. Casts and types. Casts are allowed only to a builtin type allowlist (numeric,
   text/varchar, boolean, date/time/timestamp(tz), interval, uuid, json/jsonb,
   arrays of those). Casts to `regclass`, `regproc`, `oid`, `xid`, etc. are rejected.
6. Any AST node type not explicitly allowlisted is rejected with its type name.
   The visitor must be exhaustive over child fields so nothing is skipped.
7. The deparsed canonical SQL fully qualifies every table reference
   (`schema.table`), so `search_path` cannot change resolution.
8. No comments survive deparse.

Session-level second layer:
- Postgres read tool and explain: `BEGIN READ ONLY; SET LOCAL statement_timeout;
  SET LOCAL search_path = <default-schema>;` then `ROLLBACK`.
- Postgres write transactions: `BEGIN; SET LOCAL statement_timeout;
  SET LOCAL search_path = <default-schema>;`.
- ClickHouse: per-query settings `readonly=1` (read tool), `max_execution_time`,
  `max_result_rows` (with `result_overflow_mode='break'`).

## 6. Bypass corpus (must be rejected by both guards where the syntax parses)

Both e2e suites run the same corpus against read mode and assert rejection:

```
SELECT 1; DROP TABLE allowed_orders
SELECT * FROM forbidden_secrets
SELECT * FROM allowed_orders JOIN forbidden_secrets USING (id)
SELECT * FROM allowed_orders WHERE id IN (SELECT id FROM forbidden_secrets)
WITH x AS (SELECT * FROM forbidden_secrets) SELECT * FROM x
SELECT (SELECT count(*) FROM forbidden_secrets)
SELECT * FROM public.forbidden_secrets
SELECT * FROM "allowed_orders" a, forbidden_secrets b
SELECT pg_sleep(10)
SELECT * FROM allowed_orders, LATERAL generate_series(1,10)
SELECT * FROM generate_series(1,10)
SELECT lo_import('/etc/passwd')
SELECT pg_read_file('/etc/passwd')
SELECT current_setting('is_superuser')
SELECT set_config('search_path','x',false)
SELECT * FROM pg_catalog.pg_tables
SELECT * FROM information_schema.tables
SELECT * FROM allowed_orders FOR UPDATE
SELECT * INTO new_tbl FROM allowed_orders
COPY allowed_orders TO '/tmp/x'
INSERT INTO allowed_orders VALUES (1)              -- read mode
UPDATE allowed_orders SET amount = 0               -- read mode
DELETE FROM allowed_orders                         -- read mode
TRUNCATE allowed_orders
ALTER TABLE allowed_orders ADD COLUMN x int
CREATE TABLE t (x int)
EXPLAIN SELECT * FROM allowed_orders
SET search_path = other
SHOW search_path
SELECT 'x'::regclass
SELECT * FROM allowed_orders TABLESAMPLE SYSTEM (1) -- rejected in v1 (no TABLESAMPLE)
SELECT * FROM allowed_orders /* comment */ ; --
SELECT * FROM system.tables                        -- clickhouse
SELECT * FROM url('http://x','CSV')                -- clickhouse
SELECT * FROM numbers(10)                          -- clickhouse
SELECT * FROM allowed_orders SETTINGS max_threads=1 -- clickhouse
SELECT * FROM allowed_orders FORMAT JSON           -- clickhouse
SELECT * FROM allowed_orders INTO OUTFILE '/tmp/x' -- clickhouse
SELECT sleep(3)                                    -- clickhouse
INSERT INTO allowed_orders SELECT * FROM forbidden_secrets   -- write mode, W={allowed_orders}
UPDATE allowed_orders SET amount = (SELECT max(x) FROM forbidden_secrets) -- write mode
DELETE FROM allowed_orders USING forbidden_secrets WHERE ...           -- write mode
INSERT INTO forbidden_secrets VALUES (1)           -- write mode
```

And a positive corpus that must be accepted (joins between allowed tables, CTEs over
allowed tables, aggregates, window functions, ORDER/LIMIT, INSERT…RETURNING in write
mode, UPDATE with subquery over allowed tables, etc.).

## 7. Code layout

```
cmd/restrictedsql-mcp/main.go        flags → config → boot
internal/config/                     Config struct, flag parsing, validation
internal/policy/                     TableRef, Policy, function/type allowlists per dialect
internal/sqlguard/guard.go           Guard interface, Mode, Checked, RejectError
internal/sqlguard/postgres/          pg_query_go visitor + deparse
internal/sqlguard/clickhouse/        AfterShip visitor + deparse
internal/db/backend.go               Backend, TxBackend, Tx, Result types
internal/db/postgres/                pgx implementation, catalog queries, explain, hypopg
internal/db/clickhouse/              clickhouse-go implementation, system.* queries, explain
internal/txn/                        transaction registry + reaper
internal/mcpserver/                  go-sdk server, tool registration, handlers, schemas
internal/health/                     /healthz /readyz handlers
internal/tunnel/                     wraps github.com/speakeasy-api/gram/tunnel/agent
e2e/                                 docker compose, seed SQL, harness, tests
deploy/                              Dockerfile, example k8s manifest
Makefile                             build, e2e, lint
```

Interfaces (contract for parallel work):

```go
// internal/policy
type Dialect string // "postgres" | "clickhouse"
type TableRef struct{ Schema, Name string }
func (t TableRef) String() string // schema.name
func ParseTableRef(s, defaultSchema string, d Dialect) (TableRef, error)
type Policy struct {
    Dialect       Dialect
    DefaultSchema string
    ReadTables    map[TableRef]struct{}
    WriteTables   map[TableRef]struct{}
    WritesEnabled bool
    MaxRows       int
    StatementTimeout time.Duration
}
func (p *Policy) CanRead(t TableRef) bool   // t ∈ R
func (p *Policy) CanSelectInWrite(t TableRef) bool // t ∈ R ∪ W
func (p *Policy) CanMutate(t TableRef) bool // t ∈ W
func AllowedFunction(d Dialect, name string) bool
func AllowedCastType(d Dialect, typeName string) bool

// internal/sqlguard
type Mode int
const ( ModeRead Mode = iota; ModeWrite )
type StmtKind string // "select" | "insert" | "update" | "delete"
type Checked struct {
    SQL    string            // canonical, fully qualified
    Kind   StmtKind
    Tables []policy.TableRef // every relation referenced (deduplicated)
}
type RejectError struct{ Reason, Node string }
func (e *RejectError) Error() string
type Guard interface {
    Check(raw string, mode Mode, pol *policy.Policy) (*Checked, error)
}
// Postgres only:
type HypotheticalIndex struct{ Table policy.TableRef; Columns []string; Method string }
func BuildIndexDDL(h HypotheticalIndex) (string, error) // validates identifiers, builds CREATE INDEX

// internal/db
type Column struct{ Name, Type string }
type Result struct {
    Columns      []Column
    Rows         [][]any
    RowsAffected int64
    Truncated    bool
    Duration     time.Duration
}
type ExplainOptions struct{ Analyze bool; HypotheticalIndexes []sqlguard.HypotheticalIndex }
type Schema struct{ Name, Owner, Description string }
type Object struct{ Name, Type, Engine string; RowEstimate, SizeBytes *int64 }
type ObjectDetails struct{ ... per §4 ... }
type Backend interface {
    Dialect() policy.Dialect
    Ping(ctx context.Context) error
    TablesExist(ctx context.Context, refs []policy.TableRef) (missing []policy.TableRef, err error)
    Query(ctx context.Context, canonicalSQL string, maxRows int) (*Result, error)
    Explain(ctx context.Context, canonicalSQL string, opts ExplainOptions) (json.RawMessage, string, error)
    ListSchemas(ctx context.Context) ([]Schema, error)
    ListObjects(ctx context.Context, schema, objectType string) ([]Object, error)
    ObjectDetails(ctx context.Context, ref policy.TableRef) (*ObjectDetails, error)
    Close() error
}
type Tx interface {
    Exec(ctx context.Context, canonicalSQL string, maxRows int) (*Result, error)
    Commit(ctx context.Context) error
    Rollback(ctx context.Context) error
}
type TxBackend interface { Begin(ctx context.Context) (Tx, error) } // postgres only
```

`Query` and `Explain` own the session-level protections (read-only txn / readonly
setting, timeouts, search_path). `Tx.Exec` applies `statement_timeout` and
`search_path` at `Begin`.

## 8. Dependencies

- `github.com/modelcontextprotocol/go-sdk` v1.8.0 (MCP server + client for tests)
- `github.com/pganalyze/pg_query_go/v6` v6.2.2 (cgo)
- `github.com/AfterShip/clickhouse-sql-parser` v0.5.6
- `github.com/jackc/pgx/v5` v5.11.0
- `github.com/ClickHouse/clickhouse-go/v2` v2.48.0
- `github.com/speakeasy-api/gram` (tunnel/agent; AGPL-3.0, first-party)
- stdlib for everything else (flag, slog, net/http, os/exec in tests). No
  testcontainers; e2e uses `docker compose` via the Makefile.

## 9. Testing

Only e2e tests, in `e2e/`, gated by `E2E=1` (otherwise skipped) so `go test ./...`
stays fast. `make e2e`:
1. `docker compose -f e2e/docker-compose.yml up -d --wait` — `postgres:17` with
   `hypopg` installed via `e2e/postgres/Dockerfile`, and `clickhouse/clickhouse-server`.
   Seed SQL creates `allowed_orders`, `allowed_customers` (read), `allowed_audit`
   (write), and `forbidden_secrets` in both databases.
2. `go build` the binary once in `TestMain`.
3. Each test boots the real binary as a subprocess with the flags under test on a
   free port, waits for `/readyz`, and connects with the go-sdk MCP client over
   Streamable HTTP. Subprocess stdout/stderr (JSON logs at debug level) is captured
   and printed on failure.
4. Suites: postgres read, postgres metadata, postgres explain (+hypopg), postgres
   write transaction flow (begin → insert → select rows → rollback; begin → update →
   commit; idle timeout reaper; max-open-txns), clickhouse read, clickhouse metadata,
   clickhouse explain, bypass corpus (both), positive corpus (both), health endpoints
   (readyz false when a listed table is missing; boot exit codes for bad flags;
   write tools absent without the flag; write flag rejected on clickhouse).

## 10. Deployment

- `deploy/Dockerfile`: `golang:1.27` builder with gcc (cgo for pg_query),
  `debian:bookworm-slim` runtime, non-root user, `ENTRYPOINT ["/restrictedsql-mcp"]`.
- `deploy/k8s.yaml`: Deployment with `livenessProbe` on `/healthz`, `readinessProbe`
  and `startupProbe` on `/readyz`, env `DATABASE_URL` and `TUNNEL_*` from Secrets,
  no Service/Ingress (tunnel only), one replica (transactions are process-local).
- Docs recommend pointing the DSN at a database role that only has the grants the
  allowlist needs, as an independent second layer.

## 11. Connection-level security (as built)

`--connection-level-security` (default off) adds a database-side layer that does
not depend on the guard. `--security-role-prefix` (default `restrictedsql`) names
the roles. Without the flag, behaviour is unchanged: one pool on the DSN.

Roles. The DSN is a bootstrap connection. On Postgres the server creates or
updates `<prefix>_ro` and, only with `--dangerously-add-write-tools`,
`<prefix>_rw`: `LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
NOREPLICATION`, a fresh 32-byte random password per boot held only in memory
(sent as a SCRAM-SHA-256 verifier when `password_encryption` is scram),
`ALTER ROLE ... SET search_path = <default-schema>` and `SET statement_timeout =
<flag>`. For every schema the bootstrap has `USAGE` on (system schemas
excluded) it runs `REVOKE ALL ON ALL TABLES IN SCHEMA`, `REVOKE ALL ON ALL
SEQUENCES IN SCHEMA`, `REVOKE ALL ON SCHEMA`; then grants exactly: ro — `USAGE`
on schemas of R, `SELECT` on R; rw — `USAGE` on schemas of R ∪ W, `SELECT` on
R ∪ W, `INSERT/UPDATE/DELETE` on W, `USAGE, SELECT` on the sequences W tables
depend on (`pg_depend` auto/internal dependencies and sequences referenced by
`pg_attrdef` defaults). Creation-or-update runs as a `DO` block so the
CREATE/ALTER choice is made inside the same transaction as the grants; the whole
sequence is one transaction, so a failure leaves the previous state intact.

On ClickHouse the server runs `CREATE USER OR REPLACE <prefix>_ro IDENTIFIED WITH
sha256_password BY '<random>' SETTINGS readonly = 1 READONLY, max_execution_time
= <timeout> CHANGEABLE_IN_READONLY MIN 0 MAX <timeout>, max_result_rows =
<max-rows+1> CHANGEABLE_IN_READONLY MIN 0 MAX <max-rows+1>, result_overflow_mode
= 'break' CHANGEABLE_IN_READONLY`, `REVOKE ALL ON *.*`, `GRANT SELECT ON db.table`
per R table, `GRANT SHOW TABLES, SHOW COLUMNS ON db.*` per R database, and
`GRANT SELECT ON system.data_skipping_indices`. A user pinned to `readonly = 1`
rejects any per-query setting change, so the backend's existing per-query
limits are admitted through `CHANGEABLE_IN_READONLY` with the policy values as
hard maxima; the backend is unchanged. ClickHouse filters `system.databases`,
`system.tables` and `system.columns` by the user's grants, so the metadata tools
list only databases holding allowlisted tables and the tables in those
databases; `system.data_skipping_indices` needs an explicit `SELECT` grant.

Connection. After provisioning, tool traffic runs on pools whose DSN is the
bootstrap DSN with user and password replaced (`internal/dbsec.RewriteDSN`,
`net/url`, all other query parameters preserved, `user`/`username`/`password`
query keys stripped). The Postgres backend has a read pool (Query, Explain,
metadata, TablesExist, Ping) and, when writes are enabled, a write pool used by
Begin. `SET ROLE` is never used. The bootstrap connection is a single `pgx`
connection (native `clickhouse-go` connection) opened per provisioning attempt
and closed when it returns.

Boot semantics. `internal/dbsec.Gate` implements `db.Backend` and
`db.TxBackend`; it is the backend `main` hands to the MCP server, the transaction
registry and the health checker. Every call first runs `EnsureProvisioned`,
which provisions and opens the real backend once (single-flight; concurrent
callers wait) and afterwards is a cheap atomic load. Boot attempts it with a
10 s timeout and only logs on failure; `/readyz` (3 s timeout) and every tool
call retry. Until it succeeds `/readyz` is 503 with reason `connection-level
security not provisioned: <err>` and tools return the same text. `<err>` names
the failing statement (`statement "GRANT SELECT ON TABLE ... TO ..." failed:
ERROR: permission denied ...`); role statements are rendered with the password
redacted. Passwords and DSNs are never logged; the `info` summary lists the
roles and the tables, schemas and sequences granted.

Code layout: `internal/dbsec/provisioner.go` (`Provisioner`, `Creds`,
`NotProvisionedError`, `StatementError`, `NewPassword`, `RewriteDSN`),
`internal/dbsec/gate.go`, `internal/dbsec/postgres.go`,
`internal/dbsec/clickhouse.go`; `config.Config.ConnectionLevelSecurity` and
`SecurityRolePrefix`; `pgbackend.NewWithWriteDSN`; `health` recognises a backend
with `EnsureProvisioned` and reports its error verbatim.

Operational notes: single replica (every boot rotates the passwords); privileges
granted to `PUBLIC` and pre-existing role memberships are outside what the
server revokes; e2e coverage is in `e2e/security_test.go`.
