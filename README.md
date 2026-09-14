# restrictedsql-mcp

An MCP server that gives an agent SQL access to a Postgres or ClickHouse database,
restricted to an explicit allowlist of tables and a safe subset of SQL. Every
statement is parsed into an AST, validated against the policy, and re-serialized
from the AST. The database only ever receives that canonical form, never the raw
input.

Primary use case: let an agent inspect data and debug slow queries (introspection
and explain) with no way to touch anything outside the allowlist.

## Security model

1. **Parse.** Postgres statements go through `pg_query_go` (the real Postgres
   grammar via libpg_query); ClickHouse statements go through
   `clickhouse-sql-parser`.
2. **Allowlist walk.** A fail-closed visitor checks every AST node. Unknown node
   types, statement kinds, functions, cast types, table functions, and any table
   outside the allowlist are rejected with the offending node named.
3. **Deparse.** The canonical SQL is regenerated from the validated AST with every
   table reference fully qualified as `schema.table`. Comments and unmodelled
   syntax cannot survive the round trip.
4. **Session protections.** Postgres read tools run inside `BEGIN READ ONLY` with
   `statement_timeout` and `search_path` pinned; ClickHouse read tools run with
   `readonly=1`, `max_execution_time`, and `max_result_rows`.
5. **No inbound path.** The listener binds loopback by default. The only ingress is
   the gram tunnel agent, which dials out and proxies to the local `/mcp`.

Recommended second layer: point the DSN at a database role that only has the
grants the allowlist needs. The server does not depend on it, but it makes a bug
in the guard non-fatal.

The full policy is in `docs/superpowers/specs/2026-09-14-restricted-sql-mcp-design.md`.

## Running

```
restrictedsql-mcp \
  --dialect postgres|clickhouse          (required)
  --dsn <url>                            (or env DATABASE_URL; required)
  --read-tables schema.t1,schema.t2      (required, at least one)
  --write-tables schema.t3               (optional; used only with write tools)
  --dangerously-add-write-tools          (registers the 4 write tools; Postgres only)
  --default-schema public                (schema for unqualified names;
                                          ClickHouse: database from the DSN, else "default")
  --transport http|stdio                 (default http)
  --listen 127.0.0.1:8080                (http transport; MCP at /mcp, health at /healthz /readyz)
  --max-rows 1000                        (server cap on rows returned per call)
  --statement-timeout 30s
  --txn-idle-timeout 2m                  (write txn auto-rollback after idle)
  --max-open-txns 8
  --tunnel                               (start the gram tunnel agent; requires TUNNEL_GATEWAY_URL,
                                          TUNNEL_KEY; TUNNEL_SERVICE_VERSION defaults to the build version)
  --log-level info|debug
```

Boot semantics:

- Invalid flags exit 2 with a message: unknown dialect, no DSN, no read tables, an
  unparsable table name, write tools on ClickHouse, write tools without
  `--write-tables`, `--tunnel` without its environment, unknown transport.
- An unreachable database or a missing allowlisted table does **not** fail boot.
  The server starts, `/readyz` answers 503 with the reason, and readiness is
  re-evaluated on every probe.
- `GET /healthz` is 200 once the process serves. `GET /readyz` is 200 when the
  database answers a ping and every allowlisted table exists, else 503 with
  `{"ready":false,"reason":"..."}`. The body also carries
  `"tunnel":"disabled|connecting|connected|stopped"`, which does not gate readiness.
- Logs are JSON on stdout (stderr for the stdio transport, where stdout carries the
  protocol). At `debug` they include raw and canonical SQL, referenced tables,
  rejection reasons, timings, and transaction lifecycle events. The DSN is never
  logged.

## Tools

All tools take and return JSON. Errors come back as MCP tool errors
(`isError: true`) with a stable message; rejections name the reason and the
offending node, table, function, or type so the agent can self-correct.

### Read tools (always registered)

**`execute_sql_readonly`** — `{ "sql": string, "max_rows"?: int }`
Runs one SELECT-like statement against read-allowlisted tables. Returns
`{ "columns": [{name,type}], "rows": [[...]], "row_count", "truncated", "duration_ms" }`.
`max_rows` is capped at `--max-rows`; truncation is detected by fetching one row
past the cap.

**`list_schemas`** — `{}`
Lists every schema (Postgres) or database (ClickHouse) visible to the connection.
Catalog visibility is deliberately unrestricted; only execution is restricted.
Returns `{ "schemas": [{ "name", "owner"?, "description"? }] }`.

**`list_objects`** — `{ "schema": string, "object_type"?: "table"|"view"|"sequence"|"extension" }`
Returns `{ "objects": [{ "name", "type", "row_estimate"?, "size_bytes"?, "engine"? }] }`.
On ClickHouse, `sequence` and `extension` are empty.

**`get_object_details`** — `{ "schema": string, "name": string }`
Returns columns (name, type, nullable, default, description), constraints,
indexes, size, row estimate, description, and on ClickHouse the engine, sorting
key, and partition key.

**`explain_query`** — `{ "sql": string, "analyze"?: bool, "hypothetical_indexes"?: [{ "schema"?, "table", "columns": [string], "method"?: "btree"|"hash"|"gin"|"gist"|"brin" }] }`
The SQL goes through the same read-mode guard. Postgres runs
`EXPLAIN (FORMAT JSON, VERBOSE, COSTS[, ANALYZE, BUFFERS])` in a read-only
transaction; hypothetical indexes use the `hypopg` extension and the server builds
the `CREATE INDEX` text itself from the structured input (the table must be
read-allowlisted, columns must be plain identifiers). `analyze` and hypothetical
indexes are mutually exclusive. ClickHouse runs `EXPLAIN PLAN indexes=1` (or
`EXPLAIN PIPELINE` with `analyze`) and rejects hypothetical indexes. Returns
`{ "dialect", "plan": <json or text>, "notes"?: string }`.

### Write tools (Postgres only, need `--dangerously-add-write-tools`)

Writes are only possible inside an explicit transaction so the agent can inspect
the effect before committing.

**`begin_transaction`** — `{}` → `{ "transaction_id", "expires_at" }`
Pins a dedicated connection. Fails once `--max-open-txns` is reached.

**`execute_sql_write`** — `{ "transaction_id", "sql", "max_rows"? }`
Accepts INSERT / UPDATE / DELETE (RETURNING allowed) whose target is
write-allowlisted, and SELECT over read ∪ write tables. Source tables of
INSERT…SELECT, UPDATE…FROM, DELETE…USING, and subqueries must be in read ∪ write.
Returns `{ "rows_affected", "columns", "rows", "row_count", "truncated", "duration_ms" }`.
An error leaves the transaction aborted, as Postgres does; roll it back.

**`commit_transaction`** / **`rollback_transaction`** — `{ "transaction_id" }` → `{ "status" }`
Release the connection. Unknown or expired ids return an error.

Transactions idle longer than `--txn-idle-timeout` are rolled back by a reaper and
their id is invalidated. Transactions are process-local, so run one replica.

### Transaction workflow example

```
begin_transaction        {}                                   → {"transaction_id":"…","expires_at":"…"}
execute_sql_write        {"transaction_id":"…","sql":"INSERT INTO allowed_audit (note) VALUES ('checked') RETURNING id"}
                                                              → {"rows_affected":1,"rows":[[7]],…}
execute_sql_write        {"transaction_id":"…","sql":"SELECT count(*) FROM allowed_audit"}
                                                              → {"rows":[[1]],…}
commit_transaction       {"transaction_id":"…"}               → {"status":"committed"}
```

## ClickHouse limitations

- No write tools; `--dangerously-add-write-tools` is a boot error.
- No hypothetical indexes in `explain_query`.
- `SETTINGS`, `FORMAT`, `INTO OUTFILE`, `SAMPLE`, table functions (`numbers`,
  `url`, `file`, `s3`, `remote`, `merge`, …) and `system.*` tables are rejected
  unless a `system` table is explicitly allowlisted.

## Development

Requirements: Go 1.27, a C compiler (cgo for `pg_query_go`), Docker with Compose.

```
make build      # bin/restrictedsql-mcp
make vet        # gofmt + go vet
make e2e-up     # start the shared Postgres (with hypopg) and ClickHouse stack
make e2e        # e2e-up, then E2E=1 go test ./e2e/...
make e2e-pg     # only Postgres and common suites
make e2e-ch     # only ClickHouse and common suites
```

There are no unit tests. The e2e suite builds the real binary once, boots it as a
subprocess per test with the flags under test, waits for `/readyz`, and drives it
with the go-sdk MCP client over Streamable HTTP. Subprocess logs (debug level) are
printed on failure. Without `E2E=1` the package exits immediately so
`go test ./...` stays fast.

The compose stack binds Postgres to `127.0.0.1:55433` (55432 is often taken by
other local databases) and ClickHouse to `127.0.0.1:59000` (native) and
`127.0.0.1:58123` (HTTP). Override with `E2E_PG_PORT`, `E2E_CH_NATIVE_PORT`,
`E2E_CH_HTTP_PORT`, or point the tests at other databases with `E2E_PG_DSN` and
`E2E_CH_DSN`. The stack is shared between parallel work streams; `make e2e-down`
tears it down and should be run deliberately.

## Deployment

`deploy/Dockerfile` builds with `golang:1.27-bookworm` (gcc for cgo) and ships a
`debian:bookworm-slim` image running as a non-root user with
`ENTRYPOINT ["/restrictedsql-mcp"]`:

```
docker build -f deploy/Dockerfile --build-arg VERSION=v0.1.0 -t restrictedsql-mcp:v0.1.0 .
docker run --rm restrictedsql-mcp:v0.1.0 --help
```

`deploy/k8s.yaml` is a single-replica Deployment with the liveness probe on
`/healthz`, readiness and startup probes on `/readyz`, `DATABASE_URL` and
`TUNNEL_*` from a Secret, and no Service or Ingress. The server listens on
loopback; if your CNI keeps kubelet from probing 127.0.0.1, listen on
`0.0.0.0:8080` and add a NetworkPolicy that denies ingress.

Set `TUNNEL_GATEWAY_URL` and `TUNNEL_KEY` and pass `--tunnel` to expose the server
through gram. The agent dials out and proxies to `http://<listen>/mcp`; the
readiness body reports the tunnel state without gating on it.
