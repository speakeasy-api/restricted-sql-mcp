# restrictedsql-mcp

An MCP server that gives an agent SQL access to a Postgres or ClickHouse database,
restricted by either an explicit table allowlist or per-column access annotations,
and a safe subset of SQL. Every
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
   The Speakeasy Control Plane tunnel agent, which dials out and proxies to the local `/mcp`.

Second layer, independent of the guard: `--connection-level-security` makes the
server provision database roles that hold exactly the grants the allowlist needs
and run every tool call as those roles (see below). Without the flag, point the
DSN at such a role yourself. Either way the server does not depend on it, but it
makes a bug in the guard non-fatal.

Column annotation mode requires this second layer. It grants only selected
columns, validates every column use, and serves structural metadata for all
application tables, including denied ones. See [column access](docs/column-access.md)
for the supported SQL surface and required migration procedure.

The full policy is in `docs/superpowers/specs/2026-09-14-restricted-sql-mcp-design.md`.

## Running

```
restrictedsql-mcp \
  --dialect postgres|clickhouse          (required)
  --dsn <url>                            (or env DATABASE_URL; required)
  --read-tables schema.t1,schema.t2      (required in static table mode)
  --columns-from-annotations confidential (alternative to read-tables; readable @access classes, e.g. confidential;
                                          requires connection-level-security; read-only)
  --annotation-refresh-interval 30s      (annotation catalog/grant refresh; HTTP and stdio)
  --annotation-refresh-timeout 10s       (bounds refresh and active-query draining)
  --write-tables schema.t3               (optional; used only with write tools)
                                         (<schema>.* in either list adds every table in the schema
                                          at boot; postgres only; restart to pick up new tables)
  --dangerously-add-write-tools          (registers the 4 write tools; Postgres only)
  --default-schema public                (schema for unqualified names;
                                          ClickHouse: database from the DSN, else "default")
  --transport http|stdio                 (default http)
  --listen 127.0.0.1:8080                (http transport; MCP at /mcp, health at /healthz /readyz)
  --health-listen 0.0.0.0:8081           (optional second listener serving only /healthz and /readyz)
  --max-rows 1000                        (server cap on rows returned per call)
  --statement-timeout 30s
  --txn-idle-timeout 2m                  (write txn auto-rollback after idle)
  --max-open-txns 8
  --tunnel                               (start the Speakeasy Control Plane tunnel agent; requires TUNNEL_GATEWAY_URL,
                                          TUNNEL_KEY; TUNNEL_SERVICE_VERSION defaults to the build version)
  --tunnel-only                          (refuse /mcp requests that did not arrive through the in-process
                                          tunnel agent; direct loopback access gets 401; requires --tunnel)
  --connection-level-security            (treat the DSN as a bootstrap connection, provision
                                          least-privilege roles and run tool traffic as them;
                                          see "Connection-level security")
  --security-role-prefix restrictedsql   (static roles: <prefix>_ro, <prefix>_rw;
                                          annotation mode adds a random process suffix)
  --databases '^app_preview_pr_'        (regex; also serve the matching databases of the same server
                                          next to the DSN's database; postgres static table mode only;
                                          see "Multi-database mode")
  --log-level info|debug
```

Boot semantics:

- Invalid flags exit 2 with a message: unknown dialect, no DSN, no read tables, an
  unparsable table name, write tools on ClickHouse, write tools without
  `--write-tables`, `--tunnel` without its environment, unknown transport,
  `--databases` with an invalid regex, on ClickHouse, or with `--columns-from-annotations`.
- An unreachable database or a missing allowlisted table does **not** fail boot.
  The server starts, `/readyz` answers 503 with the reason, and readiness is
  re-evaluated on every probe.
- `GET /healthz` is 200 once the process serves. `GET /readyz` is 200 when the
  database answers a ping and every allowlisted table exists (and, with
  `--connection-level-security`, the roles have been provisioned), else 503 with
  `{"ready":false,"reason":"..."}`. The body also carries
  `"tunnel":"disabled|connecting|connected|stopped"`, which does not gate readiness.
- Logs are JSON on stdout (stderr for the stdio transport, where stdout carries the
  protocol). At `debug` they include raw and canonical SQL, referenced tables,
  rejection reasons, timings, and transaction lifecycle events. The DSN is never
  logged.
- In annotation mode, readiness refreshes the catalog and verifies exact column
  grants. A failed refresh closes tool admission, including existing MCP
  sessions. Periodic refresh also runs without readiness probes. An empty set
  of selectable columns is valid: metadata remains available, data is denied.

Example annotation deployment (the bootstrap DSN is supplied in `DATABASE_URL`):

```sh
restrictedsql-mcp --dialect postgres \
  --columns-from-annotations confidential --connection-level-security
```

The database owner defines the class names. The server reads only the classes
listed and denies all others, so list only classes whose every column is fit to
expose (for the Speakeasy Control Plane, `confidential`, adding `confidential-pii` when reviewed
identity columns should be visible and `opaque-confidential` when support needs
customer-chosen names such as tool or client names). Missing or malformed column
comments deny access. Existing `--read-tables` deployments keep their
current behavior.

## Connection-level security

The details below describe **static table mode**. Annotation mode uses separate
process-specific roles, exact column grants, effective-grant audits (including
PostgreSQL `PUBLIC`), and coordinated refresh. Its bootstrap requirements and
role lifecycle are documented in [column access](docs/column-access.md).

`--connection-level-security` adds a second enforcement layer inside the database
itself. The DSN becomes a **bootstrap** connection used only to provision roles;
once that succeeds the bootstrap connection is closed and every tool call runs on
pools that authenticate as the provisioned roles. Even if a statement slipped past
the guard, the database would refuse anything outside the allowlist.

What the bootstrap DSN needs:

- Postgres: `CREATEROLE` (or superuser), and either ownership of the allowlisted
  tables and their schemas or the matching privileges `WITH GRANT OPTION`
  (`USAGE` on the schemas, `SELECT` on read tables, `SELECT/INSERT/UPDATE/DELETE`
  on write tables, `USAGE/SELECT` on the write tables' sequences). The role also
  needs `USAGE` on every schema it should be able to revoke from; schemas it
  cannot use are skipped.
- ClickHouse: `ACCESS MANAGEMENT` and the granted privileges `WITH GRANT OPTION`
  (the `default` user with `access_management=1` has both).

What gets created, on every boot and again on every `/readyz` probe until it
succeeds (the whole Postgres sequence runs in one transaction):

- Postgres `restrictedsql_ro` (`--security-role-prefix` changes the prefix):
  `LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION`, role-level
  `search_path = <default-schema>` and `statement_timeout = <flag>`; every table,
  sequence and schema privilege the bootstrap can address is revoked; then
  `USAGE` on the read tables' schemas and `SELECT` on the read tables.
- Postgres `restrictedsql_rw`, only with `--dangerously-add-write-tools`: the
  same hardening; `USAGE` on the schemas of read ∪ write, `SELECT` on read ∪
  write, `INSERT/UPDATE/DELETE` on the write tables, and `USAGE/SELECT` on the
  sequences the write tables depend on (serial, identity, and any sequence named
  in a column default). The write pool is used only by `begin_transaction`.
- ClickHouse `restrictedsql_ro`: `CREATE USER OR REPLACE ... IDENTIFIED WITH
  sha256_password` with `readonly = 1` pinned (`READONLY`) and the per-query
  limits the server sends (`max_execution_time`, `max_result_rows`,
  `result_overflow_mode`) allowed only up to the policy's caps
  (`CHANGEABLE_IN_READONLY`); `REVOKE ALL ON *.*`; `SELECT` on each read table;
  `SHOW TABLES` and `SHOW COLUMNS` on the read tables' databases; `SELECT` on
  `system.data_skipping_indices`. ClickHouse filters `system.databases`,
  `system.tables` and `system.columns` to what the user may see, so
  `list_schemas` and `list_objects` show only the databases that hold
  allowlisted tables and the tables in them.

Passwords are 32 random bytes generated per boot, held only in memory and never
logged; on Postgres they are sent as a SCRAM-SHA-256 verifier when
`password_encryption` is `scram-sha-256`, so the plaintext never appears in a
statement. Every boot rotates them, and every boot re-applies the revoke/grant
sequence, so a drifted grant is repaired and a stale password is replaced.
Because of that rotation, run a **single replica**: a second process would
rotate the first one's passwords out from under it. Role names must match
`^[a-z_][a-z0-9_]{0,59}$`.

Boot never fails because of provisioning. If it did not succeed, `/readyz`
answers 503 with `connection-level security not provisioned: <error>` (the
error names the statement that failed, with the password redacted) and every
tool returns the same message; each probe and each tool call retries. The
`info` log line `postgres roles provisioned` / `clickhouse user provisioned`
lists the roles and the tables they were granted.

Not covered: privileges granted to `PUBLIC` still apply to the provisioned
roles, and an existing role with the same name keeps any role memberships it
already had; grants that belong to other grantors cannot be revoked by the
bootstrap role.

## Multi-database mode

`--databases <regex>` serves several databases of one Postgres server from one
process, for example a main `app` database plus preview databases
`app_preview_pr_<N>` that come and go:

```sh
restrictedsql-mcp --dialect postgres --dsn postgres://bootstrap:…@host:5432/app \
  --read-tables 'app.*' --write-tables 'app.*' --dangerously-add-write-tools \
  --connection-level-security --databases '^app_preview_pr_[0-9]+$'
```

- The DSN's database is always served and is the default. The DSN must be URL-form
  and name its database. Further databases are those in `pg_database` that allow
  connections, are not templates, that the bootstrap role may `CONNECT` to, and
  whose name matches the regex (Go syntax, unanchored: use `^…$` for exact names).
- The read and metadata tools and `begin_transaction` take an optional
  `"database"` argument; omitted, they use the default database. `list_databases`
  (registered only with `--databases`) re-reads the database list and returns
  `{ "databases": [{ "name", "default", "open" }] }`. A name that is not served is
  rejected with `unknown database "<name>"` (after one re-read of the list).
- `execute_sql_write`, `commit_transaction` and `rollback_transaction` take no
  database: a transaction stays in the database it was begun in, and its
  statements are checked against that database's allowlist.
  `--max-open-txns` is shared by all databases.
- Each additional database is opened on first use: `--read-tables` /
  `--write-tables` are resolved again against that database (so `<schema>.*`
  expands to the tables it has when the database is opened; new tables need a
  restart or a re-created database), and with `--connection-level-security` it gets
  its own roles `<prefix>_<database>_ro` / `_rw` (roles are server-wide). Names that
  are not plain lowercase identifiers, or that would exceed the 63-byte limit, are
  sanitized, truncated and suffixed with a short hash. The default database keeps
  `<prefix>_ro` / `<prefix>_rw`. The bootstrap role needs the same privileges in
  every served database as in the default one. A failed open is reported to the
  calling tool and retried by the next call.
- When a served database disappears (a query or connection fails with
  `3D000`, `57P0x`, a connection exception or a broken connection and
  `pg_database` confirms it is gone, or it is missing when the list is re-read),
  its open transactions are rolled back, its pools closed and its roles dropped
  from the default database (logged as `roles of evicted database dropped`).
  Later calls get `unknown database`. A terminated connection to a database that
  still exists is not an eviction; the next call reconnects.
- `/readyz` checks the default database only. The column snapshots of the other
  open databases are reloaded every 30s and on each `list_databases` call.
- Logs of tool calls carry a `database` field.
- Not supported with ClickHouse or `--columns-from-annotations`. Pools are opened
  per database and kept until the database disappears or the process exits.

## Tools

All tools take and return JSON. Errors come back as MCP tool errors
(`isError: true`) with a stable message; rejections name the reason and the
offending node, table, function, or type so the agent can self-correct.

### Read tools (always registered)

With `--databases`, every read tool below also takes `"database"?: string`
(see "Multi-database mode").

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

In annotation mode, metadata comes from the catalog snapshot. Objects include
`access` with queryability, selectable columns and generation; columns include
tier, annotation status, selectability and denial reason. Discovery includes
closed application tables. Raw comments, defaults, index expressions and engine
connection definitions are omitted; PostgreSQL foreign-key relationships remain
available as structured column references.

**`explain_query`** — `{ "sql": string, "analyze"?: bool, "hypothetical_indexes"?: [{ "schema"?, "table", "columns": [string], "method"?: "btree"|"hash"|"gin"|"gist"|"brin" }] }`
The SQL goes through the same read-mode guard. Postgres runs
`EXPLAIN (FORMAT JSON, VERBOSE, COSTS[, ANALYZE, BUFFERS])` in a read-only
transaction; hypothetical indexes use the `hypopg` extension and the server builds
the `CREATE INDEX` text itself from the structured input (the table must be
read-allowlisted, columns must be plain identifiers). `analyze` and hypothetical
indexes are mutually exclusive. ClickHouse runs `EXPLAIN PLAN indexes=1` (or
`EXPLAIN PIPELINE` with `analyze`) and rejects hypothetical indexes. Returns
`{ "dialect", "plan": <json or text>, "notes"?: string }`.

### Database tool (Postgres only, registered only with `--databases`)

**`list_databases`** — `{}`
The database-level counterpart of `list_schemas`: lists the databases this server
serves, re-reading the database list on each call so new and dropped databases
show up. Returns `{ "databases": [{ "name", "default", "open" }] }`; `default`
marks the DSN's database (used when `"database"` is omitted), `open` whether the server already holds connections to it. Pass a
`name` as the `"database"` argument of the read tools, the metadata tools and
`begin_transaction`. Only served databases are listed: other databases on the
instance are not, and SQL cannot enumerate them because `pg_database` is not
read-allowlisted. See "Multi-database mode".

### Write tools (Postgres only, need `--dangerously-add-write-tools`)

Writes are only possible inside an explicit transaction so the agent can inspect
the effect before committing.

**`begin_transaction`** — `{}` → `{ "transaction_id", "expires_at" }`
Pins a dedicated connection. Fails once `--max-open-txns` is reached. With
`--databases` it takes `"database"?: string` and also returns `"database"`.

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
make test       # policy, admission, and SQL-binding tests
make e2e-up     # start the shared Postgres (with hypopg) and ClickHouse stack
make e2e        # e2e-up, then E2E=1 go test ./e2e/...
make e2e-pg     # only Postgres and common suites
make e2e-ch     # only ClickHouse and common suites
make e2e-annotations # column access, grants, reload, and migration suites
```

Unit tests cover annotation parsing, binding, canonicalization, expansion limits,
and admission invalidation under refresh failures. Run them with the race
detector using `go test -race ./internal/... ./cmd/...`.

The e2e suite builds the real binary once, boots it as a
subprocess per test with the flags under test, waits for `/readyz`, and drives it
with the go-sdk MCP client over Streamable HTTP. Subprocess logs (debug level) are
printed on failure. Without `E2E=1` the package exits immediately so
`go test ./...` stays fast.

Annotation fixtures contain synthetic safe, PII, content, secret, restricted and
unannotated values. Tests cover both HTTP and stdio, hidden inputs in SQL clauses,
direct restricted credentials, schema changes, canceled in-flight results,
unsupported dependencies, and the existing SQL bypass corpus.

The compose stack binds Postgres to `127.0.0.1:55433` (55432 is often taken by
other local databases) and ClickHouse to `127.0.0.1:59000` (native) and
`127.0.0.1:58123` (HTTP). Override with `E2E_PG_PORT`, `E2E_CH_NATIVE_PORT`,
`E2E_CH_HTTP_PORT`, or point the tests at other databases with `E2E_PG_DSN` and
`E2E_CH_DSN`. The stack is shared between parallel work streams; `make e2e-down`
tears it down and should be run deliberately.

`E2E_CH_VERSION` selects the Compose ClickHouse image (default `25.8`). Column
access is also tested against the Speakeasy Control Plane's pinned `26.2.19.43`; use a separate Compose
project and ports when running that version beside the shared stack.

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
`TUNNEL_*` from a Secret, and no Service or Ingress. `/mcp` listens on loopback,
where only the in-process tunnel agent reaches it. Kubelet probes the pod IP,
not loopback, so `--health-listen 0.0.0.0:8081` serves `/healthz` and `/readyz`
alone on a second port; `/mcp` there is a 404.

Set `TUNNEL_GATEWAY_URL` and `TUNNEL_KEY` and pass `--tunnel` to expose the server
through the Speakeasy Control Plane. The agent dials out and proxies to `http://<listen>/mcp`; the
readiness body reports the tunnel state without gating on it.

### Tunnel-only mode

A loopback bind is not isolation: any process on the host (or any container in
the same pod) can reach `/mcp`. `--tunnel-only` closes that path. At boot the
server generates a 256-bit token that never leaves process memory, pins it on the
local URL the in-process tunnel agent proxies to (the agent merges that query
into every request it forwards), and refuses any `/mcp` request without it with
`401`. The token is stripped before the MCP handler sees the request, is not
logged, and cannot be obtained through the tunnel. `/healthz` and `/readyz`
stay open for probes; use `--health-listen` to probe from outside the pod
without exposing `/mcp`. `--transport stdio` needs none of this: only the parent
process holds the pipe.
