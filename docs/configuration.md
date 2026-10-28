# Configuration reference

Run these commands from the repository root.

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
  --txn-max-lifetime 5m                  (write txn auto-rollback this long after begin, however busy)
  --max-open-txns 8                      (process-wide; each open txn pins one connection)
  --pool-max-conns 16                    (read connections to the default database)
  --database-pool-max-conns 4            (read connections to each further --databases database)
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
  `--databases` with an invalid regex, on ClickHouse, or with `--columns-from-annotations`,
  `--health-listen` with stdio or equal to `--listen`, and a zero or negative
  `--txn-max-lifetime`, `--pool-max-conns` or `--database-pool-max-conns`.
  The pool flags override any `pool_max_conns` in the DSN.
- `GET /healthz` reports liveness: 200 once the process serves, independently of
  database availability or schema contents.
- `GET /readyz` reports readiness: 200 when the database answers a ping, security
  provisioning has succeeded (if enabled), and the column metadata refresh
  succeeds. Otherwise it returns 503 with `{"ready":false,"reason":"..."}` and
  retries on the next probe. Once security setup succeeds, missing, dropped or
  renamed tables affect queries using those tables, not readiness of the whole
  server. An unreachable database
  or a provisioning failure remains unready without terminating the process.
- Readiness refreshes column metadata, so surviving tables pick up added,
  dropped and renamed columns. Wildcard expansion and provisioned grants remain
  startup snapshots: restart to include new wildcard tables or grant access to
  recreated tables. Renamed tables must also match the configured allowlist.
  Explicitly configured tables that were absent during provisioning receive
  their grants when a metadata refresh discovers them; passwords and open
  transactions stay unchanged. Refresh runs on readiness probes for the default
  database and on periodic/list-databases refresh for additional databases.
  Schema changes do not automatically broaden the configured access policy.
- Postgres tool queries describe their result on every execution rather than
  caching prepared statement shapes. Repeating `SELECT *` after a column
  migration therefore uses the current column names and types. This costs one
  additional database round trip per tool query.
- The readiness body carries `"tunnel":"disabled|connecting|connected|stopped"`,
  which does not gate readiness. `--health-listen` exposes only the two fixed
  probe endpoints on a separate listener; it never exposes `/mcp`.
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
role lifecycle are documented in [column access](column-access.md).

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
succeeds (the whole Postgres sequence runs in one transaction). Each Postgres
attempt intersects the configured allowlist with the current catalog, omitting
deleted tables and their sequence grants. Present tables still require the
bootstrap's grant permissions. Connecting MCP clients reuse these roles rather
than provisioning per user. Missing configured table names are logged and
retried during metadata refresh; permission errors on newly appearing tables
remain errors and are retried until their bootstrap grants are repaired.

The provisioned roles are:

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
