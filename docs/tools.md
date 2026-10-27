# Tool reference

The HTTP transport is stateless (MCP 2026-07-28): no `Mcp-Session-Id`, nothing
kept per client between requests; see [docs/connection-model.md](connection-model.md).
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
marks the DSN's database (used when `"database"` is omitted), `open` whether the server has opened it (provisioned roles, created pools);
connections are made on demand and closed after a minute unused. Pass a
`name` as the `"database"` argument of the read tools, the metadata tools and
`begin_transaction`. Only served databases are listed: other databases on the
instance are not, and SQL cannot enumerate them because `pg_database` is not
read-allowlisted. See "Multi-database mode".

### Write tools (Postgres only, need `--dangerously-add-write-tools`)

Writes are only possible inside an explicit transaction so the agent can inspect
the effect before committing.

**`begin_transaction`** — `{}` → `{ "transaction_id", "expires_at", "ends_at" }`
Pins a dedicated connection. Fails once `--max-open-txns` is reached.
`expires_at` is when it is rolled back if left idle (each call pushes it back);
`ends_at` is when it is rolled back however busy (`--txn-max-lifetime`). With
`--databases` it takes `"database"?: string` and also returns `"database"`.

**`execute_sql_write`** — `{ "transaction_id", "sql", "max_rows"? }`
Accepts INSERT / UPDATE / DELETE (RETURNING allowed) whose target is
write-allowlisted, and SELECT over read ∪ write tables. Source tables of
INSERT…SELECT, UPDATE…FROM, DELETE…USING, and subqueries must be in read ∪ write.
Returns `{ "rows_affected", "columns", "rows", "row_count", "truncated", "duration_ms" }`.
An error leaves the transaction aborted, as Postgres does; roll it back.

**`commit_transaction`** / **`rollback_transaction`** — `{ "transaction_id" }` → `{ "status" }`
Release the connection. Unknown or expired ids return an error.

Transactions idle longer than `--txn-idle-timeout`, or older than
`--txn-max-lifetime`, are rolled back by a reaper and their id is invalidated.
Postgres's `idle_in_transaction_session_timeout` (idle timeout plus 30s) is set on
each transaction as a backstop. Transactions are process-local, so run one replica.
See [docs/connection-model.md](connection-model.md).

### Transaction workflow example

```
begin_transaction        {}                                   → {"transaction_id":"…","expires_at":"…","ends_at":"…"}
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
