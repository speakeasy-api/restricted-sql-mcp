# Connection model

How restricted-sql-mcp opens, reuses and closes database connections, what
an MCP client holds, and how many Postgres connections a deployment can use.

## MCP clients hold nothing

The HTTP transport is stateless (MCP 2026-07-28): no `Mcp-Session-Id` is
issued or read, `GET` and `DELETE` on `/mcp` answer 405, and nothing is kept
per client between requests. Two hundred connected agents cost no more than
their in-flight requests. A request's context ends when its HTTP request
does, so a client that hangs up cancels its query.

The only state that outlives a request is an open write transaction,
addressed by its `transaction_id` (see below).

## Pools

Every database is reached through lazily connecting pgx pools. A pool opens
connections only when a call needs one, keeps none open at minimum, and closes
any connection unused for a minute (pgx checks once a minute).

| Pool | Size | Used by |
|---|---|---|
| read | `--pool-max-conns` (16) for the default database, `--database-pool-max-conns` (4) for each further `--databases` database | queries, explain, metadata tools |
| write | `--max-open-txns` (8); only with `--connection-level-security` and writes on | `begin_transaction` |
| probe | 1; default database only | `/readyz` and the column snapshot |

Without connection-level security there is no separate write pool: the read
pool gets `--max-open-txns` extra connections instead, so pinned transactions
never starve reads. Without write tools no transaction connections are
reserved at all.

The probe pool keeps readiness independent of load: when every read
connection is busy, `/readyz` still answers instead of timing out and taking
the pod out of service.

Short-lived single connections, closed as soon as they finish, are also made
for provisioning roles (`--connection-level-security`), expanding
`<schema>.*`, listing and checking databases (`--databases`), dropping the
roles of a dropped database, and annotation catalog loads.

## Calls

A read or metadata call acquires a read connection, runs in a `READ ONLY`
transaction with `statement_timeout` and a pinned `search_path`, always rolls
back, and releases the connection. When the pool is exhausted the call waits
for a connection until its deadline (`--statement-timeout` plus 15s) and then
fails with `acquire connection: context deadline exceeded`. A full pool slows
calls down; it never opens more connections.

## Transactions

`begin_transaction` pins one connection until `commit_transaction` or
`rollback_transaction`. Limits:

- At most `--max-open-txns` (8) are open in the whole process, across all
  databases. The next `begin_transaction` fails at once; it does not queue.
- A transaction idle longer than `--txn-idle-timeout` (2m) is rolled back.
- A transaction is rolled back `--txn-max-lifetime` (5m) after it began,
  however busy it is. `begin_transaction` returns both deadlines:
  `expires_at` (idle) and `ends_at` (lifetime).
- A reaper checks every quarter of the idle timeout and skips a transaction
  with a statement in flight, so the worst case is about the lifetime plus
  `--statement-timeout` plus one reaper interval. `execute_sql_write` also
  checks both deadlines before running.
- As a backstop, each transaction sets Postgres's
  `idle_in_transaction_session_timeout` to the idle timeout plus 30s, so the
  server ends the session itself if this process stops reaping.

A transaction is not tied to an MCP connection: the id is a 128-bit random
capability, and whoever holds it can use it until it ends. A client that
disconnects mid-transaction leaves it to the idle timeout. A cancelled
`begin_transaction` can open a transaction whose id the client never sees;
the idle timeout rolls it back.

On failure the connection is never returned dirty: a failed `COMMIT` is
followed by `ROLLBACK`, and pgx destroys any connection released while still
inside a transaction.

## Multiple databases (`--databases`)

Each further database is opened on first use: its policy is resolved, with
connection-level security its roles are provisioned, and its pools are
created. It stays open until the database is dropped, when its transactions
are rolled back, its pools closed and its roles dropped.

Open databases hold connections only while used. The column snapshot of each
open database is refreshed every 30s, but a database unused for 10 minutes is
skipped and refreshed on its next use instead, so its pools drain to zero
about a minute later.

## How many connections

Upper bound with all databases busy at once:

```
1 (probe) + P + T + p × N + transients
```

- `P` = `--pool-max-conns`, `p` = `--database-pool-max-conns`, `T` = `--max-open-txns`
- `N` = further databases in use at the same moment
- transients: one listing at a time, plus one bootstrap connection per
  database being opened concurrently

Write connections are bounded by `T` in total, not per database.

Example, defaults with connection-level security and writes on, a main
database and 30 preview databases:

| Situation | Connections |
|---|---|
| idle | 1 (the probe connection, kept open by readiness probes; plus 1 per preview used in the last 10 minutes) |
| main database busy | 1 + 16 + 8 = 25 |
| main and 5 previews busy | 25 + 5 × 4 = 45 |
| everything busy at once | 25 + 30 × 4 = 145 |

Size `--pool-max-conns` and `--database-pool-max-conns` against the server's
`max_connections`, minus what the application itself needs.
