# Stream A report — Postgres guard, backend, e2e

Branch: `stream-a-postgres` (pushed after every task). Merged `origin/stream-c-server`
twice (harness, then boot wiring) so the suites run through the real binary.

## Done

| Task | Commit | Files |
|---|---|---|
| A1 Postgres guard | `feat(pgguard): postgres AST guard with deparse` | `internal/sqlguard/postgres/{guard,nodes}.go`, `cmd/sqlguard-check/main.go` |
| A2 Postgres backend | `feat(pgbackend): pgx backend, catalog introspection, transactions` + `fix(pgbackend): report COMMIT of an aborted transaction as an error` | `internal/db/postgres/{backend,catalog,tx}.go` |
| A3 e2e + wiring | `test(e2e): postgres read, metadata, explain and write suites`, `feat: wire postgres guard and backend into boot` | `e2e/postgres_{read,meta,explain,write}_test.go`, postgres branch of `cmd/restrictedsql-mcp/main.go` |

`gofmt -l .` empty, `go vet ./...` clean, no `TODO`s, dependencies limited to the plan's list.

## What passes

`E2E=1 go test ./e2e -run 'Postgres|Common' -count=1` against the shared Docker stack
(Postgres on `127.0.0.1:55433`, stream C's default). All 36 tests pass, wall time ~11s:

- Read: basic, truncation, server row cap, join+aggregate, window+CTE, value types
  (numeric/timestamptz/jsonb/array/date/null), positive corpus, bypass corpus
  (common + postgres), write verbs rejected in read mode, 24 adversarial rejections and
  18 adversarial acceptances, statement timeout (`canceling statement`), unlisted table,
  schema-qualified allowlist with a non-public `--default-schema`.
- Metadata: `list_schemas`, `list_objects` (table/view/sequence/extension/all/unknown
  schema/bad type), `get_object_details` (columns, pk+fk, index with size, comment, view,
  not found).
- Explain: plain JSON plan, analyze (actual rows + buffers), hypopg single and composite
  hypothetical indexes with no leak into the next session, mutually exclusive,
  non-allowlisted table, injection in a column name, bad method, guarded SQL.
- Write: rollback, commit (verified from a second read-only server), policy (12 rejections
  + `bypassCorpusWritePostgres` + 11 acceptances inside one transaction), aborted
  transaction (`current transaction is aborted`, commit reports the abort), unknown id,
  max-open-txns, idle reaper, row cap on RETURNING, write tools absent without flag.
- Stream C's `TestCommon*` and `TestPostgres*` smoke tests (boot flags, healthz/readyz,
  readyz 503 on missing table and unreachable DB, tool lists).

Before wiring, every spec §6 entry (common + postgres + write) and a 40-statement positive
corpus were also verified with `cmd/sqlguard-check`.

## Unrun

Nothing of stream A is unrun. `make e2e` as a whole was not run because the ClickHouse
suites belong to stream B and its guard/backend are not on `origin` yet; the clickhouse
branch of the dialect switch still uses stream C's stubs.

## Contract deviations

None to `internal/policy/policy.go`, `internal/sqlguard/guard.go`, `internal/db/backend.go`.

Additive changes:
- `internal/policy/functions_postgres.go`: added `similar_to_escape` and `like_escape`,
  the internal functions the parser emits for `SIMILAR TO` and `LIKE ... ESCAPE`.
- `pgguard.NewWithLogger(*slog.Logger)` alongside the planned `New()`, so the boot
  wiring can pass the JSON logger without touching anything outside the postgres branch.

Plan corrections:
- hypopg's function is `hypopg_create_index(text)`, not `hypopg_create_hypothetical_index`.
  The "not installed" detection keys on SQLSTATE 42883 for that name.
- The e2e Postgres port is 55433 (stream C's compose/Makefile default), not 55432, which
  is occupied by an unrelated local container.

## Decisions worth knowing

Guard:
- Trailing content: a `;` terminator followed by anything but whitespace (a comment, an
  empty statement) is rejected, which is what makes the spec's
  `SELECT ... /* c */ ; --` corpus entry fail. A bare trailing `;` is accepted.
- Every accepted statement is deparsed and then re-parsed and re-validated; tables and
  kind must match. This is why `SELECT (ARRAY[1,2,3])[1]` is rejected: pg_query deparses
  it to `ARRAY[1, 2, 3][1]`, which does not re-parse. Fail closed; column subscripts work.
- Operators are allowlisted (arithmetic, comparison, pattern, JSON, array, text-search);
  `OPERATOR(schema.op)` is rejected. Function and type names must be exactly lowercase,
  so a quoted `"Count"` cannot resolve to a user-defined function whose lowercase spelling
  is allowlisted.
- `SQLValueFunction`: date/time keywords allowed; `current_user`, `session_user`,
  `current_role`, `current_schema`, `current_catalog`, `user` rejected as introspection.
- CTE scoping follows Postgres: non-recursive CTE names are visible to later CTEs and the
  body, `RECURSIVE` makes all visible; mutation targets never resolve to CTEs. A CTE may
  shadow an allowlisted or forbidden table name (its body is validated).
- Data-modifying CTEs are allowed only in write mode. CTE `SEARCH`/`CYCLE`, `COLLATE`,
  XML, SQL/JSON constructors, `TABLESAMPLE`, `ROWS FROM`, bind parameters are rejected.
- `A_Expr` kinds other than op/any/all/distinct/nullif/in/like/ilike/similar/between are
  rejected by kind name.

Backend:
- Pool: `MaxConns` raised to at least 16 (write transactions pin connections),
  `MinConns` 0, no connect at boot; a 3s boot ping only logs a warning.
- `SET LOCAL statement_timeout` / `search_path` run as literal statements built from boot
  config only (`pgx.Identifier.Sanitize` for the schema).
- Values: numerics as strings (`"10.00"`), times RFC3339Nano, uuid text, bytea as `\x..`,
  intervals/times via their `driver.Valuer`, arrays and json recursively.
- `RowsAffected` for SELECT is Postgres's row count from the command tag.
- hypopg indexes are session-scoped; `hypopg_reset()` runs on the bare connection after
  the transaction is rolled back so nothing leaks into the pool even if a create fails.
- `COMMIT` on an aborted transaction returns a `ROLLBACK` tag without an error; the
  backend turns that into an error so the agent is not told "committed".
- `list_objects` returns `size_bytes` for everything except plain views; `row_estimate`
  only for tables/partitioned/materialized when `reltuples >= 0`.
- `TablesExist` accepts tables, views, materialized views, partitioned and foreign tables.

## Open issues / notes for the R1 adversarial review

- Functions are matched by name only; resolution still goes through `search_path`
  (`pg_catalog` first, then the pinned default schema). A user-defined function in the
  default schema with an allowlisted name and a signature that beats the builtin could be
  reached. Mitigations: the deployment's restricted DB role (spec §10), or forcing
  `pg_catalog.` qualification on deparse (would break extension functions such as
  `uuid_generate_v4`). Same class: composite field-call notation `o.f` for functions
  taking a row type; nothing dangerous found in the allowlist but worth a look.
- `pg_typeof`, `txid_current`, `random` are in the committed allowlist; harmless but
  introspective.
- Deparser gaps in pg_query are turned into rejections by the re-validation pass, not
  silently accepted; if agents hit one, the error names the re-parse failure.
- go.mod merges with stream C conflicted twice on `go.mod`/`go.sum` (both branches added
  deps); resolved by keeping ours and `go mod tidy`, which also pulled stream C's gram
  dependency. Stream C should expect the same when merging back.
- GitHub SSH was intermittently unreachable during this session; every push eventually
  succeeded and `origin/stream-a-postgres` is at the final commit.
