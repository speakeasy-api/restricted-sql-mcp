# Stream B report — ClickHouse guard, backend, e2e

Branch: `stream-b-clickhouse`. Tasks B1, B2, B3 from
`docs/superpowers/plans/2026-09-14-restricted-sql-mcp.md`.

## Done

### B1 — ClickHouse guard (`internal/sqlguard/clickhouse/`)

- `guard.go`: `New() sqlguard.Guard`; parses with
  `parser.NewParser(raw).ParseStmts()`, requires exactly one statement, walks it
  with a fail-closed visitor, deparses with `parser.Format` after rewriting every
  `TableIdentifier` to `database.table`. Panics inside the parser or walker are
  recovered and turned into a rejection.
- `nodes.go`: explicit type switch over every AST node reachable from a SELECT;
  the default case rejects with the node type name. Rules implemented:
  SELECT only (INSERT/ALTER/CREATE/DROP/... rejected as "only SELECT statements
  are allowed"); `SETTINGS` and `FORMAT` rejected at any nesting depth; `SAMPLE`
  rejected; `FINAL`, `PREWHERE`, `ARRAY JOIN`, all join kinds, `LIMIT ... BY`,
  `WITH TOTALS/ROLLUP/CUBE`, `WITH FILL`/`INTERPOLATE`, window definitions and
  frames, `TOP`, `DISTINCT ON` allowed; table functions rejected wherever they
  appear (FROM, JOIN); bind parameters (`?`, `{x:T}`) rejected; functions checked
  against `policy.AllowedFunction` including inside lambdas and `* APPLY(f)`;
  `* EXCEPT/REPLACE` allowed; casts (`CAST(x AS T)`, `x::T`, `CAST(x, 'T')`)
  checked against `policy.AllowedCastType` after unwrapping
  `Nullable/LowCardinality/Array/...` recursively (`types.go`).
- Relation resolution: unqualified names resolve to `Policy.DefaultSchema`;
  names matching a CTE in scope are left unqualified; everything else must pass
  `CanRead` and gets `Database` set so the deparsed SQL is fully qualified.
- `cmd/sqlguard-check/main.go` created with the ClickHouse dialect wired and a
  Postgres placeholder that prints "postgres guard not merged yet". Stream A has
  since pushed its own version of this file; the primary needs to merge the two
  (keep A's Postgres branch, add the `chguard.New()` case from mine).

### B2 — ClickHouse backend (`internal/db/clickhouse/`)

- `backend.go`: `New(ctx, dsn, pol, logger)` via `clickhouse.ParseDSN` +
  `clickhouse.Open` (native protocol, lazy dial; a failed boot-time ping only
  logs a warning). `Query` runs with `readonly=1`, `max_execution_time`,
  `max_result_rows=maxRows+1`, `result_overflow_mode=break`, reads at most
  `maxRows` rows and sets `Truncated`. Values are scanned into the driver's
  natural types and normalised for JSON (times → RFC3339, Decimal/UUID/IP/
  big ints → strings, nested arrays/maps/tuples recursively). `Explain` runs
  `EXPLAIN PLAN indexes = 1` or `EXPLAIN PIPELINE` (analyze) and returns the
  text. `TablesExist` diffs against `system.tables`.
- `catalog.go`: `ListSchemas` (system.databases), `ListObjects` (system.tables
  with engine → table/view/materialized_view/dictionary mapping;
  sequence/extension return empty), `ObjectDetails` (system.tables +
  system.columns + system.data_skipping_indices; "object not found: db.name").
- Verified against the live e2e ClickHouse: `INSERT` through `Query` fails with
  "Cannot execute query in readonly mode"; a 13-way cross join is killed by the
  server at 1.0s with "Timeout exceeded" when `StatementTimeout=1s`.

### B3 — ClickHouse e2e (`e2e/clickhouse_{read,meta,explain}_test.go`)

16 tests: `TestClickHouseReadBasic`, `ReadTruncation`, `ReadJoinAndAggregate`
(`uniq`, `toStartOfDay`), `ReadPositiveCorpus`, `BypassCorpus` (common +
clickhouse), `ReadRejectsWriteVerbs`, `ReadStatementTimeout`,
`ReadOnlyWhenTableNotReadable`, `ReadQualifiedNamesAndCTEs`, `ListSchemas`,
`ListObjects`, `ObjectDetails`, `ExplainPlan`, `ExplainAnalyze`,
`ExplainHypotheticalIndexUnsupported`, `ExplainRejectsBypass`.
`TestClickHouseWriteFlagRejectedAtBoot` already exists in stream C's
`smoke_test.go`, so it is not duplicated.

## What passes

- `cmd/sqlguard-check --dialect clickhouse` over the full spec §6 corpus: all 43
  bypass entries rejected (many via parse error, see below), all positive
  entries accepted with `app.<table>` qualification. ~110 additional adversarial
  probes (table functions in JOIN, `IN <table>`, `GLOBAL IN`, `SETTINGS`/`FORMAT`
  in subqueries, lambdas calling `sleep`, `* APPLY(sleep)`, `Object('json')`
  casts, CTE shadowing, alias shadowing, quoted identifiers, trailing comments)
  behave as intended.
- `gofmt -l .` clean, `go vet ./...` clean, `go mod tidy` clean with only the
  planned direct dependencies (parser, clickhouse-go, go-sdk after the stream C
  merge).
- All 20 `-run ClickHouse` e2e tests (my 16 + stream C's 4 smoke tests) pass
  against the real binary and MCP client, using a temporary local wiring of
  `cmd/restrictedsql-mcp/main.go` (chguard + chbackend + mcpserver + minimal
  /healthz,/readyz). That wiring was not committed.

## Unrun / pending

- The e2e suites have not been run against stream C's final `main.go`: at the
  time of writing `origin/stream-c-server` has C1–C4 (config, harness, txn
  registry, mcpserver + stubs) but not C5 (health, tunnel, boot wiring), so there
  is no dialect switch to add the clickhouse branch to. Once C5 lands, wire
  `chguard.New()` and `chbackend.New(ctx, cfg.DSN, pol, logger)` into the
  clickhouse case and run `make e2e-ch`; the tests are expected to pass unchanged
  given the run above.
- `go test ./...` without `E2E=1` skips everything (by design).

## Contract deviations

- None to `internal/policy/policy.go`, `internal/sqlguard/guard.go`,
  `internal/db/backend.go`.
- `internal/policy/functions_clickhouse.go` extended (allowed by the plan):
  function `exists` (the parser represents `WHERE EXISTS (SELECT ...)` as a
  function call) and SQL-standard cast aliases `int, integer, bigint, smallint,
  tinyint, float, double, real, numeric, dec, varchar, char, text, timestamp`
  (needed for `positiveCorpusCommon`'s `CAST(id AS varchar)` /
  `CAST(amount AS int)`).
- Parse failures are returned as `*sqlguard.RejectError` ("could not parse
  statement (...)") rather than a plain error, so every rejection's text
  contains "rejected" as the corpus tests assert. The `Guard` doc comment allows
  other error types but nothing depends on them.

## Decisions worth knowing

- Anything after the first top-level `;` (outside strings, quoted identifiers
  and comments) is rejected, including a trailing comment, so the spec §6 entry
  `SELECT * FROM allowed_orders /* comment */ ; --` is rejected. Comments inside
  or before the statement are fine and are dropped by deparse.
- `x IN identifier` / `NOT IN` / `GLOBAL IN` with a bare identifier or dotted
  path on the right is rejected: ClickHouse reads a table there.
- CTE names are visible in the query's own clauses and subqueries but not in
  set-operation branches (`UNION ALL` etc.), matching ClickHouse; a reference
  there is treated as a table and checked against the allowlist.
- `SELECT * APPLY(f)` requires `f` to be an allowlisted function (or a lambda
  whose body passes); `COLUMNS('regex')` is not allowlisted.
- Cast targets written as a string (`CAST(x, 'Nullable(Decimal(10, 2))')`) are
  validated by a small recursive type-string parser; numeric parameters are
  allowed, string parameters only as DateTime/DateTime64 timezones. Parenthesised
  `Tuple(...)` cast types are rejected (parser emits `NestedType`).
- clickhouse-go v2.48.0 replaces `max_execution_time` with `deadline+5s`
  whenever the query context carries a deadline (`context.go:queryOptions`).
  The backend therefore hands the driver a cancel-only context and enforces
  its own hard cutoff (`StatementTimeout + 5s`) with a timer, so the server-side
  limit is authoritative. Do not add `context.WithTimeout` around driver calls.
- `New` returns an error only for an unparsable DSN; an unreachable server is
  logged and left to `/readyz`.
- `TestClickHouseReadStatementTimeout` uses a 13-way cross join of
  `allowed_orders` (5^13 rows, ~2.8s); the plan's 10-way join completes in
  ~30ms on ClickHouse.
- Decimal values come back as strings without trailing zeros (`"25.5"`, `"10"`),
  which is how the driver's decimal type formats them.

## Open issues

- Parser gaps in `clickhouse-sql-parser` v0.5.6 surface as parse rejections:
  `ORDER BY ... NULLS LAST`, `COLLATE`, `LIMIT ... WITH TIES`, aggregate
  `FILTER (WHERE ...)`, `EXISTS (SELECT * ...)` (`SELECT 1` inside EXISTS parses),
  `INTO OUTFILE`. All are safe (rejected) but limit what an agent can write.
- `cmd/sqlguard-check/main.go` will conflict on merge with stream A's version.
- The e2e Postgres port in stream C's Makefile defaults to 55433 (not 55432 as in
  the task brief); ClickHouse ports match (59000 native, 58123 http).
