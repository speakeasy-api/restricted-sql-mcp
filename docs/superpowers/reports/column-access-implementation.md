# Column access implementation verification

Implemented the restricted-sql-mcp portion of the
[validated plan](../plans/2026-09-23-gram-column-access-annotations.md) on
2026-09-24. Gram's application annotations, inventory, source lint, migrations
and deployment changes remain separate work. Runtime setup and limitations are
in [the column access guide](../../column-access.md).

## Delivered behavior

- Explicit, final-line column tiers; missing, malformed, duplicate and
  unselected annotations deny access. Only `safe` and `pii` are selectable.
- Read-only annotation configuration requiring connection-level security;
  existing static table and write modes remain available.
- Ordered catalog snapshots with PostgreSQL relation OID/attribute identity,
  ClickHouse table UUID/column identity, definitions and deterministic digests.
- Column binding before the existing syntax allowlists, followed by canonical
  SQL revalidation. Every expression input is checked, including aliases,
  CTEs, joins, positional renames, filters, windows and lambda captures.
- Explicit projection requirements, whole-row rejection, and correct built-in
  counts on tables with at least one selectable column. Nullable ClickHouse
  identifiers do not change `count(*)` semantics.
- Process-specific credentials with exact column grants and audits for broader
  effective access. PostgreSQL checks PUBLIC, memberships, ownership, write
  privileges and grant options; ClickHouse checks the exact grants and roles.
- Per-operation admission leases, periodic and readiness-triggered refresh,
  cancellation/draining, suppression of old results, and failure/recovery
  that gates existing sessions. Unchanged catalogs keep their pools/passwords.
- Global structural metadata, classification and denial labels, and PostgreSQL
  foreign-key relationships. Raw comment/default and engine expressions are
  omitted from discovery.
- Built-in function identity/name-resolution protections and conservative
  rejection of unsupported relation, type, policy and execution dependencies.
- Offline diagnostic flags and a catalog fixture for `sqlguard-check`.

## Verification

| Check | Result |
|---|---|
| Full e2e suite, PostgreSQL 17.10 and ClickHouse 25.8.33.6 | PASS: 100 top-level tests, 436 including subtests; no skips; 80.457s |
| ClickHouse and annotation suites with ClickHouse 26.2.19.43 | PASS: 38 top-level tests, 140 including subtests; no skips; 21.024s |
| `go test -race ./internal/... ./cmd/...` | PASS |
| `make build vet` | PASS |
| PostgreSQL and ClickHouse offline guard diagnostics | PASS |
| Metadata fixtures with sensitive comment/default literals and discovery outside the default schema | PASS on both ClickHouse versions and PostgreSQL |
| `git diff --check` | PASS |

The 16 new top-level annotation suites use synthetic fixtures and exercise
HTTP and stdio, safe/PII selection, denied tiers and malformed markers,
all-closed tables, view/computed-column denial, SQL scope adversaries, direct
database credentials, PUBLIC/write privilege drift, function/operator shadowing,
refresh failure/recovery, in-flight cancellation, newly added columns,
stop–migrate–restart changes, and the existing SQL bypass corpus. Standalone
guard tests ensure database privileges cannot mask binding failures. Admission
unit tests include drain timeout and stale-result suppression.

The first full run exposed a pre-existing test assumption that timestamps are
serialized in UTC; that one test now explicitly runs its server with `TZ=UTC`.
Overlapping verification runs initially changed the same global PostgreSQL
catalog and correctly triggered refresh failures. Final runs were sequential;
annotation suites must not run concurrently against the same database instance.

## Boundaries retained

Annotations classify entire columns; the runtime cannot prove their business
meaning. New unannotated columns are denied immediately, but restrictive or
meaning-changing migrations require stopping/draining every MCP instance before
the change or sensitive writes, then restarting and verifying grants/readiness.
Polling alone does not make live reclassification atomic.

Persisted views, external/distributed engines, unsupported computed columns,
RLS/row policies and unvalidated custom execution dependencies remain denied.
Read-only annotation mode does not enable write tools. Counts require at least
one selectable column; there is no separate count-only permission. Crashes or
database outages can leave process roles requiring operator cleanup.

No application data classification or Gram deployment was changed by this work.

## Follow-up hardening (2026-09-25)

An independent review pass of the implementation led to three changes:

- **PostgreSQL casts and default conversions.** These are resolved by type,
  so the `pg_catalog` search path cannot exclude them. The catalog loader now
  fails refresh while a cast between two built-in types, or a `pg_catalog`
  default conversion, uses a function outside `pg_catalog`; the server stays
  unavailable until it is removed. Extension casts on extension types, such as
  pgvector's 23 casts in Gram's database, are ignored because guarded SQL cannot
  reach them.
- **Refresh lifecycle.** Refreshes run detached from their trigger, bounded by
  the gate lifetime and refresh timeout. A readiness probe that times out or
  disconnects stops waiting without cancelling the refresh or closing
  admission. Probe-triggered refreshes reuse a result under two seconds old.
  A refresh's own timeout still fails closed.
- **PostgreSQL name resolution.** Non-LATERAL derived tables see enclosing
  query levels; GROUP BY (with GROUPING SETS/ROLLUP/CUBE and implicit rows)
  resolves local inputs, then output labels, then outer levels; identical
  duplicate output labels are accepted. Each accepted form was run on
  PostgreSQL 17, and adjacent forms that would resolve to denied columns are
  covered as rejections.

| Check | Result |
|---|---|
| Full e2e suite, PostgreSQL 17.10 and ClickHouse 25.8.33.6 | PASS: 104 top-level tests, sequential |
| ClickHouse annotation suites on 26.2.19.43 | PASS: 4 tests |
| New e2e tests against the pre-change gate and loader | FAIL as expected: 3 of 3 |
| `go build`, `go vet`, race-enabled unit tests | PASS |

E2E helpers that expect a probe to observe a schema change now wait out the
probe rate limit first and join a refresh that outlives one probe.

## Second independent review (2026-09-25)

Fresh Claude and Codex sessions reviewed commit 90f2b50 in isolated clones
with their own PostgreSQL 17 and ClickHouse (25.8, 26.2) containers. Neither
returned a denied value through MCP. Codex ran a 141-case differential corpus
(78 denied-column cases) through the binder, the provisioned role directly,
canonical SQL and MCP; every denied case was refused by both layers.

Fixed:

- **PostgreSQL JOIN USING types.** Merged USING columns kept the left or right
  input expression, losing PostgreSQL's common type (integer vs bigint keys
  overflowed). The bare merged reference is now preserved.
- **PostgreSQL duplicate labels.** Identical compound expressions were
  compared with source offsets and rejected; offsets are now ignored.
- **ClickHouse relation aliases.** An alias equal to a column name made the
  binder check column `x` while ClickHouse read subcolumn `alias.x` of a denied
  column; only the grants stopped it. Such aliases are now rejected.
- **ClickHouse map literals.** Map values were not walked by the binder; map
  literals are now rejected in annotation mode.
- **ClickHouse alias inlining.** Inlined aliases lost grouping
  (`k * 2` with `k = id + 1`) and could be captured by lambda parameters. They
  are now parenthesised, bound in their defining scope, and capture is refused.
- **ClickHouse settings drift.** Verification now checks that the binder's
  pinned settings remain immutable on the process user and no settings
  profile is inherited.
- **Test harness.** Pausing PostgreSQL requires an explicit container name
  for non-default ports.

Documented: ClickHouse data users can read `system.tables` DDL unless
`select_from_system_db_requires_grant` is enabled; `EXISTS` is unavailable on
ClickHouse in annotation mode.

The reviewers' regression tests are in the repository: the PostgreSQL
differential corpus (`internal/sqlguard/testdata/postgres_resolution_review.json`,
unit and e2e runners) and ClickHouse binder tests.

| Check | Result |
|---|---|
| Full e2e suite, PostgreSQL 17.10 and ClickHouse 25.8.33.6 | PASS: 107 top-level tests, sequential, no skips |
| ClickHouse annotation suites on 26.2.19.43 | PASS: 6 tests |
| PostgreSQL differential corpus (unit and e2e) | PASS: 141 cases |
| `go build`, `go vet`, race-enabled unit tests | PASS |
