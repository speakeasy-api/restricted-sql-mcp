# Column access annotations

`--columns-from-annotations <classes>` enables read-only access to columns whose
`@access` class is in the comma-separated list, for example `confidential` or
`confidential,confidential-pii`. Every other class, and every missing or malformed marker, is
denied. The mode requires `--connection-level-security` and cannot be combined
with `--read-tables`, `--write-tables`, or write tools. Omit the annotation flag
to keep the existing static table policy.

## Classifying a column

The database owner defines the class vocabulary. Column classifications are
ordinary schema documentation that other tools (redaction, retention, exports,
reviews) can use too; this server only needs to know which classes a
deployment allows. Class names are lowercase words joined by single
hyphens, at most 63 characters.

Append exactly one access marker as the last nonempty line of its comment:

```sql
-- PostgreSQL
COMMENT ON COLUMN public.messages.id IS E'Message identifier\n@access: confidential';
COMMENT ON COLUMN public.messages.body IS '@access: opaque-restricted';
COMMENT ON COLUMN public.messages.email IS '@access: confidential-pii';

-- ClickHouse
ALTER TABLE app.messages COMMENT COLUMN id '@access: confidential';
ALTER TABLE app.messages COMMENT COLUMN body '@access: opaque-restricted';
```

In PostgreSQL use an actual newline in the comment or an `E'...\n...'` string
when preserving existing prose. Markers and class names are case-sensitive.
CRLF, horizontal whitespace around the marker, and trailing empty lines are
accepted. Duplicate markers, a marker mentioned mid-line, malformed class names, trailing prose, and missing
markers deny the column. A valid marker followed by an invalid marker is still
denied.

An example vocabulary (Gram's):

| Class | Meaning | Typical allowlist |
|---|---|---|
| `confidential` | Reviewed operational/organizational metadata | Allowed |
| `confidential-pii` | Reviewed identity/contact fields | Opt-in |
| `opaque-confidential` | Short identifiers and labels chosen outside the database owner, such as tool, client or span names | Opt-in |
| `secret-restricted` | Credentials, tokens, keys, cookies, credential hashes | Never |
| `restricted` | Known regulated or sensitive data, including PHI | Never |
| `opaque-restricted` | Arbitrary customer, user or model content that may hold restricted data | Never |

Only list classes whose every column is fit to expose: the allowlist is the
only thing that decides readability.

Values in `opaque-*` columns were chosen by someone outside the database owner.
The type is known, the contents are not. Results go to an LLM, so allowing
`opaque-confidential` lets those values reach the model: an agent should treat
them as untrusted text, not instructions.

Permissions apply to the whole column, including JSON, array and map contents.
Column names are not classification evidence. No table, schema, or database
comment supplies an inherited default. The server enforces annotations; it does
not decide whether a producer's data is safe or lint your migration source.

## Query behavior

Every column reference must be selectable, including WHERE/PREWHERE, joins,
GROUP BY/HAVING, ordering, aggregate arguments/filters, windows, subqueries,
CTEs and lambda captures. Denied columns still participate in name resolution,
so a matching alias or outer column cannot silently override them.

```sql
SELECT id FROM messages;                       -- allowed with a safe id
SELECT count(*) FROM messages;                 -- counts rows without body access
SELECT count(*) FROM messages WHERE body='x';  -- rejected
SELECT * FROM messages;                        -- rejected even if all columns are safe
```

Use explicit projections. Whole rows, implicit projections, NATURAL JOIN and
wildcard expansion/modifiers are rejected. The only star exception is the
approved built-in `count(*)`; ClickHouse also supports `count()`. Counts are not
rewritten to `count(id)`: a nullable id must not change the result. A table must
have at least one selectable column for any query, including counts, existence
checks, and `SELECT 1 FROM table`. Completely closed tables have metadata only.
Counts and existence intentionally reveal cardinality of queryable tables.

PostgreSQL supports positional aliases, derived outputs, nonrecursive CTEs,
correlation/LATERAL, set operations, and modeled JOIN USING output semantics.
System columns, whole records, recursive CTEs, and unsupported bindings fail.
Functions and types are qualified to `pg_catalog`, and execution uses a
`pg_catalog` search path to prevent custom function/operator shadowing.
Name resolution follows PostgreSQL: non-LATERAL derived tables may reference
enclosing query levels; GROUP BY (including GROUPING SETS, ROLLUP and CUBE)
resolves this level's input columns, then output labels, then outer levels;
duplicate output labels are accepted only when their expressions are identical.

ClickHouse supports explicit joins, CTEs, scalar aliases, array indexing/ARRAY
JOIN and lexical lambda parameters. Ambiguous USING output needs qualification;
complex USING scopes should use ON. Correlated subqueries, nested expression
aliases, alias/source collisions except identity projections, FINAL/SAMPLE, and
unproven dotted subcolumn paths fail. Use supported functions on an allowed
parent column instead of a dotted path. Allowed functions are checked against
the engine's built-in function identities, including case-sensitivity rules.
Alias expansion and expression nesting have bounds. Expression aliases are
inlined with their original grouping and bound where they are defined; an
alias that a lambda parameter would capture is rejected. A relation alias may
not equal a column name (or a flattened `Nested` prefix) in scope, because
ClickHouse would read `alias.x` as a subcolumn of that column. Map literals
(`{'k': v}`) are rejected; use `map()`. EXISTS is not a ClickHouse function in
annotation mode; test existence with `count()` or `SELECT 1 FROM t LIMIT 1`.

EXPLAIN uses the same column guard and generation as SELECT. PostgreSQL
hypothetical-index columns must also be selectable. Writes remain unsupported.

## Supported catalog objects

PostgreSQL queryable objects are ordinary local stored tables without inheritance,
partitioning, row-level security, rewrite rules, or custom function/operator/access
method dependencies in indexes and constraints. Columns must have built-in
base or array types. PostgreSQL resolves casts and default encoding conversions
by type rather than by name, so a search path cannot exclude them: while a cast
between two built-in types, or a `pg_catalog` default conversion, uses a
function outside `pg_catalog`, refresh fails and the whole server stays
unavailable until it is removed. Extension casts that involve the extension's
own types (for example pgvector) are unaffected, because guarded SQL cannot
produce or name those types. Generated columns, custom types/domains, persisted views,
materialized views and foreign tables are denied until their dependencies can
be validated.

ClickHouse queryable engines are `MergeTree`, `Memory`, `Log`, `TinyLog`, and
`StripeLog`. Other engines, persisted views, and objects with row policies are
denied. Columns with DEFAULT, MATERIALIZED or ALIAS expressions are denied;
dynamic JSON/Object and aggregate-state types are unsupported. This conservative
surface prevents a safe output annotation from authorizing an unreviewed input.

PostgreSQL system/temp schemas and ClickHouse system/information schemas and
temporary tables are outside the application inventory. Unsupported application
tables and their denied columns remain discoverable.

## Metadata

`list_schemas`, `list_objects` and `get_object_details` read a fixed structural
projection of the privileged catalog snapshot. They do not execute caller SQL
on the bootstrap connection. Data roles need no extra global metadata grants.

Object `access` includes `generation`, `queryable`, `selectable_columns` and an
optional `denial_reason`. Each column's `access` includes `tier`,
`annotation_status`, `selectable` and an optional `denial_reason`. Column order,
names, types and nullability are retained. PostgreSQL constraints retain names,
kinds, participating columns and referenced foreign-key table/columns.

Raw comments/default expressions, view/index definitions, engine connection
expressions, sample values, query logs, and statistics containing data values
are omitted. All metadata permission labels come from the same generation.
This applies to the MCP tools. The provisioned data role itself can still read
PostgreSQL's global catalogs (comments, default expressions, function bodies,
view definitions) like any role; the SQL guard is what keeps those catalogs out
of reach of caller queries. ClickHouse is the same: the data user can read
`system.tables` DDL, including comments and defaults of denied columns, unless
the server sets `access_control_improvements.select_from_system_db_requires_grant`
(recommended). Keep sensitive values out of catalog text.

## Grants and refresh

The bootstrap credential must read the required global catalogs and manage
exclusive process roles. PostgreSQL needs CREATEROLE and authority to revoke
and grant schema USAGE and column SELECT throughout the application inventory;
ownership or appropriate GRANT OPTION is required. ClickHouse needs ACCESS
MANAGEMENT, the relevant catalog reads, and column SELECT WITH GRANT OPTION.
An insufficient bootstrap credential leaves data access unavailable.

Each process uses `<prefix>_a<random>_ro` (long prefixes are truncated). Passwords
remain in memory and stay stable across refresh. The process grants SELECT on
explicit columns only, with no table-wide or future-column grants. Effective
privilege audits reject excess PostgreSQL PUBLIC access, schema creation/ownership,
role memberships, table/write grants and column grant options; ClickHouse audits
the exact grants and absence of role memberships. The server does not remove
unrelated PUBLIC grants to make an audit pass.

ClickHouse pins `readonly=1`, `enable_analyzer=1`,
`prefer_column_name_to_alias=1`, and `optimize_functions_to_subcolumns=0`.
The latter avoids additional implicit subcolumn grants for operations such as
`count(nullable_id)`. Caller SETTINGS remain prohibited. Every verification
checks that these four settings are still pinned as immutable on the process
user and that no settings profile is inherited; drift closes access.

At boot, every `--annotation-refresh-interval` (default 30s), and on `/readyz`,
the coordinator loads a catalog and checks grants. Refresh calls are coalesced
and bounded by `--annotation-refresh-timeout` (default 10s). An unchanged catalog
is audited without replacing pools or passwords. This also works over stdio.
A refresh runs independently of whoever triggered it: a probe that times out or
disconnects stops waiting and reports unready, but cannot cancel the refresh or
close admission. Probe-triggered refreshes reuse a result completed within the
last two seconds. `/readyz` should still be reachable only by the orchestrator.

On a change, admission closes; active operations are canceled and drained;
exact grants are reconciled; the catalog is rechecked; then the new immutable
generation and pool are published together. Canceled old results are suppressed.
Any load, grant, verification or drain failure closes tool admission and makes
readiness unhealthy until a complete refresh succeeds. Existing MCP sessions
cannot bypass that gate. Liveness remains available for diagnostics. An empty
selectable set is valid and serves metadata.

Graceful shutdown revokes and drops the process role. Crashes or database
outages can leave roles behind; operators should remove confirmed stale process
roles using the logged `read_role` names. Do not reuse roles across processes.

## Required migration procedure

New unannotated columns are denied immediately, before and after refresh, because
both SQL binding and grants use explicit columns. Adding a column never inherits
the table's permissions.

Polling does **not** make changes to an already allowed field instantaneous.
For restrictive reclassification, rename/name reuse, changed type/definition, or
changed meaning (including a new sensitive JSON key):

1. Stop and drain **all** MCP instances before the migration or sensitive writes.
2. Apply the schema/annotation change and review the entire column's semantics.
3. Restart every instance; verify readiness, metadata labels, and column grants.
4. Reopen access only after those checks succeed.

A rolling deployment or comment-only update with live traffic does not provide
this guarantee. Persisted view/computed-column support requires a separate
dependency validation design.

## Verification and diagnostics

`make e2e-annotations` exercises synthetic annotated fixtures on real PostgreSQL
and ClickHouse servers, including SQL binding, direct column privileges, refresh
failure/recovery, migration changes, in-flight cancellation and stdio. The full
`make e2e` suite also retains static-mode coverage. Compose supports
`E2E_CH_VERSION` for the 25.8 and Gram 26.2.19.43 version checks.
Run annotation suites sequentially against each database instance: their DDL
fixtures change the global catalog and deliberately affect refresh admission.

Inspect a PostgreSQL binding without a database:

```sh
go run ./cmd/sqlguard-check --tiers safe \
  --columns 'messages=id:safe,body:content' \
  'SELECT count(*) FROM messages'
```

For richer fixtures, pass `--tiers safe --catalog <policy.Catalog JSON>`.
ClickHouse fixtures also need the built-in function maps when using functions;
an absent map denies them. These files are diagnostic inputs, not a substitute
for the runtime's database catalog.

An example fixture is in `cmd/sqlguard-check/testdata/annotations.json`:

```sh
go run ./cmd/sqlguard-check --dialect clickhouse --default-schema app \
  --tiers safe --catalog cmd/sqlguard-check/testdata/annotations.json \
  'SELECT count(*) FROM messages'
```
