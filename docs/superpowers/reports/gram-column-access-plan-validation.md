# Codex validation of the Gram column-access plan

Reviewed the v2 draft at MCP commit `4ba0fa8`, the existing implementation, and
Gram source at `55298d2bfef31ee337e6f5281f00359a1e109a7f`. Continued the unfinished
validation requested in Claude session `1e8a498f-32c1-415c-b8c2-3bc78ec90bd0`.

**Verdict:** the column-level approach fits the requested migration protection,
but v2 had gaps that needed correction before implementation. The
[revised plan](../plans/2026-09-23-gram-column-access-annotations.md) addresses
them as implementation requirements. This is design validation, not a claim
that the feature or its security acceptance tests are implemented.

The subsequent runtime implementation and completed checks are recorded in
[the implementation report](column-access-implementation.md). The findings below
describe the pre-implementation review.

## Findings and corrections

1. **Initial annotation could expose sensitive data.** V2 inferred `safe` from
   table tiers and generic names/types, including JSON metadata/config and names
   in otherwise sensitive tables. An explicit annotation produced by an unsafe
   heuristic is still unsafe. V3 makes these review suggestions only, requires
   explicit allowed-tier decisions, and adds `restricted` for PHI/SSNs and other
   data that must not become selectable through `safe,pii`.

2. **Readiness did not provide an enforcement boundary.**
   [health.go](../../../internal/health/health.go) returns before column refresh
   when its static table list is empty. Annotation mode deliberately has no such
   list. [gate.go](../../../internal/dbsec/gate.go) stops provisioning once its
   backend exists; it cannot reconcile changed grants. Readiness failure alone
   does not block existing MCP/tunnel calls. V3 adds a coordinator, one immutable
   generation per operation, gated admission, exact grant reconciliation and
   periodic refresh independent of HTTP probes.

3. **Polling could not deliver immediate revocation.** A comment change can
   leave a formerly allowed field accessible until refresh; already-running
   queries may finish under the old policy. Same-name object replacement and
   changes to existing column contents/definitions are also different from
   adding an unannotated column. V3 explicitly requires stopping/draining the
   deployment before restrictive or meaning-changing migrations. New columns
   remain denied without waiting for refresh. The plan no longer conflates these
   guarantees or treats a post-migration readiness probe as synchronization.

4. **Names and renamed outputs were insufficient provenance.**
   [columns.go](../../../internal/sqlguard/postgres/columns.go) currently stores
   names and applies positional aliases to those names. With base columns
   `(id, hidden)`, `FROM t AS x(hidden, id)` makes `x.id` refer to `hidden`.
   V3 requires original identities/ordinals and lineage through aliases, joins,
   CTEs and set operations. It also separates clause-specific output aliases,
   merged USING columns, and lexical lambda scopes from base name lookup.
   ClickHouse alias substitution depends on settings, so a blanket alias-first
   rule is insufficient. [ClickHouse syntax](https://clickhouse.com/docs/reference/syntax)

5. **Stored views could expose hidden base columns.** A view can rename a hidden
   column to a permitted-looking output, and default PostgreSQL views use the
   owner's base-table privileges. A restricted-role probe reproduced this.
   V3 keeps unvalidated persisted views and indirect execution paths closed;
   support requires dependency and execution-identity checks. An annotation on
   the output is not a substitute for those checks.
   [PostgreSQL CREATE VIEW](https://www.postgresql.org/docs/18/sql-createview.html)

6. **Column grants needed effective-privilege verification.** Removing a grant
   from one role does not remove access inherited through PUBLIC or membership;
   table-level SELECT also authorizes columns regardless of individual column
   grants. V3 requires exact and effective-grant checks, without changing
   unrelated application permissions. It also retains guard-level wildcard
   rejection: database grants permit a wildcard when every column is allowed.
   [PostgreSQL GRANT](https://www.postgresql.org/docs/18/sql-grant.html)

7. **Counts had a version-specific engine edge case.** Row counts worked with
   one permitted-column grant on both test databases. However, ClickHouse's
   nullable-column optimization asked for an additional `id.null` privilege for
   `count(id)`. Disabling `optimize_functions_to_subcolumns` fixed the probe.
   V3 pins that setting for the initial supported configuration and requires
   versioned engine coverage; it never replaces count(*) with count(nullable_id)
   or broadens to table grants. The optimization is documented by ClickHouse.
   [ClickHouse count](https://clickhouse.com/docs/reference/functions/aggregate-functions/count)

8. **The global metadata surface needed a defined projection.** Existing
   [Postgres](../../../internal/db/postgres/catalog.go) and
   [ClickHouse](../../../internal/db/clickhouse/catalog.go) metadata handlers
   return comments/default expressions, which can contain sensitive literals.
   V3 keeps global structural discovery while reviewing/sanitizing those fields.
   Hypothetical-index inputs in
   [tools_read.go](../../../internal/mcpserver/tools_read.go) currently check
   table permission and identifier syntax only; they need column authorization.

9. **Write semantics and built-in resolution were underspecified.** Column
   selection does not define the safety of DELETE, triggers/defaults, constraint
   errors, or long-lived write transactions. The first annotation release is
   read-only, with static write behavior preserved. The existing documented
   routine/operator shadowing risk also remains a prerequisite: neither column
   grants nor function names alone constrain privileged/custom execution paths.

10. **Schema inventory and migration integration needed stronger checks.** A
    regex over CREATE blocks misses inferred view columns and other SQL shapes.
    V3 requires SQL-aware inventory plus scratch-catalog parity. Gram's inspected
    ClickHouse diff task generates both migration formats and materialized-column
    Go output; `atlas.hcl` includes `schema.sql` and `mart.sql`. V3 includes those
    artifacts and requires actual comment round trips, including unsupported
    object-kind handling.

## Database probes performed

Used existing MCP e2e containers, synthetic rows, and temporary probe objects.
Postgres schema/role changes were rolled back in one transaction. ClickHouse
database/user objects were removed in cleanup. No application rows were read.

| Engine | Probe | Observed result |
|---|---|---|
| PostgreSQL 17.10 | SELECT(id) only; count(*) and count(1), two rows, one NULL id | Both returned 2 |
| PostgreSQL 17.10 | Same fixture; count(id) | Returned 1 |
| PostgreSQL 17.10 | Hidden column, wildcard, positional alias to hidden | All denied by column privileges |
| PostgreSQL 17.10 | Owner-created view selecting hidden AS id; grant SELECT(id) on view | Returned the synthetic hidden sentinel |
| PostgreSQL 17.10 | REVOKE ALL on table after explicit column grant | has_column_privilege(id, SELECT) became false |
| ClickHouse 25.8.33.6 | SELECT(id) only; count(*) with metadata optimization enabled and disabled | Both returned 2 |
| ClickHouse 25.8.33.6 | count(1); count(*) WHERE id=1 | Returned 2 and 1 respectively |
| ClickHouse 25.8.33.6 | Hidden column and wildcard | Both denied |
| ClickHouse 25.8.33.6 | count(nullable id), default settings | ACCESS_DENIED requesting SELECT(id.null) |
| ClickHouse 25.8.33.6 | Same count with optimize_functions_to_subcolumns=0 | Returned 1 |

Core PostgreSQL reproduction (inside a transaction with a temporary schema/role):

```sql
CREATE TABLE probe.rows (id integer, hidden text);
INSERT INTO probe.rows VALUES (1, 'synthetic-hidden'), (NULL, 'synthetic-hidden');
GRANT SELECT(id) ON probe.rows TO probe_role;
CREATE VIEW probe.masked AS SELECT hidden AS id FROM probe.rows;
GRANT SELECT(id) ON probe.masked TO probe_role;
-- As probe_role, with USAGE on probe:
SELECT count(*), count(id) FROM probe.rows; -- 2, 1
SELECT x.id FROM probe.rows AS x(hidden, id); -- denied
SELECT id FROM probe.masked; -- synthetic-hidden: owner-view privilege path
```

Core ClickHouse reproduction:

```sql
CREATE TABLE probe.rows (id Nullable(UInt64), hidden UInt8)
ENGINE=MergeTree ORDER BY tuple();
INSERT INTO probe.rows VALUES (1,9), (NULL,8);
GRANT SELECT(id) ON probe.rows TO probe_user;
-- As probe_user on the inspected 25.8.33.6 server:
SELECT count(*) FROM probe.rows; -- 2
SELECT count(id) FROM probe.rows; -- requests SELECT(id.null)
SELECT count(id) FROM probe.rows SETTINGS optimize_functions_to_subcolumns=0; -- 1
```

## Limits and remaining validation

These probes validate database behavior underlying the plan; they do not test a
column-aware MCP implementation. Gram's inspected Atlas engine is pinned to
ClickHouse 26.2.19.43, newer than the MCP e2e image, so repeat the engine/comment
checks there and on actual deployment versions before rollout. Atlas comment
round trips were not run, and no production column classification was approved.

The revised plan's acceptance matrix still requires implementation tests for
binding, aliases, catalog/grant races, startup/reload failure, direct-role access,
metadata sanitization, and the existing routine/operator risk. This turn changed
documentation only; no application code, migrations, commits, or remote writes
were performed. Markdown whitespace and local document links were checked.
