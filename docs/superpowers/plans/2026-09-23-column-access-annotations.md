# Speakeasy Control Plane column access annotations — validated plan (v3)

Supersedes the 2026-09-21 table-level draft and the unvalidated v2 column draft.
Repos: `speakeasy-api/gram` (annotations, lint, export) and
`speakeasy-api/restricted-sql-mcp` (catalog snapshots and enforcement).

Status: the restricted-sql-mcp runtime and e2e implementation is now present;
The Speakeasy Control Plane's application annotations, inventory, migrations, lint and rollout remain
separate work. See [the runtime guide](../../column-access.md) for the implemented
surface and operational requirements.
Implementation and test evidence are recorded in
[the implementation report](../reports/column-access-implementation.md).
Codex validation, probes, and remaining implementation checks are recorded in
[the validation report](../reports/column-access-plan-validation.md).
The Speakeasy Control Plane schema and migration tasks were inspected at
`55298d2bfef31ee337e6f5281f00359a1e109a7f`; rebase classifications against the
actual implementation revision. That snapshot has 227 Postgres CREATE objects,
40 ClickHouse schema objects (including 9 materialized views), and one additional
object in `server/clickhouse/mart.sql`.

## Goal and security contract

Every application column has an explicit access annotation. The server snapshots
column identities and permissions, and accepts SQL only when every referenced
column is permitted. Adding a column never grants access by inheritance.
Schema discovery remains global through dedicated metadata tools.

- Default tier selection: `safe`. The Speakeasy Control Plane can opt into `safe,pii` to include reviewed
  identity fields such as email. This does not include PHI or arbitrary personal
  data merely because the deployment opted into email.
- Unknown, missing, invalid, duplicate, or unselected annotations deny access.
  No table, schema, or database default can promote a new column to `safe`.
- Check all uses of a column: projection, predicates, joins, grouping, ordering,
  aggregate arguments/filters, windows, subqueries, and expressions. A query
  returning only a count must not filter on a forbidden column.
- Reject projection wildcards, whole rows, implicit column sets, and constructs
  whose binding cannot be proved. Permit only the built-in row-count exception
  `count(*)` (and ClickHouse `count()`). `count(secret)` remains forbidden.
- `SELECT count(*) FROM chat_messages` can work with a reviewed safe `id` grant,
  while message bodies stay inaccessible. Relations with no permitted columns
  remain discoverable but cannot be queried, even for counts or `SELECT 1`.
  A count-only permission for completely closed relations is a separate feature;
  do not manufacture a safe column or a table-wide grant to enable it.
- The promise concerns SQL access and data returned to the client. It is not a
  promise that database storage reads never touch a page containing other data.
  Counts and existence reveal row cardinality; they are intentionally allowed
  on queryable relations, without hidden-column predicates.

The annotation deployment requires connection-level column grants as well as the
AST guard. The bootstrap credential is never used for caller-supplied queries.
The existing static `--read-tables` mode retains its current behavior.

## Format and annotation decisions

Append one final line to each column's existing comment:

```text
@access: safe
```

| Tier | Meaning | Runtime selection |
|---|---|---|
| `safe` | Reviewed organizational/operational metadata | Default |
| `pii` | Reviewed identity/contact data, such as email or name | Explicit opt-in |
| `content` | User/LLM content and derivatives: messages, summaries, embeddings, tool inputs/outputs | Never |
| `secret` | Credentials, tokens, keys, cookies, hashes/encrypted credentials | Never |
| `restricted` | Other sensitive data, including PHI, SSNs, or mixed/uncertain payloads | Never |

Parse by lines: normalize CRLF; count **all** lines beginning with `@access:`
(after horizontal whitespace), including malformed markers. Require exactly one,
as the last nonempty line, matching
`^[\t ]*@access:[\t ]*(safe|pii|content|secret|restricted)[\t ]*$`.
A valid marker plus an unknown marker is invalid, not one valid match.
Keep `access` fixed; no custom-key flag in phase 1.

Annotate every application table/view/materialized-view column. Table comments
remain prose; lint rejects table-level markers. System, temporary, and internal
engine objects are outside the classification inventory and never implicitly
become queryable. Unsupported application objects still appear in metadata.

```sql
-- Illustrative columns; the inventory determines actual Speakeasy Control Plane column names.
COMMENT ON COLUMN public.chat_messages.id IS '@access: safe';
COMMENT ON COLUMN public.chat_messages.content IS '@access: content';
COMMENT ON COLUMN public.chat_messages.user_email IS '@access: pii';
COMMENT ON COLUMN public.chat_messages.ssn IS '@access: restricted';
```

ClickHouse uses inline column `COMMENT` clauses in the declarative schema.
Preserve existing prose and let the migration workflow generate the DDL.

**No automatic public classification.** The old table lists and column-name
heuristics are review aids only. A field called `metadata`, `config`, `name`,
`*_id`, or `*_at` is not evidence that its values are safe. Mixed JSON, arrays,
free text, logs, and configuration can contain messages or credentials. A column
is exposed as a whole; access to a JSON key is not a separate permission.
Unreviewed columns remain denied and block completion of the initial inventory.
Every promotion to `safe` or `pii` needs an explicit decision based on producers,
consumers, and stored semantics. Tokens billed and authentication tokens must
not be confused by name matching. Org-authored text is not automatically safe.

## Snapshot and migration lifecycle

One immutable catalog generation contains every application's relation identity,
kind/engine, ordered columns, original column identities, types, annotation
status, and effective permissions. Include relevant definition/dependency
fingerprints and a deterministic digest. PostgreSQL identity includes relation
OID and attribute number; ClickHouse includes table UUID where available and
ordered column/definition fingerprints. Never authorize by an alias name.

A request acquires one generation and uses it for parsing, binding, canonical SQL,
the server's independent permission check, execution, and response release.
Publishing another generation must not make a request mix old and new decisions.
A map of names alone loses both order and identity and is insufficient.

Startup and reload use a shared coordinator:

1. Close data-query admission. Load and validate a complete catalog candidate
   through fixed catalog queries; never fall back to table-level access.
2. For a change, drain or cancel old-generation operations before publication;
   suppress responses from canceled operations. If draining fails, remain closed.
3. Reconcile **exact** column grants, including revocations and effective-grant
   verification. PostgreSQL updates are transactional; ClickHouse updates keep
   admission closed across all DDL steps. A partial failure never publishes.
4. Publish the immutable catalog and matching grant generation together, then
   reopen admission. A catalog/grant failure makes data tools unavailable and
   readiness unhealthy until a complete retry succeeds.

Do not implement this as an atomic pointer swap plus `/readyz` returning 503:
existing MCP sessions and the tunnel can still send calls. Gate every data tool,
including EXPLAIN, and cover HTTP and stdio. Boot failure can leave health serving
for diagnostics/retry, but data access stays closed.

Provide a bounded periodic refresh, coalesced with an explicit readiness-triggered
refresh, so stdio and deployments without readiness polling also converge.
Unchanged digests do not rotate passwords or rebuild pools. Remove the current
health check's early return when the static table list is empty.

**Migration guarantee:** new unannotated columns are denied before and after
refresh by explicit bindings and explicit grants. However, polling cannot make a
comment change, a column rename/reuse, a changed view/computed definition, or a
semantic change to an existing allowed field instantly atomic with live queries.
For restrictive or meaning-changing migrations, stop/drain the MCP deployment
before applying the migration or writing sensitive values, then restart/reload
and verify grants before reopening. Document this as the initial deployment
protocol, not an optional refinement. Comment-only reclassification without that
protocol takes effect after successful refresh and is not instantaneous.

## Part G — Speakeasy Control Plane repository

### G1: Convention and migration workflow

Create `server/database/ACCESS_TIERS.md` and link it from the schema docs.
Document tiers, whole-column semantics, counts, unsupported object kinds, and
new-column/reclassification checklists. New columns require explicit comments;
existing-column meaning changes require both a classification review and the
migration protocol above. A newly added JSON key can change a column's meaning
without adding a SQL column, so the same review applies.

### G2: Inventory and explicit decisions

Create a seed/inventory task under `.mise-tasks/db/` and annotate
`server/database/schema.sql`. It may propose denied tiers and highlight likely
identity fields, but must not write inferred `safe`/`pii` decisions. Preserve
comments and identify objects with correctly quoted schema/table/column names.
Track unresolved decisions separately; do not invent a valid runtime tier such
as `unreviewed`. Review allowed columns across **all** tables, including those
previously described as safe. Historical table classifications are not approval.

Generate Postgres migrations and hashes with the existing tasks, inspect that
the annotation migration contains comment changes only, and apply to a fresh
local database. The task declares a positional migration name:
`mise run db:diff column-access-tiers`; confirm CLI usage on the target revision.

### G3: ClickHouse annotations and generated artifacts

Annotate `server/clickhouse/schema.sql` and `server/clickhouse/mart.sql`; the
inspected `server/atlas.hcl` combines both in each ClickHouse environment and
pins its development engine to 26.2.19.43. Our current MCP e2e engine is 25.8,
so grant/comment probes must also run on the Speakeasy Control Plane's pinned version before rollout.
Classify materialized-view output independently of its source/target: transforms
can change sensitivity. Include generated/materialized/alias columns in inventory;
a selected tier alone does not make an unsupported computed column queryable.

Run `mise run clickhouse:diff column-access-tiers`. The inspected task generates
both Atlas and golang-migrate variants and runs `clickhouse:gen-materialized-cols`.
Review both migration formats, their hashes, and generated Go output. Confirm
comment DDL support for each object kind on the deployed engine version; if a
view column cannot carry a comment, keep it denied and record the unsupported
kind rather than silently inheriting a target's annotation.

### G4: Lint and structured export

Create `.mise-tasks/lint/access-tiers.mts`, `.mise-tasks/db/access-tiers.mts`, and
`server/database/access-tiers.json`; wire lint into `.github/workflows/pr.yaml`
next to migration lint. Use an SQL-aware parser and catalog verification, not a
regex over CREATE blocks. Views can infer columns without declaring a column
list; quoted identifiers, generated columns, nested types and ALTER statements
must also be represented. Where source parsing cannot prove the shape, build an
ephemeral database from schema/migrations and inspect its catalog; no production
rows are needed. Unknown syntax must fail the check.

Lint fails on missing/duplicate/invalid markers, table-level markers, stale
export, or unaccounted application columns. Export a versioned deterministic
JSON inventory with dialect, qualified relation, kind, ordered columns, type,
tier, and annotation status. Generated review-only rationale can live beside the
export; runtime policy reads database comments, not that file.

CI applies migrations to scratch databases and compares live inventory to the
source/export. Include table additions, view outputs, inherited/partition
columns, and generated columns. Engine-created objects must be explicitly
excluded by kind/ownership, not accidentally omitted. A dropped comment on a
recreated column must be detected.

### G5: Deployment

Use `--columns-from-annotations safe --connection-level-security --tunnel
--tunnel-only` (or `safe,pii` after the identity-field review), plus existing DSN
and tunnel configuration. Record the migration stop/drain/reload protocol in
infra/runbooks. Keep single-owner role provisioning; replicas must not race over
shared role credentials or grants. Prove the chosen role prefix is exclusive.

## Part R — restricted SQL MCP repository

### R0: Supported surface and prerequisites

The first annotation release is read-only. Reject annotation mode combined with
`--write-tables` or `--dangerously-add-write-tools`; static write mode remains
available with its existing contract. Column reads do not define safe DELETE,
triggers, defaults, constraint errors, or write-transaction revocation. Add those
only under a separate write-security plan.

Start with supported local stored table columns. Query-time CTEs/subqueries are
supported when their full inputs and bindings can be checked. Persisted views,
foreign/external tables, distributed engines, and query-time computed/alias
columns remain metadata-only until dependency and execution-identity checks are
implemented. A view's own `safe` annotation is not proof that its definition
cannot read a hidden base column. Materialized/stored outputs require review of
their value semantics and proof that reads do not evaluate unapproved inputs.
Reject an unsupported relation even for `count(*)`.

Retain fail-closed function/type/operator checks. Close the documented
user-defined-function/operator shadowing path before declaring this mode ready
for the Speakeasy Control Plane: bind approved built-ins by resolved identity and trusted signatures,
qualify where sufficient, and reject unresolved overloads, custom types/casts,
or SECURITY DEFINER execution paths. Column grants do not constrain arbitrary
privileged routines. Include implicit engine policies/expressions in the trusted
schema review; unsupported execution dependencies must remain denied.

### R1: Catalog API and coordinator

Modify `internal/policy/policy.go`, `internal/db/backend.go`, both backends,
`internal/health/health.go`, `internal/dbsec/gate.go`, and server boot wiring.
Add annotation parsing and dialect catalog loaders.

Use a `CatalogSnapshot` with ordered `Column` records and lookup indexes, not
`map[TableRef]map[string]Tier`. Track annotation status separately from tier,
and distinguish relation queryability from column readability. Expose a captured
snapshot handle to the guard; `Checked` includes its generation, relation/column
identities, and referenced read columns. AllTables/readiness must use the dynamic
inventory in annotation mode instead of the static `ReadTables` map.

Postgres loads `pg_attribute`, `pg_class`, `pg_namespace`, and `pg_description`
with object identity, attribute order, type, kind, generated status and relevant
dependencies. Exclude dropped/system/temp columns from queryable inventory.
ClickHouse loads `system.columns` plus table UUID, engine and relevant definition
metadata from `system.tables`, with explicit ordering by column position.
Include unannotated columns so binding cannot mistakenly fall through to an
outer relation or an alias. Catalog loading must work before data grants exist;
use a dedicated fixed-query metadata path if restricted-role visibility is
insufficient. No arbitrary SQL runs on that path.

Implement the lifecycle above. Replace one-time `EnsureProvisioned` semantics
with grant-generation reconciliation; do not reuse boot-time password rotation
for every refresh. Serialize refreshes and publish only complete snapshots.

### R2: Configuration

Add `--columns-from-annotations <tiers>` with a nonempty subset of `safe,pii`.
Reject unknown/denied tiers, static read tables, write flags, or absence of
`--connection-level-security` in annotation mode. Add bounded refresh settings
with positive validated durations. Preserve static-mode flag requirements.
Document unknown/unsupported columns as denied, including during catalog failure.

### R3: Postgres binding and canonicalization

Extend `internal/sqlguard/postgres/{columns,nodes,guard}.go`,
`internal/sqlguard/guard.go`, and `internal/mcpserver/server.go`.

- Preserve base-column provenance and ordinals through relation aliases,
  positional alias lists, CTE output renames, joins, and set-operation branches.
  `FROM t AS x(secret, id)` can rename the original `secret` to `id`; checking
  the alias string against the base catalog would authorize the wrong column.
- Resolve qualified and unqualified names in the correct SQL scope, respecting
  LATERAL visibility and correlation. Denied columns participate in name lookup
  before authorization. Reject duplicate/unknown/ambiguous bindings.
- Validate every derived input before exposing outputs. Track lineage in joined
  and derived output slots. `USING` checks both input columns and has a merged
  output binding, including FULL JOIN coalescing. Reject unsupported forms until
  modeled; a join alias is not automatically a safe derived relation.
- Handle output aliases and ordinal references with clause-specific rules:
  ORDER BY and GROUP BY cannot share a generic alias-first resolver. Reject
  unsupported collisions; qualify canonical base references to preserve the
  chosen binding without changing merged-join or output-alias semantics.
- Reject `*`, `rel.*`, whole-row values, composite star expansion, NATURAL JOIN,
  and implicit projections. The only star exemption is the approved built-in
  `count(*)` aggregate, with FILTER/window inputs still checked. Set operations
  and VALUES require their own validation; an empty AST target list in those
  structures is not the same as a projection-free leaf SELECT.
- Reject system columns and unprovable recursion/record shapes. Validate
  EXPLAIN through the same generation and column path; hypothetical-index
  column names must be permitted too. Canonical SQL is the only executed SQL.

Add catalog fixtures to `cmd/sqlguard-check` so these bindings can be inspected
without connecting to a real database.

### R4: ClickHouse binding and engine settings

Add `internal/sqlguard/clickhouse/columns.go` and extend its walker/guard.
Cover PREWHERE, WHERE, JOIN, ARRAY JOIN, GROUP BY, HAVING, ORDER BY, LIMIT BY,
windows, CTEs, scalar aliases and lexical lambda bindings. Validate lambda bodies;
a lambda parameter is local but a captured identifier can be a hidden column.
Reject wildcard matchers/modifiers (`COLUMNS`, EXCEPT/REPLACE/APPLY), whole rows,
virtual/system subcolumns, and unknown expansion forms.

Pin analyzer and name-resolution settings supported by the deployed version.
Do not assume universal alias-first resolution: reject alias/column collisions
or prove and canonicalize their exact binding. Keep caller SETTINGS forbidden.
Treat subcolumns as dependent on the classified parent; allowing a JSON/map/tuple
column allows its contents as a unit, and hidden parents cannot be bypassed with
a path expression. Initially reject shapes whose parent cannot be proven.

Allow built-in `count()` and `count(*)` without rewriting to `count(id)` (nullable
ids change results). Probe access with real restricted credentials. Pin
`optimize_functions_to_subcolumns=0` for the initial supported version: the
validation probe found that `count(nullable_id)` otherwise required an additional
`id.null` grant despite `SELECT(id)`. Do not broaden to table-wide grants to work
around engine optimizations; add versioned regression coverage.

### R5: Exact column grants and admission

Postgres grants `USAGE` on required schemas and `SELECT (c1, c2, ...)` on each
queryable relation, without table-level SELECT or future-column defaults.
ClickHouse grants `SELECT(c1, c2, ...)` with only the metadata visibility needed
for dedicated tools. Neither data role owns the relations or inherits broader
rights. Verify effective grants, including PUBLIC/default roles, role membership,
existing table grants, and schema ownership; fail closed if excess privileges
cannot be removed within the provisioner's authority. Do not modify unrelated
application roles to make the audit pass.

Revoke obsolete grants as part of every changed generation, including columns
removed/re-tiered or renamed and objects replaced under the same name. Verify
actual privileges before publication. An all-permitted table can still satisfy
`SELECT *` at the database layer; the AST guard must always reject that syntax.

`count(*)` worked with a single column grant in the inspected Postgres 17.10 and
ClickHouse 25.8.33.6 fixtures. Test the deployed versions, engines and settings;
never silently broaden permissions if another shape fails.

### R6: Global metadata without unrestricted catalog SQL

Extend `ColumnDetail` with tier, annotation status, selectable, and denial reason;
objects show their queryability and selectable-column count. Names, types,
nullability and structural relationships remain visible across application
schemas, including closed tables. Use the same catalog generation for permission
labels and expose its version to make reload state inspectable.

Expose a fixed structural projection. Do not return sample rows, histograms,
query logs, raw connection/engine definitions, or secret-bearing default/comment
literals through global discovery. Existing metadata handlers return default
expressions and prose comments: review and omit/sanitize these in annotation mode.
Catalog/metadata tables are never automatically added to arbitrary SQL access.
Preserve static-mode output compatibility.

### R7: Verification matrix

Use synthetic sensitive sentinels and both guard-only and real-database checks.
These are implementation acceptance checks, not claims that the feature exists.

| Area | Required evidence |
|---|---|
| Tier parsing | Missing, malformed, duplicate, mixed valid/invalid, CRLF and trailing prose cases deny; only explicit safe/opt-in pii permit |
| Explicit access | Qualified/unqualified safe selections work; hidden columns fail in every expression/clause, even when absent from output |
| Counts | count(*)/count()/count(1) work on eligible relations; count(hidden), hidden predicates, and zero-permitted-column relations fail; NULL semantics preserved |
| Expansion | Star, qualified/composite star, whole rows, NATURAL and ClickHouse matchers fail, including on all-safe tables |
| Binding | Positional aliases, duplicate outputs, shadowing, correlated/LATERAL references, USING/FULL JOIN, unions, output aliases/ordinals, lambdas and nested subcolumns |
| Indirect access | View renaming hidden to safe, changed definitions, computed aliases, external engines and privileged/custom routine paths fail until explicitly supported |
| New migration | Add an unannotated PHI column while serving; deny immediately before refresh and afterward, by name, aliases and expansion attempts; safe existing queries remain valid |
| Reclassification | Stop/drain, re-tier/rename/drop-recreate/type-change, reload; old references and grants cannot survive; do not claim an uncontrolled comment change revokes instantly |
| Lifecycle | Cold catalog failure, empty static list, stdio refresh, concurrent requests, cancellation, stale-generation result suppression, partial grant failure/retry and unchanged reload |
| Direct grants | Connect as restricted role; safe columns/counts work, hidden and newly added columns fail; extra PUBLIC/membership grants are detected |
| Metadata/EXPLAIN | Discover closed schemas/columns without values or credential literals; EXPLAIN and hypothetical indexes obey column policy |
| ClickHouse | Nullable-count optimization fixture, pinned analyzer settings, supported engines and subcolumn paths; no permission broadening workaround |
| Compatibility | Existing static suite unchanged; annotation corpus has explicit separate expectations (wildcards differ) |

### R8: Adversarial validation

After implementation, review each resolver against the actual database's
binding rules and attack every new supported AST shape. Require reproducible
regressions for any bypass and run races between catalog/grant publication and
queries. Test both privilege enforcement and guard rejection; a guard mistake
hidden by a database permission error still needs fixing.

### R9: Documentation and rollout

Update README, design spec and deploy examples with the actual supported surface,
read-only annotation scope, metadata fields, failure behavior and migration
protocol. First run against Speakeasy Control Plane scratch databases, compare every exported column
to live metadata, and verify permitted queries with restricted credentials.
Roll out only after the acceptance matrix and the column-classification review
are complete. Do not claim table comments or names alone establish safety.

## Implementation order

1. Agree the contract above; build G1/G4 inventory and prove comment round trips
   for the targeted versions/object kinds.
2. Make explicit G2/G3 classification decisions; generate/review migrations.
3. Implement R0 prerequisites and R1/R2 snapshot/lifecycle/configuration.
4. Implement R3/R4 binding, R5 grants and R6 metadata on the shared generation.
5. Run R7/R8 and Speakeasy Control Plane integration, then G5/R9 rollout documentation.

The initial seed review and support for complex derived/engine objects are the
largest work items. It is acceptable to keep unsupported shapes denied while
supporting explicit safe columns and counts on ordinary tables. It is not
acceptable to approximate binding, infer allowed tiers, retain stale grants
while serving, or hide a weakened guarantee behind a successful readiness probe.
