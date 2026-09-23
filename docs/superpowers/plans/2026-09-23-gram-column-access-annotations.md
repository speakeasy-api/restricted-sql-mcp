# Gram column access annotations — plan (v2, column-level)

Date: 2026-09-23 (supersedes the 2026-09-21 table-level draft)
Repos: `speakeasy-api/gram` (annotations, generator, lint, export) and
`speakeasy-api/gram-restricted-sql-mcp` (reads annotations, enforces columns).

## Goal

Access is decided per **column**, never per table. Every column of every
table and view in gram carries an access tier next to its definition, migrated
with the schema, readable live from the database. The MCP server exposes only
columns whose tier is selected at boot, rejects every wildcard, and resolves
every column reference before the statement can run. Schema metadata (which
tables and columns exist, their types, tiers) is readable globally.

Consequences:
- A migration that adds a PHI column to a previously safe table cannot leak it:
  the column has no annotation, so it is not in the allowed set (runtime,
  fail closed) and CI refuses the migration until it is annotated (lint).
- Tables that were "content" or "secret" become partially usable:
  `SELECT count(*), date_trunc('day', created_at) FROM chat_messages GROUP BY 2`
  works because `id`, `chat_id`, `project_id`, `created_at`, token counts are
  `safe`; `content` is not selectable.
- Views are no longer needed to carve out subsets; they remain useful only for
  derived shapes.

## Options considered

Where the annotation lives — unchanged from v1: **structured comments**
(`COMMENT ON COLUMN` in Postgres, inline `COMMENT` in ClickHouse). Gram is
Atlas-declarative (`server/database/schema.sql`, `server/clickhouse/schema.sql`
are the source of truth; `mise run db:diff` / `mise run clickhouse:diff`
generate migrations), Atlas diffs comments, and both schemas already use column
comments (71 Postgres, 465 ClickHouse). A registry table would put ~3,000 rows
outside the declarative flow with no link to the column they describe.

Granularity — **column-level with no inheritance**. A table-level annotation
was considered as a default for unannotated columns; rejected because a new
column would inherit `safe`, which is exactly the migration hazard to close.
Table comments stay free prose (no `@access:` line at table level; the lint
rejects one there to avoid two sources of truth).

Wildcards — **rejected outright** (`*`, `t.*`, whole-row references
`to_json(t)` / `SELECT t FROM t`, `RETURNING *`, `NATURAL JOIN`, `SELECT`
without a target list). Expanding `*` to the allowed columns was considered;
rejected because a query's meaning would then change silently when tiers
change, and because the DB-level grants reject `*` anyway.

## Annotation format

One trailing line inside every column comment:

```
@access: <tier>
```

Regex: `(?m)^@access:\s*(safe|pii|content|secret)\s*$`, exactly one match per
column. Prose above it is optional. Table comments carry no `@access:` line.

| Tier | Meaning | Selectable by default |
|---|---|---|
| `safe` | ids, foreign keys, timestamps, status/enum, counts, sizes, org/project/config values, org-authored configuration text | yes |
| `pii` | user identity: email, name, phone, device owner, IP, external user ids that map to a person | opt-in |
| `content` | user or LLM message content and anything derived from it: bodies, summaries, embeddings, spans, telemetry bodies, tool inputs/outputs | never |
| `secret` | credentials, tokens, keys, cookies, signed or encrypted material, hashes of any of those | never |

Rules:
- Every column of every table, view and materialized view is annotated; the
  lint enforces exactly one line per column and none at table level.
- `content` and `secret` cannot be selected at boot; the server refuses the
  flag. They exist so the lint can require a decision for every column, and so
  the export documents why a column is closed.
- ClickHouse `*_mv` objects are annotated like their targets (Atlas needs the
  column list anyway); `*_staging` columns get the same tiers as the promoted
  table.
- The same tiers apply in write mode: `--write-tables` still names the tables
  an agent may mutate, and every column it writes or returns must be in the
  selected tiers. `content`/`secret` columns are never writable through the
  server.

Postgres example (`schema.sql`; Atlas emits the migration):

```sql
COMMENT ON COLUMN chat_messages.id IS '@access: safe';
COMMENT ON COLUMN chat_messages.chat_id IS '@access: safe';
COMMENT ON COLUMN chat_messages.created_at IS '@access: safe';
COMMENT ON COLUMN chat_messages.prompt_tokens IS 'Prompt tokens billed for this message.
@access: safe';
COMMENT ON COLUMN chat_messages.content IS 'Rendered message body.
@access: content';
COMMENT ON COLUMN chat_messages.ip_address IS '@access: pii';
```

ClickHouse example:

```sql
CREATE TABLE gram.agent_events (
    id UUID COMMENT 'Event id.
@access: safe',
    user_email String COMMENT '@access: pii',
    input_content String COMMENT '@access: content',
    ...
) ENGINE = ...
```

Precedence in the MCP server: annotation mode (`--columns-from-annotations`)
and static mode (`--read-tables`) are mutually exclusive per boot. Static mode
keeps today's table-level behaviour for databases without annotations (e2e
fixtures, third-party users). Annotation mode is the gram deployment.

---

# Part G — gram repository

### G1: Convention doc

**Files:** create `server/database/ACCESS_TIERS.md`; link from the schema
README (`grep -rl "schema.sql" server/*.md docs/`).

- Tier table, regex, "one line per column, none per table", how tiers map to
  runtime behaviour (selectable / count-only / closed), how to run the lint and
  the export, and the checklist for adding a column: schema.sql column +
  comment → `mise run db:diff --name <x>` → `mise run lint:access-tiers`.

### G2: Generator for the initial Postgres annotations

**Files:** create `.mise-tasks/db/access-tiers/seed.mts` (one-off, kept for
re-runs on new tables); modify `server/database/schema.sql`; generated
`server/migrations/<ts>_column-access-tiers.sql` + `atlas.sum`.

- Input: the table-level tiering in the appendix plus column-name rules.
  Output: a `COMMENT ON COLUMN` per column, appended to an existing comment
  when one exists.
- Rules, first match wins:
  1. Column name matches `(^|_)(email|phone|ip_address|user_name|full_name|
     first_name|last_name|owner_email|assignee_email|requester_email|
     actor_email|upstream_email|alert_email)$` → `pii`.
  2. Name matches `(secret|token|password|api_key|apikey|credential|
     encrypted|_hash$|private_key|bearer|cookie|session_key|authorization_code|
     refresh_token|access_token|signing|marketplace_token|lease_token|
     claim_token|challenge_token)` → `secret`.
  3. Name matches `(^|_)(content|content_raw|body|payload|prompt|completion|
     transcript|summary|spans|embedding|normalized_payload_json|
     source_payload_json|result_payload|message|input|output|arguments|
     system_prompt|user_message|confirm_prompt)($|_)` → `content`, except in
     tables tiered `safe` in the appendix where the value is org-authored
     configuration (`prompt_templates.prompt`, `tool_variations.confirm_prompt`,
     `http_tool_definitions.confirm_prompt`, `risk_policies.*`,
     `skill_versions.content`, `deployment_logs.message`,
     `function_tool_definitions.input_schema`, `queries.spec`) → `safe`.
  4. Type `bytea`, `halfvec`, `vector`, `jsonb` named `spec|config|settings|
     metadata|attributes` → `safe`; other `jsonb`/`bytea` in `content`/`secret`
     tables → the table's tier.
  5. Everything else: `safe` if the table is `safe`/`pii`/`internal` in the
     appendix; ids, `*_id`, `*_at`, `deleted`, `status`, `kind`, `type`,
     `count`, `size`, `version`, `name`, `slug` → `safe` in every table;
     remaining columns of `content` tables → `content`; remaining columns of
     `secret` tables → `secret`.
- The generated diff is reviewed column by column in the PR (this is the
  security review; the script only removes the typing). The reviewer's
  contract: every `safe` column in a `content`/`secret`/`pii` table is
  justified in the PR description.
- `mise run db:diff --name column-access-tiers`; the migration must contain
  only `COMMENT ON COLUMN` statements; apply on a fresh local DB.

### G3: ClickHouse annotations

**Files:** modify `server/clickhouse/schema.sql`, `server/clickhouse/mart.sql`;
generated `server/clickhouse/migrations/<ts>_column-access-tiers.sql` (and the
golang-migrate mirror if `.mise-tasks/lint/migrations.sh` requires it).

- Same generator (`--dialect clickhouse`) reading the CH schema: inline
  `COMMENT '…'` per column, appended when present. `user_email`,
  `session_user_email`, `emails`, `email_lower`, `canonical_email` → `pii`;
  `input_content`, `output_content`, `body`, `status_message`,
  `outcome_message` → `content`; `api_key_id` → `safe` (it is an id);
  `identity_map.*` beyond ids → `secret`.
- `mise run clickhouse:diff --name column-access-tiers`; apply locally.

### G4: Lint and export

**Files:** create `.mise-tasks/lint/access-tiers.mts`, `.mise-tasks/db/
access-tiers.mts`, `server/database/access-tiers.json`; modify
`.github/workflows/pr.yaml` (next to `mise run lint:migrations`, ~line 858).

- Parser (shared by lint, export and the seed script): Postgres — every
  `CREATE TABLE` / `CREATE [MATERIALIZED] VIEW` column list, joined with every
  `COMMENT ON COLUMN`; ClickHouse — every `CREATE …` block's column list with
  its inline `COMMENT`.
- `lint:access-tiers` fails, naming each offender, when: a column has zero or
  more than one `@access:` line; a tier is outside the vocabulary; a table
  comment carries `@access:`; `access-tiers.json` is stale.
- `db:access-tiers --format json|table` prints
  `{"postgres": {"public.chat_messages": {"id": "safe", "content": "content",
  …}}, "clickhouse": {"gram.agent_events": {…}}}`. The JSON is committed so
  every tier change is a reviewable diff; the runtime reads the database, not
  the file.
- CI: `mise run lint:access-tiers` in `pr.yaml`.

### G5: Deploy manifest

**Files:** gram infra for the MCP server (`grep -rl restrictedsql infra/
deploy/`), or a section in `ACCESS_TIERS.md` if infra is elsewhere.

- Postgres instance: `restrictedsql-mcp --dialect postgres
  --columns-from-annotations safe --connection-level-security --tunnel
  --tunnel-only`; ClickHouse instance likewise. `pii` is a per-deployment
  decision (`safe,pii`).

---

# Part R — gram-restricted-sql-mcp repository

### R1: Column catalog with tiers

**Files:** modify `internal/policy/policy.go`, `internal/db/backend.go`;
create `internal/policy/annotations.go`, `internal/db/postgres/annotations.go`,
`internal/db/clickhouse/annotations.go`.

```go
// policy
type Tier string // "safe" | "pii" | "content" | "secret"
func ParseAccessTier(comment string) (Tier, bool)   // the regex, exactly one match
type ColumnSet map[TableRef]map[string]Tier          // every annotated column
func (p *Policy) SetCatalog(cs ColumnSet)            // replaces snapshot atomically
func (p *Policy) SelectedTiers() map[Tier]struct{}
func (p *Policy) CanReadColumn(t TableRef, col string) bool  // annotation mode: tier ∈ selected; static mode: t ∈ R
func (p *Policy) ReadableColumns(t TableRef) []string        // ordered as in the catalog
func (p *Policy) CanRead(t TableRef) bool            // annotation mode: len(ReadableColumns) > 0

// db
type CatalogLoader interface {
    // LoadCatalog returns every column of every table/view (outside system
    // schemas) with its parsed tier; columns without a valid annotation are
    // returned with tier "" so the guard can name them in rejections.
    LoadCatalog(ctx context.Context) (policy.ColumnSet, error)
}
```

- Postgres: `pg_attribute` ⨝ `pg_class` ⨝ `pg_namespace` LEFT JOIN
  `pg_description` on `(objoid, objsubid = attnum)`, `attnum > 0`, not
  dropped, relkind in `r,p,v,m`, schema not `pg_catalog`/`information_schema`/
  `pg_toast%`. Replaces the existing `RefreshColumns` query (same rows, plus
  the comment).
- ClickHouse: `SELECT database, table, name, comment FROM system.columns WHERE
  database NOT IN ('system','INFORMATION_SCHEMA','information_schema')`.
- Loaded at boot (warn on failure) and on every `/readyz`, replacing the
  current column refresh. Log added, removed and re-tiered columns at info.

### R2: Config

**Files:** modify `internal/config/config.go`, `README.md`.

- `--columns-from-annotations <tiers>`: comma list ⊆ `{safe, pii}`;
  `content`/`secret` refused at boot. Mutually exclusive with `--read-tables`.
  `--write-tables` allowed with either. `--annotation-key` (default `access`).
- Static mode is unchanged for existing users; annotation mode implies strict
  column checking.

### R3: Guard — column resolution and wildcard rejection (Postgres)

**Files:** modify `internal/sqlguard/postgres/columns.go`, `nodes.go`,
`guard.go`; modify `internal/sqlguard/guard.go` (`Checked.Columns`).

- `Checked` gains `Columns map[policy.TableRef][]string` — every base-table
  column the statement reads or writes, for logging and for the server's
  double check.
- Reject in annotation mode: `A_Star` anywhere (`SELECT *`, `t.*`, `count(*)`
  is **allowed**: `count(*)` is a `FuncCall` with `AggStar`, not a target
  `A_Star`; keep it), whole-row references (a `ColumnRef` naming a relation
  alias with no column, `ROW(t)`, `to_json(t)`), `RETURNING *`, `NATURAL`
  joins, `SELECT` with an empty target list, `INSERT … DEFAULT VALUES` (no
  column list → cannot be checked; require an explicit column list),
  `INSERT INTO t SELECT …` without a column list.
- Resolution (extends the scope machinery added by the column-notation fix):
  every `ColumnRef` — qualified or not — is resolved to exactly one relation in
  scope. Unqualified names are looked up in every relation of the innermost
  scope, then outer scopes (correlation); zero matches → reject
  "unknown column"; more than one → reject "ambiguous column". A match on a
  base table checks `CanReadColumn`; a match on a derived relation (subquery,
  CTE, VALUES, function-free join output) is allowed because its inputs were
  already checked when the derived relation was walked. `USING (c)` resolves
  `c` on both sides. Output column names of derived relations are inferred as
  today (`FigureColname`), now including aliases from `AS (c1, c2)` lists.
- Write mode: `INSERT` column list, `UPDATE SET` targets, `ON CONFLICT` index
  and `DO UPDATE SET` columns, `RETURNING` items and `excluded.c` all resolve
  through the same path; a target column must be writable
  (`CanReadColumn` with the same tiers) and its table in `--write-tables`.
- Static mode keeps today's behaviour (no per-column check) so existing e2e
  and third-party use keep working; the walker takes the mode from the policy.
- `cmd/sqlguard-check` gains `--columns 't=c1:safe,c2:pii'` and `--tiers safe`.

### R4: Guard — same for ClickHouse

**Files:** modify `internal/sqlguard/clickhouse/nodes.go`, `guard.go`;
create `internal/sqlguard/clickhouse/columns.go`.

- Reject `*`, `t.*`, `COLUMNS(...)`, `* EXCEPT/REPLACE/APPLY`, `count(*)`?
  — no: ClickHouse `count()` and `count(*)` are the same aggregate and read no
  column; allow both. Reject whole-row/tuple references to a relation alias.
- Resolution as in R3 over the AfterShip AST: FROM/JOIN/ARRAY JOIN scopes,
  aliases, CTEs (both forms), subqueries, lambda parameters (never columns),
  `PREWHERE`/`WHERE`/`GROUP BY`/`HAVING`/`ORDER BY`/`LIMIT BY`/window
  clauses. ClickHouse allows referencing SELECT-list aliases in `WHERE`;
  resolve aliases first, then columns.

### R5: Connection-level security — column grants

**Files:** modify `internal/dbsec/postgres.go`, `internal/dbsec/clickhouse.go`,
`internal/dbsec/gate.go`.

- Postgres: in annotation mode, `GRANT SELECT (c1, c2, …) ON schema.table TO
  restrictedsql_ro` per table with at least one readable column (no table-level
  SELECT); `rw` additionally gets `INSERT (cols)`, `UPDATE (cols)` on
  `--write-tables` columns in the selected tiers and table-level `DELETE`
  (Postgres has no column-level DELETE). Postgres allows `count(*)` with a
  column-level grant on any one column, so counts work at the DB layer too.
- ClickHouse: `GRANT SELECT(c1, c2) ON db.table TO restrictedsql_ro`; `GRANT
  SHOW TABLES, SHOW COLUMNS ON *.*` so metadata tools list everything
  (metadata is global by design).
- Re-provision whenever the readiness reload changes the column set; until it
  succeeds `/readyz` is 503 `grants stale`.

### R6: Metadata tools

**Files:** modify `internal/mcpserver/tools_meta.go`, `internal/db/backend.go`
(`ColumnDetail.Tier`, `ColumnDetail.Selectable`).

- `get_object_details` and `list_objects` are global (all schemas, all
  tables, all columns). Each column shows `tier` and `selectable` so an agent
  can write a valid query without trial and error; tables show
  `selectable_columns` count. Tool descriptions say wildcards are rejected and
  point at `get_object_details`.
- Rejections name the column and its tier: `column chat_messages.content is
  tier "content"; selectable columns: id, chat_id, …`.

### R7: e2e

**Files:** modify `e2e/postgres/init.sql`, `e2e/clickhouse/init.sql`;
create `e2e/annotations_test.go`, `e2e/clickhouse_annotations_test.go`;
modify `e2e/corpus_test.go` (annotation-mode corpus).

- Seed comments: `allowed_orders` all `safe` except a new `note` column
  tiered `content` and `customer_email` tiered `pii`; `allowed_customers`
  (`email` → `pii`, rest `safe`); `forbidden_secrets` (`id` → `safe`,
  `secret` → `secret`); `allowed_audit` (`note` → `content`, rest `safe`);
  one column left unannotated on purpose (`allowed_orders.legacy_flag`).
- `TestPostgresAnnotationsSafeOnly`: `SELECT id, amount FROM allowed_orders`
  ok; `SELECT *` rejected `wildcard`; `SELECT note` rejected naming tier
  `content`; `SELECT customer_email` rejected `pii`; `SELECT legacy_flag`
  rejected `not annotated`; `SELECT count(*) FROM forbidden_secrets` **ok**;
  `SELECT secret FROM forbidden_secrets` rejected; `SELECT o.id FROM
  allowed_orders o JOIN allowed_customers c USING (id)` ok; ambiguous
  unqualified `id` across a join rejected; `to_json(o)` rejected; `SELECT
  o FROM allowed_orders o` rejected; CTE selecting `note` rejected at the CTE.
- `TestPostgresAnnotationsSafeAndPii`: `customer_email` readable.
- `TestPostgresAnnotationsFlagValidation`: `content`, `secret`, combining with
  `--read-tables` → exit 2.
- `TestPostgresAnnotationsMigrationAddsPhiColumn`: boot; `ALTER TABLE
  allowed_orders ADD COLUMN ssn text` from the test; `/readyz`; `SELECT ssn`
  rejected `not annotated`; `COMMENT ON COLUMN allowed_orders.ssn IS
  '@access: pii'`; `/readyz`; still rejected under `safe`; boot with
  `safe,pii` → readable. Drop the column in cleanup.
- `TestPostgresAnnotationsReTierColumn`: `amount` re-commented to `content` →
  after `/readyz` rejected; back to `safe` → readable.
- `TestPostgresAnnotationsWithConnectionLevelSecurity`: same flows with the
  flag; direct probe as `restrictedsql_ro`: `SELECT id FROM allowed_orders`
  ok, `SELECT *` permission denied, `SELECT note` permission denied,
  `SELECT count(*) FROM forbidden_secrets` ok; `has_column_privilege` matrix
  flips after the re-tier probe.
- `TestPostgresAnnotationsWrite` (`--write-tables allowed_audit`,
  `safe`): `INSERT INTO allowed_audit (id) VALUES (…) RETURNING id` ok;
  `INSERT … (note)` rejected; `RETURNING *` rejected; `INSERT INTO allowed_audit
  SELECT …` without column list rejected; `UPDATE allowed_audit SET note = …`
  rejected.
- `TestPostgresAnnotationsMetadataGlobal`: `get_object_details forbidden_secrets`
  returns both columns with tiers; `list_objects` lists every table.
- ClickHouse twins for safe-only, safe+pii, wildcard forms (`*`, `COLUMNS`,
  `* EXCEPT`), `count()`, re-tier via `ALTER TABLE … MODIFY COLUMN … COMMENT`,
  and the connection-level grant probe via HTTP as `restrictedsql_ro`.
- Adversarial pass (R8) reuses both guards' existing corpus in annotation mode.

### R8: Adversarial review of column resolution

Cross-account, as before: one account attacks the Postgres resolver
(aliases shadowing table names, CTE output names colliding with base columns,
`USING` on a `content` column, `ORDER BY` / `GROUP BY` positional vs. name,
window `PARTITION BY` on a hidden column, `LATERAL` correlation to a hidden
column, `DISTINCT ON (content)`, `EXISTS (SELECT content …)`, `IN (SELECT …)`,
`ANY (ARRAY(SELECT content …))`, `xmin`/`ctid` system columns, `t.*` inside
`ROW()`, `jsonb_build_object('c', t)`), the other the ClickHouse resolver
(alias-in-WHERE, `COLUMNS('regex')`, `* EXCEPT`, `APPLY`, tuple of relation,
`arrayJoin` over a hidden column, `PREWHERE content != ''`, `LIMIT BY`,
`GROUP BY` on hidden, `_row_exists`/`_part` virtual columns).

### R9: Docs

**Files:** `README.md`, spec §4/§5 (column rules), `deploy/k8s.yaml`.

---

## Order and ownership

- G2/G3 depend on the appendix tiering; G4 on the parser; R1–R2 first, then
  R3/R4 in parallel (two accounts), then R5–R7, then R8 cross-review.
- G and R streams are independent. Integration: gram local DBs after
  `mise run db:reset` / `clickhouse:rebuild`; boot the server with `safe`;
  `get_object_details` for every table must agree with
  `server/database/access-tiers.json`; the adversarial corpus must be green.

## Risks

- **Volume of the initial annotation** (~3,000 Postgres columns, ~700
  ClickHouse). Mitigated by the generator plus a column-by-column PR review;
  the review is the real security work and must not be skipped.
- **Unqualified column resolution** must match the database's own resolution
  exactly, or the guard could resolve `c` to a safe relation while Postgres
  resolves it to a hidden one. Mitigation: reject ambiguity instead of
  choosing, deparse fully qualified column references (`alias.c`) so the
  canonical SQL sent to the DB carries the guard's resolution, and rely on the
  column grants as the second layer.
- **Derived relations laundering**: a CTE that selects a hidden column is
  rejected when the CTE is walked, so no later reference can reach it; the
  e2e corpus must cover every derived form.
- **System/virtual columns** (`ctid`, `xmin`, ClickHouse `_part`) are not in
  the catalog and therefore unresolvable → rejected by construction; keep a
  test.
- **Static mode divergence**: two code paths in the guard. Keep the static
  path as a strict superset (no column checks) and run the full existing
  corpus in both modes.

## Appendix — starting table tiers for the generator

Unchanged from the v1 plan: the `safe` / `pii` / `content` / `secret` /
`internal` lists for Postgres and ClickHouse (see git history of this file,
commit `7cb82a5`). In v2 they only seed the generator's per-column decisions;
the committed annotations are per column.
