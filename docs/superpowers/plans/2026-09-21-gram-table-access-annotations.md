# Gram table access annotations — plan

Date: 2026-09-21
Repos: `speakeasy-api/gram` (annotations, lint, views) and
`speakeasy-api/gram-restricted-sql-mcp` (reads the annotations at boot).

## Goal

Every gram table and view carries an access tier, declared next to its
definition, migrated with the schema, and readable in structured form from the
live database. The restricted SQL MCP server boots with a tier selection
(e.g. `safe,pii`) instead of a hand-written table list, and the lists can never
drift from the schema because CI refuses an unannotated table.

## Options considered

1. **Structured `COMMENT ON TABLE` / ClickHouse table `COMMENT`** — chosen.
   Co-located with the definition in `server/database/schema.sql` and
   `server/clickhouse/schema.sql`; Atlas already diffs comments into
   migrations (`mise run db:diff`, `mise run clickhouse:diff`), so no manual
   migration authoring; readable at runtime via `pg_description` and
   `system.tables.comment`; gram already uses table and column comments
   (71 in Postgres, 465 in ClickHouse), so the convention is an extension of
   an existing one, not a new mechanism.
2. **Registry table** (`table_access_tiers(schema, name, tier)`) seeded by
   migration. Rejected: Atlas is declarative for DDL only, so the rows would
   live in hand-written data migrations outside `schema.sql`; nothing ties a
   row to the table it describes; a lint would have to cross-reference two
   sources.
3. **Repo-side manifest** (`access_tiers.yaml`) shipped to the MCP server.
   Rejected as the source of truth: not visible in the database, needs a
   deploy-time file, and drifts from what is actually migrated. Kept only as
   a generated, read-only artefact for PR review (see G4).

## Annotation format

One trailing line inside the object's comment:

```
@access: <tier>
```

Regex (both databases): `(?m)^@access:\s*(safe|pii|content|secret|internal)\s*$`,
exactly one match per table or view. Prose stays above it; the line is
stripped when the comment is shown as documentation.

| Tier | Meaning | Exposed by default |
|---|---|---|
| `safe` | org, project, config, deployment, tool, billing metadata; no user identity, no message content, no credentials | yes |
| `pii` | contains user identity (email, name, device owner) but no message content | opt-in |
| `content` | user or LLM message content, or data derived from it (summaries, embeddings, risk spans, telemetry bodies) | never |
| `secret` | credentials, tokens, keys, cookies, signed material — hashed or encrypted included | never |
| `internal` | outboxes, receipts, staging tables, materialized-view targets; no sensitive data but no analytical value | never |

Rules:
- Views and materialized views are annotated like tables. A view is the way to
  expose a subset of a `content`/`pii`/`secret` table: e.g. `chat_metadata`
  (safe) over `chats` (content, because of `summary`).
- Column comments may additionally carry `@access: pii|content|secret` on the
  offending column. Phase 1 ignores them at runtime; they document why the
  table has its tier and feed the phase 2 column-level grants.
- ClickHouse materialized views (`*_mv`) are `internal`; their target tables get
  their own tier.

Postgres example (in `schema.sql`, Atlas turns it into the migration):

```sql
COMMENT ON TABLE tunneled_mcp_servers IS 'Customer-hosted MCP server sources that connect to Gram through outbound tunnels.
@access: secret';
COMMENT ON COLUMN tunneled_mcp_servers.key_hash IS 'SHA-256 of the tunnel key.
@access: secret';
```

ClickHouse example:

```sql
CREATE TABLE gram.organization_metadata (...) ENGINE = ...
COMMENT 'Org dimension replicated from Postgres.
@access: safe';
```

Precedence when the MCP server reads them: an explicit `--read-tables` entry is
unioned with the annotated set; `--write-tables` stays explicit only. A table
with no annotation is never exposed, whatever the flags say.

---

# Part G — gram repository

### G1: Convention doc and vocabulary

**Files:** create `server/database/ACCESS_TIERS.md`.

- Tier table above, the regex, the "one line per object" rule, view guidance,
  how to run the lint locally, and a worked example of adding a new table
  (schema.sql edit → `mise run db:diff --name <x>` → lint passes).
- Link it from `server/database/README` (or wherever schema conventions live;
  find with `grep -rl "schema.sql" server/*.md docs/`).

### G2: Annotate every Postgres object

**Files:** modify `server/database/schema.sql`; generated
`server/migrations/<ts>_table-access-tiers.sql` + `atlas.sum`.

- Apply the tiering in the appendix. For the ~30 tables that already have a
  `COMMENT ON TABLE`, append the `@access:` line; for the rest add a new
  `COMMENT ON TABLE` whose prose is one sentence (write it from the table's
  columns and the owning package under `server/internal/`).
- Column comments on the columns that decided a non-safe tier (`email`,
  `*_encrypted`, `*_hash`, `content`, `summary`, `spans`, `payload`, …).
- Add `chat_metadata` view: `CREATE VIEW chat_metadata AS SELECT id,
  project_id, user_account_id, title_manually_set, pinned_at,
  summary_generated_at, litellm_proxied, created_at, updated_at, deleted_at,
  deleted FROM chats;` annotated `safe`. (Only view needed today; add more
  when a `pii` table is wanted without its email column.)
- `mise run db:diff --name table-access-tiers`; confirm the migration contains
  only `COMMENT ON` and the view; `mise run db:migrate` on a fresh local DB.

### G3: Annotate every ClickHouse object

**Files:** modify `server/clickhouse/schema.sql` (and `mart.sql` for
`marts.weekly_ai_surface_adoption`); generated
`server/clickhouse/migrations/<ts>_table-access-tiers.sql`.

- 23 of 40 objects already have a table comment; append the line, add the
  rest. `*_mv` → `internal`; `*_staging` → `internal`; `identity_map` →
  `secret` (it is the email ↔ id crosswalk); `agent_events`,
  `telemetry_logs`, `otel_logs`, `otel_traces`, `risk_findings` → `content`;
  aggregates with `user_email` → `pii`; the rest `safe`.
- `mise run clickhouse:diff --name table-access-tiers`; apply locally with
  `mise run clickhouse:migrate`. Check the golang-migrate mirror under
  `server/clickhouse/local/golang_migrate` if the repo convention requires
  both (see `.mise-tasks/lint/migrations.sh`).

### G4: Lint and structured export

**Files:** create `.mise-tasks/lint/access-tiers.mts`, create
`.mise-tasks/db/access-tiers.mts`; modify `.github/workflows/pr.yaml` (the job
that runs `mise run lint:migrations` at line ~858).

- `lint:access-tiers`: parse both `schema.sql` files (Postgres: every
  `CREATE TABLE` / `CREATE [MATERIALIZED] VIEW` name and every
  `COMMENT ON TABLE|VIEW` statement; ClickHouse: each `CREATE …` block's
  trailing `COMMENT '…'`). Fail listing every object with zero or more than
  one `@access:` line, or an unknown tier. Exit 0 with a count when clean.
- `db:access-tiers --format json|table`: print `{"postgres": {"public.projects":
  "safe", …}, "clickhouse": {"gram.projects": "safe", …}}` from the same
  parser. This is the repo-side structured export; the runtime reads the
  database, not this.
- Commit `server/database/access-tiers.json` produced by that command and make
  the lint fail when it is stale, so tier changes show up as a reviewable diff
  in every PR.
- Wire `mise run lint:access-tiers` into `pr.yaml` next to `lint:migrations`.

### G5: Deploy manifest for gram

**Files:** gram's infra for the MCP server (wherever `tunneled` workloads are
defined; find with `grep -rl restrictedsql infra/ deploy/`), or a note in
`ACCESS_TIERS.md` if infra lives elsewhere.

- `restrictedsql-mcp --dialect postgres --tables-from-annotations safe
  --connection-level-security --tunnel --tunnel-only`, DSN from a bootstrap
  secret with `CREATEROLE` and `GRANT` rights. Second instance for ClickHouse
  with the same tiers. `pii` is enabled per deployment by changing the flag
  to `safe,pii`.

---

# Part R — gram-restricted-sql-mcp repository

### R1: Annotation loader in both backends

**Files:** modify `internal/db/backend.go`; create
`internal/db/postgres/annotations.go`, `internal/db/clickhouse/annotations.go`.

```go
// AnnotationLoader is implemented by backends that can read access tiers
// from object comments.
type AnnotationLoader interface {
    // AnnotatedTables returns every table or view whose comment carries a
    // recognised "@access: <tier>" line, keyed by fully qualified name.
    AnnotatedTables(ctx context.Context) (map[policy.TableRef]string, error)
}
```

- Postgres: `SELECT n.nspname, c.relname, d.description FROM pg_class c JOIN
  pg_namespace n ON n.oid = c.relnamespace LEFT JOIN pg_description d ON
  d.objoid = c.oid AND d.objsubid = 0 WHERE c.relkind IN ('r','p','v','m') AND
  n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE
  'pg_toast%'`; apply the regex; ignore rows without a match.
- ClickHouse: `SELECT database, name, comment FROM system.tables WHERE
  database NOT IN ('system','INFORMATION_SCHEMA','information_schema')`.
- The regex and tier vocabulary live in `internal/policy/annotations.go`
  (`ParseAccessTier(comment string) (tier string, ok bool)`), shared by both.

### R2: Dynamic read set in the policy

**Files:** modify `internal/policy/policy.go`, `internal/config/config.go`,
`cmd/restrictedsql-mcp/main.go`, `internal/health/health.go`.

- Flags: `--tables-from-annotations <tiers>` (comma list; empty = off) and
  `--annotation-key` (default `access`, so the marker is `@access:`).
  Validation: tiers ⊆ vocabulary; `content` and `secret` are refused at boot
  with a message saying they are never exposed.
- `Policy` gets `SetAnnotatedRead(map[TableRef]struct{})` behind the same
  lock as `SetColumns`; `CanRead` = static ∪ annotated. `WriteTables` remain
  static. `AllTables()` (used by readiness and `TablesExist`) includes the
  annotated set.
- Boot: after the backend is up, load annotations once (warn, do not fail,
  when the DB is unreachable). `/readyz`: reload annotations before
  `RefreshColumns`, so a migration that adds or re-tiers a table is picked up
  on the next probe without a restart. Log added and removed tables at info.
- With `--tables-from-annotations` and no static `--read-tables`, boot must not
  require `--read-tables` (relax the config check).

### R3: Re-provision grants when the set changes

**Files:** modify `internal/dbsec/gate.go`, `internal/dbsec/postgres.go`,
`internal/dbsec/clickhouse.go`.

- The provisioner records the table set it granted. When the readiness reload
  yields a different set, re-run provisioning (idempotent; revoke-then-grant)
  before reporting ready. Until it succeeds `/readyz` is 503 with
  `grants stale: <n> tables changed`.

### R4: e2e

**Files:** modify `e2e/postgres/init.sql`, `e2e/clickhouse/init.sql`; create
`e2e/annotations_test.go`.

- Seed: `allowed_orders` → `safe`, `allowed_customers` → `pii`,
  `forbidden_secrets` → `secret`, `allowed_audit` → no annotation, plus a view
  `allowed_orders_v` → `safe`. Same in ClickHouse.
- `TestPostgresAnnotationsSafeOnly`: boot with `--tables-from-annotations
  safe` and no `--read-tables`; `allowed_orders` and the view readable;
  `allowed_customers`, `forbidden_secrets`, `allowed_audit` rejected;
  `list_objects` still shows everything (catalog visibility unchanged).
- `TestPostgresAnnotationsSafeAndPii`: `safe,pii` → customers readable.
- `TestPostgresAnnotationsRejectContentTier`: `--tables-from-annotations
  content` exits 2.
- `TestPostgresAnnotationsUnionWithStatic`: `--read-tables allowed_audit`
  plus `safe` → audit and orders readable.
- `TestPostgresAnnotationsReloadOnReadyz`: boot; `COMMENT ON TABLE
  allowed_audit IS '@access: safe'` from the test; query rejected; hit
  `/readyz`; query succeeds; remove the comment; `/readyz`; rejected again.
- `TestPostgresAnnotationsWithConnectionLevelSecurity`: same reload with the
  flag; `has_table_privilege` flips for `restrictedsql_ro` after the probe.
- ClickHouse twins for safe-only, safe+pii, and reload (`ALTER TABLE … MODIFY
  COMMENT`).
- Bad comment formats (`@access:safe` without space is fine; two lines;
  unknown tier) → ignored and logged at warn, table not exposed.

### R5: Docs

**Files:** modify `README.md`, spec §3/§5, `deploy/k8s.yaml`.

- Flag reference, the tier vocabulary (copy from gram's `ACCESS_TIERS.md`),
  precedence rules, the reload behaviour, and a gram-specific example command.

---

## Order and ownership

- G1 → G4 and R1 → R5 are independent; run them in parallel (two accounts).
- Integration check after both land: `mise run db:reset && mise run
  clickhouse:rebuild` in gram, boot the MCP server against the local DBs with
  `safe,pii`, and diff `list_objects` minus rejected tables against
  `server/database/access-tiers.json`. They must match exactly.
- Phase 2 (separate plan): column-level `@access:` → `GRANT SELECT (cols)` in
  the provisioner and column pruning in the guard, which removes the need for
  most `*_metadata` views.

## Appendix — initial tiering (from the 2026-09-20 classification)

Postgres `safe` (127): organization_metadata, organization_features,
organization_onboarding, organization_roles, organization_role_assignments,
organization_user_relationships, organization_mcp_collections,
organization_mcp_collection_registries,
organization_mcp_collection_server_attachments, projects,
project_allowed_origins, project_managed_assistants,
project_marketplace_settings, project_tool_variations, trials,
billing_cycle_usage, stripe_invoices, stripe_invoice_allocations,
stripe_meter_reports, openrouter_spend_daily, spend_rules, global_roles,
principal_grants, deployments, deployment_statuses, deployment_tags,
deployment_tag_history, deployment_logs, deployments_functions,
deployments_openapiv3_assets, deployments_packages, packages,
package_versions, assets, toolsets, toolset_versions, toolset_environments,
toolset_origins, toolset_prompts, tool_variations, tool_variations_groups,
http_tool_definitions, function_tool_definitions,
function_resource_definitions, functions_access, http_security,
prompt_templates, queries, environments, source_environments, fly_apps,
trigger_instances, data_export_routes, hooks_server_name_overrides,
mcp_servers, mcp_endpoints, mcp_metadata, mcp_registries,
mcp_server_tool_metadata, mcp_environment_configs, meta_mcp_servers,
meta_mcp_server_members, remote_mcp_servers, unproxied_mcp_servers,
external_mcp_attachments, external_mcp_tool_definitions,
external_oauth_server_metadata, mcp_approval_requests,
mcp_approval_decisions, mcp_research_reports,
platform_mcp_catalog_registrations, platform_mcp_distributions,
platform_mcp_onboarding_milestones, platform_mcp_onboarding_workflows,
platform_mcp_selected_use_evidence, platform_mcp_feedback,
platform_mcp_connections, platform_mcp_readiness, plugins, plugin_servers,
plugin_assignments, slack_registrations, slack_app_toolsets, agents,
agent_executions, agent_role_assignments, assistants, assistant_threads,
assistant_toolsets, assistant_runtimes, assistant_mcp_servers,
chat_resolutions, chat_resolution_messages, chat_user_feedback,
chat_analysis_evaluations, chat_analysis_settings, tool_call_blocks,
ai_integration_syncs, ai_integration_config_chats, ai_scan_targets,
audit_logs, authz_challenge_resolutions, risk_policies,
risk_custom_detection_rules, risk_exclusions, risk_policy_challenges,
risk_policy_eval_reviews, session_quarantines, killswitch_operations,
killswitch_prescriptions, killswitch_prescription_versions,
killswitch_prescription_version_resources, killswitch_expiry_events,
workload_issuers, workload_agent_assignments, workload_identity_admissions,
identity_provider_connections, okta_identity_provider_connections,
okta_applications, okta_application_assignments,
okta_application_reconcile_runs, okta_resource_connections,
workos_organization_syncs, workos_user_syncs, directory_groups,
directory_user_group_memberships, user_session_issuers,
user_session_issuer_cimd_clients, remote_session_issuers,
remote_session_ema_bindings, principal_remote_session_bindings,
json_web_key_sets, json_web_keys, skills, skill_versions,
skill_distributions, skill_sync_receipts, skill_version_lineages,
skill_version_origins, skill_raw_hashes, skill_edit_suggestions,
skill_edit_suggestion_changes, skill_edit_suggestion_feedback,
skill_efficacy_settings, support_matrix_capabilities,
support_matrix_coverage, support_matrix_integration_methods,
support_matrix_method_capabilities, support_matrix_method_platforms,
support_matrix_platforms; view chat_metadata.

Postgres `pii`: users, user_accounts, directory_users,
organization_setup_tasks, billing_metadata, spend_rule_events,
mcp_approval_request_requesters, mdm_devices, device_owners,
device_agent_configurations, device_agent_device_syncs,
device_agent_environment_syncs, device_agent_syncs, chat_session_links,
risk_policy_bypass_requests, skill_feedback, skill_observations.

Postgres `content`: chats, chat_messages, chat_content_parts,
assistant_dashboard_messages, assistant_memories, assistant_thread_events,
business_memories, risk_results, toolset_embeddings.

Postgres `secret`: api_keys, external_credentials, external_keys,
aws_iam_credentials, gcp_iam_credentials, aws_kms_keys, gcp_kms_keys,
model_provider_keys, openrouter_api_keys, litellm_instances,
ai_integration_configs, device_integration_configs,
device_integration_schedules, device_integration_syncs, network_ingresses,
otel_destinations, otel_forwarding_configs, oauth_proxy_client_info,
oauth_proxy_providers, oauth_proxy_servers,
external_oauth_client_registrations, assistant_mcp_oauth_clients,
remote_session_clients, remote_session_client_user_session_issuers,
remote_sessions, trusted_issuer_sessions, user_oauth_tokens, user_sessions,
user_session_clients, user_session_consents, session_handoff_links,
custom_domains, slack_apps, plugin_github_connections, environment_entries,
remote_mcp_server_headers, tunneled_mcp_server_headers,
tunneled_mcp_servers, platform_mcp_oauth_clients,
platform_mcp_authorization_grants, platform_mcp_sessions,
platform_mcp_setup_handoffs, platform_mcp_operation_receipts,
skill_share_links, skill_efficacy_evaluations, organization_invitations.

Postgres `internal`: outbox, outbox_relays, publish_outbox,
publish_outbox_dead_letters, stripe_webhook_receipts.

ClickHouse `safe`: organization_metadata, projects,
billing_meter_daily_summaries, billing_meter_readings,
billing_meter_readings_by_time, metrics_summaries, attribute_keys,
chat_token_summaries, chat_analysis_scores, skill_efficacy_scores,
skill_session_versions, shadow_mcp_inventory_urls,
marts.weekly_ai_surface_adoption.
ClickHouse `pii`: agent_metrics, attribute_metrics_summaries,
trace_summaries, authz_challenges, authz_challenge_bucket_summaries,
ai_detections, ai_scan_receipts, spend_rule_usage_summaries,
chat_session_summaries.
ClickHouse `content`: agent_events, telemetry_logs, otel_logs, otel_traces,
risk_findings.
ClickHouse `secret`: identity_map.
ClickHouse `internal`: every `*_mv`, `*_staging`.

Tables not listed above are new since the classification and must be tiered
by the author of G2/G3; the lint will name them.
