# Feature report — connection-level security

Branch: `feature-connection-security` (off `main`). Flag: `--connection-level-security`
(default off) with `--security-role-prefix` (default `restrictedsql`).

## What was built

A second security layer inside the database, independent of the SQL guard. With
the flag, the DSN is a bootstrap connection used only to provision roles; tool
traffic then runs on pools connected as those roles, never via `SET ROLE`.

| Commit | Content |
|---|---|
| `feat(dbsec): provision least-privilege roles with --connection-level-security` | `internal/dbsec/{provisioner,gate,postgres,clickhouse}.go`, config flags, `pgbackend.NewWithWriteDSN` (read + write pools), health preflight, boot wiring |
| `test(e2e): connection-level security suites for postgres and clickhouse` | `e2e/security_test.go` |
| `docs: connection-level security in README, spec §11 and k8s example` | README flags table + section, spec §11, commented k8s args |

### Provisioning

- **Postgres** (`internal/dbsec/postgres.go`): one transaction on a single `pgx`
  connection, closed when it returns. Per role (`<prefix>_ro`; `<prefix>_rw` only
  with `--dangerously-add-write-tools`): a `DO` block that runs `CREATE ROLE` or
  `ALTER ROLE` with `LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
  NOREPLICATION PASSWORD ...`; `ALTER ROLE ... SET search_path` / `SET
  statement_timeout`; for every schema the bootstrap has `USAGE` on (system
  schemas skipped) `REVOKE ALL ON ALL TABLES / ALL SEQUENCES IN SCHEMA` and
  `REVOKE ALL ON SCHEMA`; then the exact grants (ro: schema `USAGE` + `SELECT` on
  R; rw: `USAGE` on R ∪ W schemas, `SELECT` on R ∪ W, `INSERT/UPDATE/DELETE` on W,
  `USAGE, SELECT` on W's sequences found through `pg_depend` auto/internal
  dependencies and `pg_attrdef` defaults).
- **ClickHouse** (`internal/dbsec/clickhouse.go`): `CREATE USER OR REPLACE
  <prefix>_ro IDENTIFIED WITH sha256_password BY '<random>' SETTINGS readonly = 1
  READONLY, max_execution_time = T CHANGEABLE_IN_READONLY MIN 0 MAX T,
  max_result_rows = N+1 CHANGEABLE_IN_READONLY MIN 0 MAX N+1, result_overflow_mode
  = 'break' CHANGEABLE_IN_READONLY`; `REVOKE ALL ON *.*`; `GRANT SELECT` per R
  table; `GRANT SHOW TABLES, SHOW COLUMNS ON db.*` per R database; `GRANT SELECT
  ON system.data_skipping_indices`.
- Passwords: 32 random bytes as hex per boot, in memory only. On Postgres, when
  `password_encryption = scram-sha-256`, the role statement carries a
  SCRAM-SHA-256 verifier computed with `crypto/pbkdf2` + `crypto/hmac` (stdlib),
  so the plaintext never reaches the server or its statement log.
- `RewriteDSN` (`net/url`) swaps userinfo, keeps every query parameter and strips
  `user`/`username`/`password` query keys that would override it.

### Wiring

- `dbsec.Gate` implements `db.Backend` and `db.TxBackend`. Every method calls
  `EnsureProvisioned`, which is a single-flight provision + backend open, then an
  atomic load. `main` hands the gate to the MCP server, the transaction registry
  and the health checker, so `db.Backend` and the tool handlers are untouched.
- `health` type-asserts an `EnsureProvisioned(ctx) error` method and returns its
  error verbatim as the `/readyz` reason
  (`connection-level security not provisioned: statement "..." failed: ...`).
- Boot attempts provisioning with a 10 s timeout and only logs a warning on
  failure; `/readyz` (3 s) and every tool call retry it.
- Postgres backend: `read` pool for Query/Explain/metadata/TablesExist/Ping,
  `write` pool for `Begin`; both are the same pool without the flag.
- ClickHouse backend unchanged: its per-query `readonly`, `max_execution_time`,
  `max_result_rows`, `result_overflow_mode` settings are admitted by the user's
  `CHANGEABLE_IN_READONLY` constraints, bounded by the policy values.

## What passes

`E2E=1 go test ./e2e/... -count=1` against the shared stack: 61 top-level tests,
all green (15.6 s). `gofmt -l .` empty, `go vet ./...` clean, no new
dependencies (`go.mod` unchanged).

New suites in `e2e/security_test.go`:

- `TestPostgresConnectionLevelSecurity` — boots with the flag and writes; as
  superuser checks `pg_roles` (login, no superuser/createrole/createdb/inherit/
  replication, `rolconfig = {search_path=public,statement_timeout=30000}`) and a
  19-entry `has_table_privilege` / `has_sequence_privilege` /
  `has_schema_privilege` matrix (ro: no SELECT on `forbidden_secrets`, no INSERT
  on `allowed_orders`; rw: INSERT/UPDATE/DELETE on `allowed_audit`, no UPDATE on
  `allowed_orders`, USAGE+SELECT on `allowed_audit_id_seq`, none on
  `allowed_seq`); then runs `execute_sql_readonly`, `list_schemas`,
  `list_objects`, `get_object_details`, `explain_query` plain and with a hypopg
  hypothetical index, and a begin → INSERT RETURNING → SELECT → commit flow; with
  the transaction open, `pg_stat_activity` filtered by a per-test
  `application_name` shows exactly `restrictedsql_ro,restrictedsql_rw` and never
  `postgres`; logs contain the provisioning summary and no verifier or DSN.
- `TestPostgresConnectionLevelSecurityNotProvisionedWhenUnprivileged` — creates
  `e2e_unpriv` (LOGIN, SELECT on the allowed tables only), boots as it with the
  flag; `/readyz` is 503 with a reason containing `not provisioned`, `permission
  denied` and the redacted `CREATE OR ALTER ROLE` statement, no DSN;
  `execute_sql_readonly` and `list_schemas` return `not provisioned`; the role is
  dropped in cleanup.
- `TestPostgresConnectionLevelSecurityReprovisionIdempotent` — two sequential
  boots; the same attribute/grant matrix holds after each, `pg_authid` verifiers
  are SCRAM and differ between boots (rotation), tools work after the second.
- `TestClickHouseConnectionLevelSecurity` — via HTTP as `default`: `system.users`
  has `restrictedsql_ro`; `system.grants` SELECT rows in `app` are exactly
  `allowed_customers, allowed_orders`; no grant mentions `forbidden_secrets`;
  `system.settings_profile_elements` shows `readonly=1` `CONST`; a request as
  `restrictedsql_ro` without a password is refused; then read (including
  `max_rows` truncation under the pinned settings), metadata and explain tools
  through MCP.

All pre-existing suites still pass with the flag off (behaviour unchanged: one
pool on the DSN).

## Decisions

- **Gate wrapper instead of a mutable pool holder.** Keeping `db.Backend`
  unchanged and constructing the real backend only after provisioning was the
  smallest change: the concrete backends gained one constructor, the handlers
  and the registry did not change at all.
- **ClickHouse `readonly = 1` at the user, with `CHANGEABLE_IN_READONLY` caps.**
  Probing the live server showed a `readonly = 1` user rejects any per-query
  setting change, including the ones the backend already sends. Instead of
  weakening to `readonly = 2` or removing the backend's settings, the user
  profile admits exactly those four settings with the policy values as hard
  maxima; a caller can lower but never raise the limits.
- **SCRAM verifier client-side.** Avoids the plaintext password in the
  `CREATE/ALTER ROLE` statement (which `log_statement = 'all'` would record).
  Falls back to a plaintext `PASSWORD` clause only when the server's
  `password_encryption` is not SCRAM.
- **`DO` block for create-or-alter.** Keeps the existence check and the
  CREATE/ALTER in the same transaction as the grants, so a failure anywhere
  rolls the whole thing back and the previous role state survives.
- **Revoke scope.** `REVOKE ... IN SCHEMA` needs `USAGE` on the schema, so
  only schemas the bootstrap can use are swept; `REVOKE ALL ON SCHEMA` (not
  just `USAGE`) also drops `CREATE`.
- **ClickHouse catalog grants.** `SHOW TABLES, SHOW COLUMNS ON db.*` for the
  read databases (as specified), which makes every table in those databases
  visible in `system.tables`/`system.columns` (metadata only, matching the
  server's stated catalog-visibility stance); other databases are invisible.
  `system.data_skipping_indices` needs an explicit `SELECT` grant, found by
  probing.
- **`application_name` in the test DSN** so the `pg_stat_activity` assertion is
  robust while other suites share the same Postgres.

## Risks and notes

- **Single replica.** Every boot rotates both passwords; a second process with
  the same prefix would break the first one's pools. Documented in README and
  the k8s manifest. Two servers with different `--security-role-prefix` values
  are fine.
- **`PUBLIC` grants and pre-existing memberships** are not revoked; a table
  granted to `PUBLIC` stays readable by the provisioned roles. Documented.
- **Bootstrap privilege model.** With a non-superuser bootstrap the grants only
  succeed for objects it owns or holds `WITH GRANT OPTION`; the error names the
  failing statement so the missing privilege is obvious.
- **Provisioning under the 3 s probe timeout.** Provisioning takes ~40 ms
  locally; on a slow database a probe could time out repeatedly while the boot
  attempt (10 s) would have succeeded. Tool calls retry with their own longer
  timeout, so a slow database still converges.
- **Lost roles at runtime.** If someone drops or re-passwords the roles while the
  server runs, the pools fail and `/readyz` reports the ping error; the gate does
  not re-provision automatically after a successful boot. A restart repairs it.
- **Pre-existing flake unrelated to this feature:** `TestPostgresWriteIdleTimeout`
  failed once in a full run under load ("reaper did not log the rollback") and
  passed three times in isolation. When the expired transaction is first touched
  by a tool call, the registry's own expiry path rolls it back and the reaper
  never logs `reaped`. Not changed here.
