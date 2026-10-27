---
"restricted-sql-mcp": patch
---

Simplify readiness to check database connectivity, security provisioning and metadata refresh instead of requiring every allowlisted table to exist. Schema migrations no longer make the whole server unready; queries against missing tables still fail, while surviving tables pick up column changes.

Postgres tool queries no longer cache prepared statement result shapes, so repeated SELECT * and RETURNING * queries tolerate column migrations.

Postgres provisioning rechecks the catalog on every attempt and skips deleted allowlisted tables, so stale configuration does not block startup or retries.
