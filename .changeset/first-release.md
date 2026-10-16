---
"restricted-sql-mcp": minor
---

First release cut with changesets. Stateless MCP (2026-07-28) over
allowlisted SQL for Postgres and ClickHouse, with connection-level security,
multi-database mode, write transactions bounded by an idle timeout and a 5
minute lifetime (each closing its connection when it ends), bounded
connection pools, a probe pool for readiness, a separate health listener, and
tunnel-only access through the Speakeasy Control Plane tunnel.
