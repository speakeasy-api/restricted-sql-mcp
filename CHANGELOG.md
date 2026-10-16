# restricted-sql-mcp

## 0.2.0

### Minor Changes

- 5aaa6b6: First release cut with changesets. Stateless MCP (2026-07-28) over
  allowlisted SQL for Postgres and ClickHouse, with connection-level security,
  multi-database mode, write transactions bounded by an idle timeout and a 5
  minute lifetime (each closing its connection when it ends), bounded
  connection pools, a probe pool for readiness, a separate health listener, and
  tunnel-only access through the Speakeasy Control Plane tunnel.

Releases before v0.2.0 (v0.1.0 to v0.1.2) were tagged by hand and have no
entries here.
