# restricted-sql-mcp

## 0.2.2

### Patch Changes

- 572d455: Tunnel metadata reports table counts instead of the full table list, so a
  large allowlist (such as `<schema>.*`) no longer exceeds the gateway's
  1024-byte limit and leaves the tunnel agent reconnecting forever.

## 0.2.1

### Patch Changes

- d8a1730: The image runs as the numeric user 65532 instead of the name `nonroot`, so
  Kubernetes `runAsNonRoot` works without setting `runAsUser`.

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
