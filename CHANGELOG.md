# restricted-sql-mcp

## 0.2.5

### Patch Changes

- c5b8082: License the project under GNU AGPL version 3, matching the embedded Gram tunnel dependency. Include license notices in container images, declare the SPDX license in package and image metadata, and add contribution and private security reporting guidance for public use.

## 0.2.4

### Patch Changes

- 6e1e627: Simplify readiness to check database connectivity, security provisioning and metadata refresh instead of requiring every allowlisted table to exist. Schema migrations no longer make the whole server unready; queries against missing tables still fail, while surviving tables pick up column changes.
  
  Postgres tool queries no longer cache prepared statement result shapes, so repeated SELECT * and RETURNING * queries tolerate column migrations.
  
  Postgres provisioning rechecks the catalog on every attempt and skips deleted allowlisted tables, so stale configuration does not block startup or retries.
  
  Previously missing, explicitly configured Postgres tables receive grants when metadata refresh discovers them, without rotating passwords or interrupting active transactions.

## 0.2.3

### Patch Changes

- 8d01ba4: The embedded tunnel agent is upgraded to the current Speakeasy release. It now
  reports network checks of the local MCP listener, so the MCP server's Overview
  shows whether the agent can reach it instead of "Diagnostics unsupported".
  Requests are forwarded exactly as before. The build image moves to Go 1.27.3,
  which the upgraded agent requires.

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
