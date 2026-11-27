---
"restricted-sql-mcp": patch
---

Wait for the grant job's revision on the read replica before serving, so deployments no longer need to pin a WAL position.
