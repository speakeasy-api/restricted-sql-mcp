---
"restricted-sql-mcp": patch
---

Remove the configurable WAL replay floor. Restricted SQL continues to require a physical standby and verify the live replica catalog and reader grants.
