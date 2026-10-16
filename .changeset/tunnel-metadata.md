---
"restricted-sql-mcp": patch
---

Tunnel metadata reports table counts instead of the full table list, so a
large allowlist (such as `<schema>.*`) no longer exceeds the gateway's
1024-byte limit and leaves the tunnel agent reconnecting forever.
