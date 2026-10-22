---
"restricted-sql-mcp": patch
---

The embedded tunnel agent is upgraded to the current Speakeasy release. It now
reports network checks of the local MCP listener, so the MCP server's Overview
shows whether the agent can reach it instead of "Diagnostics unsupported".
Requests are forwarded exactly as before. The build image moves to Go 1.27.3,
which the upgraded agent requires.
