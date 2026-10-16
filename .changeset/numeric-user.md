---
"restricted-sql-mcp": patch
---

The image runs as the numeric user 65532 instead of the name `nonroot`, so
Kubernetes `runAsNonRoot` works without setting `runAsUser`.
