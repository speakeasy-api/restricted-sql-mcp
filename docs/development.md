# Development and releases

Run these commands from the repository root.

## Development

Requirements: Go 1.27, a C compiler (cgo for `pg_query_go`), Docker with Compose.

```
make build      # bin/restrictedsql-mcp
make vet        # gofmt + go vet
make test       # policy, admission, and SQL-binding tests
make e2e-up     # start the shared Postgres (with hypopg) and ClickHouse stack
make e2e        # e2e-up, then E2E=1 go test ./e2e/...
make e2e-pg     # only Postgres and common suites
make e2e-ch     # only ClickHouse and common suites
make e2e-annotations # column access, grants, reload, and migration suites
```

Unit tests cover annotation parsing, binding, canonicalization, expansion limits,
and admission invalidation under refresh failures. Run them with the race
detector using `go test -race ./internal/... ./cmd/...`.

The e2e suite builds the real binary once, boots it as a
subprocess per test with the flags under test, waits for `/readyz`, and drives it
with the go-sdk MCP client over Streamable HTTP. Subprocess logs (debug level) are
printed on failure. Without `E2E=1` the package exits immediately so
`go test ./...` stays fast.

Annotation fixtures contain synthetic safe, PII, content, secret, restricted and
unannotated values. Tests cover both HTTP and stdio, hidden inputs in SQL clauses,
direct restricted credentials, schema changes, canceled in-flight results,
unsupported dependencies, and the existing SQL bypass corpus.

The compose stack binds Postgres to `127.0.0.1:55433` (55432 is often taken by
other local databases) and ClickHouse to `127.0.0.1:59000` (native) and
`127.0.0.1:58123` (HTTP). Override with `E2E_PG_PORT`, `E2E_CH_NATIVE_PORT`,
`E2E_CH_HTTP_PORT`, or point the tests at other databases with `E2E_PG_DSN` and
`E2E_CH_DSN`. The stack is shared between parallel work streams; `make e2e-down`
tears it down and should be run deliberately.

`E2E_CH_VERSION` selects the Compose ClickHouse image (default `25.8`). Column
access is also tested against the Speakeasy Control Plane's pinned `26.2.19.43`; use a separate Compose
project and ports when running that version beside the shared stack.

## Releases

Versions follow semver and are cut with [changesets](https://github.com/changesets/changesets):
add one to every PR that changes the server (`npx changeset`, then pick patch, minor
or major); the Changeset check fails a PR that changes Go code, modules or the
Dockerfile without one (label `no-changeset` to skip). On main the Release workflow keeps a "chore: version packages" PR open
with the version bump and `CHANGELOG.md`; merging it tags `vX.Y.Z`, creates the GitHub
release and publishes `ghcr.io/speakeasy-api/restricted-sql-mcp:X.Y.Z` (plus `:X.Y`
and `:latest`), signed with cosign. Every commit on main is also published as
`:sha-<commit>`. Deploy by digest.
