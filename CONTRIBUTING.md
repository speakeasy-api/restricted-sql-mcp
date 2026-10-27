# Contributing

Bug reports, focused fixes, and tests are welcome. For security issues, follow
[SECURITY.md](SECURITY.md) instead of opening a public issue.

## Local development

Install the Go version specified in `go.mod` and a C compiler (`pg_query_go` uses
cgo). Docker Compose is needed only for integration tests. Node.js 22 and npm are
needed only to manage changesets and releases; the server is written in Go.

```sh
go build ./cmd/restrictedsql-mcp
go test -race ./internal/... ./cmd/...
go vet ./...
```

Use `gofmt` on changed Go files. Add a regression test for behavior changes,
especially changes to SQL validation, database privileges, or transaction handling.
See [development and integration tests](docs/development.md) for suites and fixture ports.
Use synthetic databases; never include real credentials, customer data, or query
results from a live service in tests or reports.

## Pull requests

Describe the problem, resulting behavior, and checks you ran. Keep unrelated
changes separate. Changes to the server, its dependencies, or its container image
need a changeset:

```sh
npm ci --ignore-scripts
npx changeset
```

The root npm package is private because it is release tooling, not a published npm
library. This does not control the repository's source visibility or license.

Contributions to this repository are submitted under [GNU Affero General Public License, version 3](LICENSE)
(`AGPL-3.0-only`).
After changing Go dependencies, regenerate their notices and include the result:

```sh
python3 scripts/update-third-party-notices.py
```

Preserve third-party copyright and license notices. Changes involving copied or
vendored code must identify its source and license in the pull request.
