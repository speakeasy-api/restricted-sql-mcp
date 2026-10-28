<img src="docs/assets/readme-hero.svg" alt="Restricted SQL MCP by Speakeasy. SQL access with explicit limits. PostgreSQL and ClickHouse." width="1200" />

# Restricted SQL MCP

Give an agent SQL access to Postgres or ClickHouse, with the tables, columns,
and statements it can use defined in policy.

Queries are parsed into an AST, checked against that policy, and rebuilt as
canonical SQL before reaching the database. Reads are the default. Postgres
writes are opt-in and run inside explicit transactions.

[Quick start](#quick-start) · [Configuration](docs/configuration.md) · [Tools](docs/tools.md) · [Contributing](CONTRIBUTING.md) · [AGPL v3](LICENSE)

## What it does

| Boundary | Behavior |
| --- | --- |
| Tables | Read and write allowlists, with fully qualified relation names. |
| Columns | Optional access classes from column annotations; missing annotations deny data access. |
| SQL | An AST visitor rejects unsupported statements, functions, types, and relations. |
| Database roles | Optional provisioning of restricted roles, separate from SQL validation. Required for annotation mode. |
| Writes | Postgres `INSERT`, `UPDATE`, and `DELETE`, inside a transaction you explicitly commit or roll back. |
| Transport | stdio, loopback HTTP, or an optional outbound Speakeasy Control Plane tunnel. |

A Speakeasy account is not required for stdio or direct loopback HTTP.

## Quick start

You need the Go version in [go.mod](go.mod) and a C compiler. The Postgres parser
uses cgo.

```sh
git clone https://github.com/speakeasy-api/restricted-sql-mcp.git
cd restricted-sql-mcp
go build -o bin/restrictedsql-mcp ./cmd/restrictedsql-mcp
```

Point the server at a database role with access to the intended tables. The URL
below is an example; supply your own credentials through your environment.

```sh
export DATABASE_URL='postgres://readonly:change-me@127.0.0.1:5432/app?sslmode=require'

./bin/restrictedsql-mcp \
  --dialect=postgres \
  --transport=stdio \
  --read-tables=public.orders,public.customers
```

For ClickHouse, use `--dialect=clickhouse`, a ClickHouse connection URL, and
allowlist names such as `app.orders`. ClickHouse is read-only.

### Connect an MCP client

Configure your client to launch the binary. Pass `DATABASE_URL` using the client's
environment or secret configuration; do not commit database credentials.

```json
{
  "mcpServers": {
    "restricted-sql": {
      "command": "/absolute/path/to/bin/restrictedsql-mcp",
      "args": [
        "--dialect=postgres",
        "--transport=stdio",
        "--read-tables=public.orders,public.customers"
      ]
    }
  }
}
```

## Running

For direct HTTP, replace `--transport=stdio` with `--transport=http`. The default
listener is `127.0.0.1:8080`, with MCP at `/mcp`. Keep it on loopback unless you
provide an appropriate authenticated boundary.

| Endpoint | Purpose |
| --- | --- |
| `/mcp` | Stateless Streamable HTTP MCP endpoint. |
| `/healthz` | Process liveness. |
| `/readyz` | Database connectivity, security setup, and metadata refresh. |

`--health-listen=0.0.0.0:8081` exposes just the probes on a separate listener.
Dropping an allowlisted table does not make the whole server unready; queries
against that table fail. Surviving tables pick up column changes on metadata
refresh.

[All flags, startup behavior, and refresh rules →](docs/configuration.md)

## How SQL is checked

```text
SQL → parse → validate policy → deparse canonical SQL → restricted database session
```

Postgres uses `pg_query_go`, based on the Postgres grammar. ClickHouse uses
`clickhouse-sql-parser`. Both guards reject unsupported AST nodes and operations.
Tables are fully qualified in the canonical SQL sent to the database.

Postgres read tools use read-only transactions with a pinned `search_path` and
statement timeout. ClickHouse read tools use `readonly=1` and query limits.

### Connection-level security

`--connection-level-security` treats `DATABASE_URL` as a bootstrap connection and
provisions database roles with the configured grants. Tool traffic then uses
those roles. The SQL guard and database permissions enforce separate boundaries.

Run one replica: startup rotates role passwords. Previously missing, explicitly
configured Postgres tables receive grants when metadata refresh discovers them,
without changing passwords or interrupting open transactions. New tables outside
the configured policy are not admitted automatically.

[Bootstrap permissions, grants, and limitations →](docs/configuration.md#connection-level-security)

### Column access

For read-only access based on column annotations:

```sh
./bin/restrictedsql-mcp \
  --dialect=postgres \
  --transport=stdio \
  --columns-from-annotations=confidential \
  --connection-level-security
```

The database owner defines the access classes. Unannotated or malformed columns
are denied. Annotation refresh coordinates catalog changes, grants, and active
queries.

[Column policy and migration procedure →](docs/column-access.md)

### Multi-database mode

`--databases='^app_preview_pr_[0-9]+$'` lets one Postgres server serve matching
preview databases alongside the default database. Each database gets its own
policy, pools, and provisioned roles. Additional databases open on demand and
are removed when they disappear.

[Database routing and lifecycle →](docs/configuration.md#multi-database-mode)

## Tools

| Tool | Use |
| --- | --- |
| `execute_sql_readonly` | Run a validated read query with bounded results. |
| `list_schemas`, `list_objects`, `get_object_details` | Inspect database structure. |
| `explain_query` | Inspect a query plan; Postgres also supports hypothetical indexes. |
| `list_databases` | Discover served databases when multi-database mode is enabled. |
| `begin_transaction`, `execute_sql_write` | Run opt-in Postgres writes within a transaction. |
| `commit_transaction`, `rollback_transaction` | Explicitly finish a write transaction. |

### Writes stay explicit

Enable writes with both `--write-tables=public.audit` and
`--dangerously-add-write-tools`. The workflow is:

```text
begin_transaction → execute_sql_write → inspect results → commit_transaction
                                                     ↘ rollback_transaction
```

Transactions expire after configured idle and lifetime limits. DDL remains
rejected. Read-only deployments do not register the write tools.

[Tool inputs, outputs, examples, and dialect limits →](docs/tools.md)

## Deployment

Build the release image locally:

```sh
docker build --build-arg VERSION=dev -t restrictedsql-mcp:dev .
docker run --rm restrictedsql-mcp:dev --help
```

Release images are published to
[`ghcr.io/speakeasy-api/restricted-sql-mcp`](https://github.com/speakeasy-api/restricted-sql-mcp/pkgs/container/restricted-sql-mcp).
Pin a digest for deployments. The image runs as a non-root user and includes
project and third-party license notices.

[Container builds, Kubernetes, and tunnel-only deployments →](docs/deployment.md)

## Development

```sh
go test -race ./internal/... ./cmd/...
go vet ./...
```

The integration suite runs the real binary against synthetic Postgres and
ClickHouse fixtures through an MCP client. Docker Compose is needed for these
suites; see the fixture ports before starting another stack.

[Contributing](CONTRIBUTING.md) · [Integration suites and local setup](docs/development.md)

## Releases

Versions use Changesets. Server, dependency, and container changes need a
changeset; the release workflow creates the version PR and signed multi-platform
images.

[Latest releases](https://github.com/speakeasy-api/restricted-sql-mcp/releases) · [Release process](docs/development.md#releases)

## Security

Report vulnerabilities privately to **security@speakeasy.com**. Include a version
and a reproduction against a synthetic database. Keep credentials, real query
results, and SQL guard bypasses out of public issues.

[Security reporting policy →](SECURITY.md)

## License

Copyright 2026 Speakeasy. Licensed under the
[GNU Affero General Public License, version 3](LICENSE) (`AGPL-3.0-only`), matching
the embedded Gram tunnel agent's license version. Third-party dependencies
retain their own licenses and attribution in [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).
