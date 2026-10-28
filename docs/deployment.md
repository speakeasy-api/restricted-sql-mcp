# Deployment

Run these commands from the repository root.

The root `Dockerfile` builds the release image with cgo and runs it as a non-root
user on distroless Debian. To build the same image locally:

```sh
docker build --build-arg VERSION=dev -t restrictedsql-mcp:dev .
docker run --rm restrictedsql-mcp:dev --help
```

`deploy/Dockerfile` is an alternative image that builds with
`golang:1.27-bookworm` (gcc for cgo) and ships a
`debian:bookworm-slim` image running as a non-root user with
`ENTRYPOINT ["/restrictedsql-mcp"]`:

```
docker build -f deploy/Dockerfile --build-arg VERSION=v0.1.0 -t restrictedsql-mcp:v0.1.0 .
docker run --rm restrictedsql-mcp:v0.1.0 --help
```

`deploy/k8s.yaml` is a single-replica Deployment with the liveness probe on
`/healthz`, readiness and startup probes on `/readyz`, `DATABASE_URL` and
`TUNNEL_*` from a Secret, and no Service or Ingress. `/mcp` listens on loopback,
where only the in-process tunnel agent reaches it. Kubelet probes the pod IP,
not loopback, so `--health-listen 0.0.0.0:8081` serves `/healthz` and `/readyz`
alone on a second port; `/mcp` there is a 404.

Set `TUNNEL_GATEWAY_URL` and `TUNNEL_KEY` and pass `--tunnel` to expose the server
through the Speakeasy Control Plane. The agent dials out and proxies to `http://<listen>/mcp`; the
readiness body reports the tunnel state without gating on it.

### Tunnel-only mode

A loopback bind is not isolation: any process on the host (or any container in
the same pod) can reach `/mcp`. `--tunnel-only` closes that path. At boot the
server generates a 256-bit token that never leaves process memory, pins it on the
local URL the in-process tunnel agent proxies to (the agent merges that query
into every request it forwards), and refuses any `/mcp` request without it with
`401`. The token is stripped before the MCP handler sees the request, is not
logged, and cannot be obtained through the tunnel. `/healthz` and `/readyz`
stay open for probes; use `--health-listen` to probe from outside the pod
without exposing `/mcp`. `--transport stdio` needs none of this: only the parent
process holds the pipe.
