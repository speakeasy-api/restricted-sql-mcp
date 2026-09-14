FROM golang:1.27-bookworm AS build
ARG VERSION=dev
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=1 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/restrictedsql-mcp ./cmd/restrictedsql-mcp

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/restrictedsql-mcp /restrictedsql-mcp
USER 65532:65532
ENTRYPOINT ["/restrictedsql-mcp"]
