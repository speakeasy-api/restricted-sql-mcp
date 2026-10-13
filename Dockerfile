# pg_query_go needs cgo, so build against glibc and run on distroless/base.
FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=1 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/restrictedsql-mcp ./cmd/restrictedsql-mcp

FROM gcr.io/distroless/base-debian12:nonroot
COPY --from=build /out/restrictedsql-mcp /restrictedsql-mcp
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/restrictedsql-mcp"]
