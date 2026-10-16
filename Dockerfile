# pg_query_go needs cgo, so build against glibc and run on distroless/base.
FROM golang:1.27-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=1 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/restrictedsql-mcp ./cmd/restrictedsql-mcp

FROM gcr.io/distroless/base-debian12:nonroot@sha256:7f0c72cd138b442ae0deeb69c08b1acf5525439ba251a49ad93c320a061567e5
COPY --from=build /out/restrictedsql-mcp /restrictedsql-mcp
# Numeric so Kubernetes runAsNonRoot can verify it (distroless nonroot is 65532).
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/restrictedsql-mcp"]
