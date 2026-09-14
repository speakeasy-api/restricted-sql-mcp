# Host ports for the shared e2e stack. Postgres defaults to 55433 because 55432
# is commonly occupied by other local containers. Override with
# E2E_PG_PORT / E2E_CH_NATIVE_PORT / E2E_CH_HTTP_PORT.
export E2E_PG_PORT ?= 55433
export E2E_CH_NATIVE_PORT ?= 59000
export E2E_CH_HTTP_PORT ?= 58123

COMPOSE := docker compose -f e2e/docker-compose.yml
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build vet e2e-up e2e-down e2e e2e-pg e2e-ch

build:
	CGO_ENABLED=1 go build -trimpath -ldflags "-X main.version=$(VERSION)" -o bin/restrictedsql-mcp ./cmd/restrictedsql-mcp

vet:
	gofmt -l . | tee /dev/stderr | test -z "$$(cat)"
	go vet ./...

e2e-up:
	$(COMPOSE) up -d --build --wait
	@echo "postgres: 127.0.0.1:$(E2E_PG_PORT)  clickhouse native: 127.0.0.1:$(E2E_CH_NATIVE_PORT)  clickhouse http: 127.0.0.1:$(E2E_CH_HTTP_PORT)"

# The stack is shared by parallel work streams; only tear it down deliberately.
e2e-down:
	$(COMPOSE) down -v

e2e: e2e-up
	E2E=1 go test ./e2e/... -count=1 -v -timeout 20m

e2e-pg: e2e-up
	E2E=1 go test ./e2e/... -count=1 -v -timeout 20m -run 'Postgres|Common'

e2e-ch: e2e-up
	E2E=1 go test ./e2e/... -count=1 -v -timeout 20m -run 'ClickHouse|Common'
