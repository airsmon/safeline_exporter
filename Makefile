BINARY := safeline_exporter
VERSION ?= $(shell cat VERSION)
REVISION ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.revision=$(REVISION) -X main.buildDate=$(BUILD_DATE)

.PHONY: all build test test-race vet fmt fmt-check check docker-build dashboard-check helm-lint

all: check build

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) .

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w main.go collector/*.go config/*.go safeline/*.go

fmt-check:
	@test -z "$$(gofmt -l main.go collector/*.go config/*.go safeline/*.go)" || \
		(printf 'Go files need formatting:\n%s\n' "$$(gofmt -l main.go collector/*.go config/*.go safeline/*.go)"; exit 1)

dashboard-check:
	jq empty grafana/*.json

helm-lint:
	helm lint charts/safeline-exporter
	helm template safeline-exporter charts/safeline-exporter >/dev/null

check: fmt-check vet test dashboard-check

docker-build:
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg REVISION=$(REVISION) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t safeline-exporter:$(VERSION) .
