MODULE       := github.com/guided-traffic/guided-ssh
IMAGE        ?= docker.io/guidedtraffic/guided-ssh
VERSION      ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT       ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE         ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
COVERAGE_MIN ?= 80

LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.version=$(VERSION) \
	-X $(MODULE)/internal/version.commit=$(COMMIT) \
	-X $(MODULE)/internal/version.date=$(DATE)

.PHONY: all build test cover lint fmt image clean

all: lint cover build

## build: alle Binaries nach bin/ bauen (statisch, versioniert)
build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/ ./cmd/...

## test: Unit-Tests mit Race-Detector
test:
	go test -race ./...

## cover: Unit- + Integrationstests (Docker nötig) mit Coverage über alle Pakete + Gate (>= $(COVERAGE_MIN) %)
cover:
	go test -race -tags integration -covermode=atomic -coverpkg=./... -coverprofile=coverage.out ./...
	hack/coverage.sh coverage.out $(COVERAGE_MIN)

## lint: golangci-lint (Linter + Formatierungsprüfung)
lint:
	golangci-lint run

## fmt: Code formatieren (gofumpt/goimports via golangci-lint)
fmt:
	golangci-lint fmt

## image: Container-Image lokal bauen
image:
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg DATE=$(DATE) \
		-t $(IMAGE):$(VERSION) .

## clean: Build-Artefakte entfernen
clean:
	rm -rf bin coverage.out
