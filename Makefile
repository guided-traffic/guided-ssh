MODULE       := github.com/guided-traffic/guided-ssh
IMAGE        ?= docker.io/guidedtraffic/guided-ssh
VERSION      ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT       ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE         ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
COVERAGE_MIN ?= 80
COVERAGE_DIR := coverage

# Threshold as in valkey-operator; tool versions pinned for reproducible CI
CYCLO_THRESHOLD ?= 15
GOCYCLO_VERSION ?= v0.6.0

LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.version=$(VERSION) \
	-X $(MODULE)/internal/version.commit=$(COMMIT) \
	-X $(MODULE)/internal/version.date=$(DATE)

.PHONY: all build cross packages test cover test-unit-coverage test-integration-coverage \
	e2e loadtest lint fmt gosec vuln cyclo image clean web web-api web-test

# Target platforms of the user CLI gssh (plan phase 4)
CROSS_PLATFORMS := linux/amd64 linux/arm64 darwin/arm64

all: lint cover build

## build: build all binaries into bin/ (static, versioned)
build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/ ./cmd/...

## cross: build gssh for all target platforms and gssh-agentd for linux
cross:
	@for platform in $(CROSS_PLATFORMS); do \
		echo "gssh for $$platform"; \
		GOOS=$${platform%/*} GOARCH=$${platform#*/} CGO_ENABLED=0 \
		go build -trimpath -ldflags '$(LDFLAGS)' \
			-o bin/gssh-$${platform%/*}-$${platform#*/} ./cmd/gssh || exit 1; \
	done
	@for arch in amd64 arm64; do \
		echo "gssh-agentd for linux/$$arch"; \
		GOOS=linux GOARCH=$$arch CGO_ENABLED=0 \
		go build -trimpath -ldflags '$(LDFLAGS)' \
			-o bin/gssh-agentd-linux-$$arch ./cmd/gssh-agentd || exit 1; \
	done

## packages: build deb/rpm for gssh-agentd (after `make cross`; needs nfpm)
packages:
	@command -v nfpm >/dev/null || { echo "nfpm missing — https://nfpm.goreleaser.com"; exit 1; }
	@mkdir -p dist bin/pkg
	@for arch in amd64 arm64; do \
		cp bin/gssh-agentd-linux-$$arch bin/pkg/gssh-agentd; \
		for fmt in deb rpm; do \
			VERSION=$(patsubst v%,%,$(VERSION)) ARCH=$$arch \
			nfpm package -f deploy/packaging/nfpm.yaml -p $$fmt -t dist/ || exit 1; \
		done; \
	done
	@rm -rf bin/pkg

## test: unit tests with race detector
test:
	go test -race ./...

## cover: unit + integration tests (Docker needed) with coverage across all packages + gate (>= $(COVERAGE_MIN) %)
cover:
	go test -race -tags integration -covermode=atomic -coverpkg=./... -coverprofile=coverage.out ./...
	hack/coverage.sh coverage.out $(COVERAGE_MIN)

## test-unit-coverage: unit tests only (no Docker) with coverage profile for the CI merge
test-unit-coverage:
	@mkdir -p $(COVERAGE_DIR)
	go test -race -covermode=atomic -coverpkg=./... -coverprofile=$(COVERAGE_DIR)/unit.out ./...

## test-integration-coverage: test suite incl. integration tests (Docker needed) with coverage profile for the CI merge
test-integration-coverage:
	@mkdir -p $(COVERAGE_DIR)
	go test -race -tags integration -count=1 -p 2 -covermode=atomic -coverpkg=./... -coverprofile=$(COVERAGE_DIR)/integration.out ./...

## e2e: end-to-end suite in the kind cluster (Docker, kind, kubectl, helm needed;
## ansible optional). Switches: E2E_KEEP=1, E2E_SKIP_BUILD=1, E2E_CLUSTER=name
e2e:
	go test -tags e2e -count=1 -timeout 45m -v ./test/e2e

## loadtest: load test of the sign endpoint (Docker needed for Postgres);
## target via GSSH_LOAD_TARGET_RATE (default 50 certificates/s)
loadtest:
	go test -tags loadtest -count=1 -timeout 10m -v ./test/load

## lint: golangci-lint (linter + formatting check)
lint:
	golangci-lint run

## fmt: format code (gofumpt/goimports via golangci-lint)
fmt:
	golangci-lint fmt

## gosec: gosec security rules only (respects the justified nolint exceptions)
gosec:
	golangci-lint run --enable-only gosec

## vuln: govulncheck against the current vulnerability database (deliberately @latest)
vuln:
	GOFLAGS="-buildvcs=false" go run golang.org/x/vuln/cmd/govulncheck@latest ./...

## cyclo: cyclomatic complexity, gate at > $(CYCLO_THRESHOLD) (tests excluded)
cyclo:
	go run github.com/fzipp/gocyclo/cmd/gocyclo@$(GOCYCLO_VERSION) -over $(CYCLO_THRESHOLD) -ignore "_test.go" .

## web: build the Angular UI (output web/dist, embedded via go:embed);
## the build empties dist — restore .gitkeep afterwards (go:embed placeholder)
web:
	cd web && npm ci && npx ng build && touch dist/.gitkeep

## web-api: regenerate the Angular API client from api/openapi.yaml
web-api:
	cd web && npx ng-openapi-gen --input ../api/openapi.yaml --output src/app/api

## web-test: frontend unit tests (vitest, headless)
web-test:
	cd web && npx ng test --watch=false

## image: build the container image locally
image:
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg DATE=$(DATE) \
		-t $(IMAGE):$(VERSION) .

## clean: remove build artifacts
clean:
	rm -rf bin coverage.out
