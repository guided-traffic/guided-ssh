MODULE       := github.com/guided-traffic/guided-ssh
IMAGE        ?= docker.io/guidedtraffic/guided-ssh
VERSION      ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT       ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE         ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
COVERAGE_MIN ?= 80
COVERAGE_DIR := coverage

# Schwellwert wie in valkey-operator; Tool-Versionen gepinnt für reproduzierbare CI
CYCLO_THRESHOLD ?= 15
GOCYCLO_VERSION ?= v0.6.0

LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.version=$(VERSION) \
	-X $(MODULE)/internal/version.commit=$(COMMIT) \
	-X $(MODULE)/internal/version.date=$(DATE)

.PHONY: all build cross packages test cover test-unit-coverage test-integration-coverage \
	e2e loadtest lint fmt gosec vuln cyclo image clean web web-api web-test

# Zielplattformen des Benutzer-CLI gssh (Plan Phase 4)
CROSS_PLATFORMS := linux/amd64 linux/arm64 darwin/arm64

all: lint cover build

## build: alle Binaries nach bin/ bauen (statisch, versioniert)
build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/ ./cmd/...

## cross: gssh für alle Zielplattformen und gssh-agentd für linux bauen
cross:
	@for platform in $(CROSS_PLATFORMS); do \
		echo "gssh für $$platform"; \
		GOOS=$${platform%/*} GOARCH=$${platform#*/} CGO_ENABLED=0 \
		go build -trimpath -ldflags '$(LDFLAGS)' \
			-o bin/gssh-$${platform%/*}-$${platform#*/} ./cmd/gssh || exit 1; \
	done
	@for arch in amd64 arm64; do \
		echo "gssh-agentd für linux/$$arch"; \
		GOOS=linux GOARCH=$$arch CGO_ENABLED=0 \
		go build -trimpath -ldflags '$(LDFLAGS)' \
			-o bin/gssh-agentd-linux-$$arch ./cmd/gssh-agentd || exit 1; \
	done

## packages: deb/rpm für gssh-agentd bauen (nach `make cross`; braucht nfpm)
packages:
	@command -v nfpm >/dev/null || { echo "nfpm fehlt — https://nfpm.goreleaser.com"; exit 1; }
	@mkdir -p dist
	@for arch in amd64 arm64; do \
		for fmt in deb rpm; do \
			VERSION=$(patsubst v%,%,$(VERSION)) ARCH=$$arch \
			nfpm package -f deploy/packaging/nfpm.yaml -p $$fmt -t dist/ || exit 1; \
		done; \
	done

## test: Unit-Tests mit Race-Detector
test:
	go test -race ./...

## cover: Unit- + Integrationstests (Docker nötig) mit Coverage über alle Pakete + Gate (>= $(COVERAGE_MIN) %)
cover:
	go test -race -tags integration -covermode=atomic -coverpkg=./... -coverprofile=coverage.out ./...
	hack/coverage.sh coverage.out $(COVERAGE_MIN)

## test-unit-coverage: nur Unit-Tests (ohne Docker) mit Coverage-Profil für den CI-Merge
test-unit-coverage:
	@mkdir -p $(COVERAGE_DIR)
	go test -race -covermode=atomic -coverpkg=./... -coverprofile=$(COVERAGE_DIR)/unit.out ./...

## test-integration-coverage: Testsuite inkl. Integrationstests (Docker nötig) mit Coverage-Profil für den CI-Merge
test-integration-coverage:
	@mkdir -p $(COVERAGE_DIR)
	go test -race -tags integration -count=1 -covermode=atomic -coverpkg=./... -coverprofile=$(COVERAGE_DIR)/integration.out ./...

## e2e: End-to-End-Suite im kind-Cluster (Docker, kind, kubectl, helm nötig;
## ansible optional). Schalter: E2E_KEEP=1, E2E_SKIP_BUILD=1, E2E_CLUSTER=name
e2e:
	go test -tags e2e -count=1 -timeout 45m -v ./test/e2e

## loadtest: Lasttest des Sign-Endpoints (Docker für Postgres nötig);
## Ziel per GSSH_LOAD_TARGET_RATE (Default 50 Zertifikate/s)
loadtest:
	go test -tags loadtest -count=1 -timeout 10m -v ./test/load

## lint: golangci-lint (Linter + Formatierungsprüfung)
lint:
	golangci-lint run

## fmt: Code formatieren (gofumpt/goimports via golangci-lint)
fmt:
	golangci-lint fmt

## gosec: nur die gosec-Security-Regeln (respektiert die begründeten nolint-Ausnahmen)
gosec:
	golangci-lint run --enable-only gosec

## vuln: govulncheck gegen die aktuelle Schwachstellen-Datenbank (bewusst @latest)
vuln:
	GOFLAGS="-buildvcs=false" go run golang.org/x/vuln/cmd/govulncheck@latest ./...

## cyclo: zyklomatische Komplexität, Gate bei > $(CYCLO_THRESHOLD) (Tests ausgenommen)
cyclo:
	go run github.com/fzipp/gocyclo/cmd/gocyclo@$(GOCYCLO_VERSION) -over $(CYCLO_THRESHOLD) -ignore "_test.go" .

## web: Angular-UI bauen (Ausgabe web/dist, wird via go:embed eingebettet);
## der Build leert dist — .gitkeep danach wiederherstellen (go:embed-Platzhalter)
web:
	cd web && npm ci && npx ng build && touch dist/.gitkeep

## web-api: Angular-API-Client aus api/openapi.yaml neu generieren
web-api:
	cd web && npx ng-openapi-gen --input ../api/openapi.yaml --output src/app/api

## web-test: Frontend-Unit-Tests (vitest, headless)
web-test:
	cd web && npx ng test --watch=false

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
