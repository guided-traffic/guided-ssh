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

.PHONY: all build cross packages test cover lint fmt image clean

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
