# Web UI stage: Angular build (Phase 8), embedded into the binary via go:embed
FROM node:24-bookworm-slim AS webbuild
WORKDIR /web

COPY web/package.json web/package-lock.json ./
RUN npm ci

COPY web/ .
RUN npx ng build

# Agent build stage: cross-build gssh-agentd and the gssh client for all
# target platforms. The binaries are embedded into the server binary
# (internal/agentdist, internal/clientdist) and shipped during the
# one-command host install respectively the client install — same build,
# same -ldflags, so a guaranteed version lockstep with the server.
#
# --platform=$BUILDPLATFORM is mandatory: otherwise this stage would run
# under QEMU for each target platform on buildx multi-arch builds (Go compile
# many times slower). This way the compiler runs natively and cross-compiles
# via GOOS/GOARCH; the stage is platform-invariant, so BuildKit deduplicates
# it. Every server variant embeds the full agent set (the amd64 server also
# contains arm64).
FROM --platform=$BUILDPLATFORM golang:1.26 AS agentbuild
WORKDIR /src

COPY go.* ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

RUN for arch in amd64 arm64; do \
      CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath \
        -ldflags "-s -w \
          -X github.com/guided-traffic/guided-ssh/internal/version.version=${VERSION} \
          -X github.com/guided-traffic/guided-ssh/internal/version.commit=${COMMIT} \
          -X github.com/guided-traffic/guided-ssh/internal/version.date=${DATE}" \
        -o /out/gssh-agentd-linux-$arch ./cmd/gssh-agentd || exit 1; \
    done

# Client binaries go into their own output directory: /out/ is COPY'd whole
# into internal/agentdist/bin/, so mixing the families would embed clients
# into the agent manifest. Platforms mirror CROSS_PLATFORMS in the Makefile.
RUN for platform in linux/amd64 linux/arm64 darwin/arm64; do \
      CGO_ENABLED=0 GOOS=${platform%/*} GOARCH=${platform#*/} go build -trimpath \
        -ldflags "-s -w \
          -X github.com/guided-traffic/guided-ssh/internal/version.version=${VERSION} \
          -X github.com/guided-traffic/guided-ssh/internal/version.commit=${COMMIT} \
          -X github.com/guided-traffic/guided-ssh/internal/version.date=${DATE}" \
        -o /out-client/gssh-${platform%/*}-${platform#*/} ./cmd/gssh || exit 1; \
    done

# Build stage
FROM golang:1.26 AS build
WORKDIR /src

# Dependencies first, for layer caching (go.sum appears with the first external dependency)
COPY go.* ./
RUN go mod download

COPY . .
COPY --from=webbuild /web/dist ./web/dist
# Identical -ldflags as in agentbuild — that is the version lockstep.
COPY --from=agentbuild /out/ ./internal/agentdist/bin/
COPY --from=agentbuild /out-client/ ./internal/clientdist/bin/

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

# gssh-admin ships in the image too: the GitOps grants sync (CronJob, Phase 12)
# invokes it with an overridden command — distroless has no shell.
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w \
        -X github.com/guided-traffic/guided-ssh/internal/version.version=${VERSION} \
        -X github.com/guided-traffic/guided-ssh/internal/version.commit=${COMMIT} \
        -X github.com/guided-traffic/guided-ssh/internal/version.date=${DATE}" \
      -o /out/ ./cmd/gssh-server ./cmd/gssh-admin

# Runtime stage: distroless, non-root, static binaries only
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/gssh-server /out/gssh-admin /usr/local/bin/
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/gssh-server"]
