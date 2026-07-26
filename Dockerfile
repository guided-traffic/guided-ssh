# Web-UI-Stage: Angular-Build (Phase 8), wird via go:embed ins Binary eingebettet
FROM node:24-bookworm-slim AS webbuild
WORKDIR /web

COPY web/package.json web/package-lock.json ./
RUN npm ci

COPY web/ .
RUN npx ng build

# Agent-Build-Stage: gssh-agentd für alle Ziel-Arches cross-bauen. Die Binaries
# werden ins Server-Binary eingebettet (internal/agentdist) und beim
# One-Command-Host-Install ausgeliefert — gleicher Build, gleiche -ldflags,
# also garantierter Versions-Lockstep mit dem Server.
#
# --platform=$BUILDPLATFORM ist zwingend: sonst liefe diese Stage bei
# buildx-Multi-Arch je Zielplattform unter QEMU (Go-Compile um ein Vielfaches
# langsamer). So läuft der Compiler nativ und crosst via GOOS/GOARCH; die Stage
# ist plattform-invariant, BuildKit dedupliziert sie. Jede Server-Variante
# bettet den vollständigen Agent-Satz ein (amd64-Server enthält auch arm64).
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

# Build-Stage
FROM golang:1.26 AS build
WORKDIR /src

# Abhängigkeiten zuerst, für Layer-Caching (go.sum entsteht mit der ersten externen Dependency)
COPY go.* ./
RUN go mod download

COPY . .
COPY --from=webbuild /web/dist ./web/dist
# Identische -ldflags wie in agentbuild — das ist der Versions-Lockstep.
COPY --from=agentbuild /out/ ./internal/agentdist/bin/

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

# gssh-admin liegt mit im Image: der GitOps-Grants-Sync (CronJob, Phase 12)
# ruft es mit überschriebenem command auf — distroless hat keine Shell.
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w \
        -X github.com/guided-traffic/guided-ssh/internal/version.version=${VERSION} \
        -X github.com/guided-traffic/guided-ssh/internal/version.commit=${COMMIT} \
        -X github.com/guided-traffic/guided-ssh/internal/version.date=${DATE}" \
      -o /out/ ./cmd/gssh-server ./cmd/gssh-admin

# Runtime-Stage: distroless, non-root, nur die statischen Binaries
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/gssh-server /out/gssh-admin /usr/local/bin/
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/gssh-server"]
