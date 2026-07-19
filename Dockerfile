# Web-UI-Stage: Angular-Build (Phase 8), wird via go:embed ins Binary eingebettet
FROM node:24-bookworm-slim AS webbuild
WORKDIR /web

COPY web/package.json web/package-lock.json ./
RUN npm ci

COPY web/ .
RUN npx ng build

# Build-Stage
FROM golang:1.26 AS build
WORKDIR /src

# Abhängigkeiten zuerst, für Layer-Caching (go.sum entsteht mit der ersten externen Dependency)
COPY go.* ./
RUN go mod download

COPY . .
COPY --from=webbuild /web/dist ./web/dist

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
