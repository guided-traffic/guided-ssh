# ADR-010: Container-Image via Dockerfile (statt ko)

- Status: akzeptiert
- Datum: 2026-07-19

## Kontext

Der Plan ließ `ko` oder Dockerfile offen. `ko` baut Go-Images ohne Docker-Daemon,
kann aber nur Go — der Angular-Build (ADR-003) muss vor dem `go build` laufen,
und der self-hosted Runner braucht Docker ohnehin für Testcontainer.

## Entscheidung

Multi-Stage-Dockerfile: Build-Stage `golang`, Runtime-Stage
`gcr.io/distroless/static-debian12:nonroot`, statisches Binary, non-root.
Der Angular-Build kommt in Phase 8 als zusätzliche Stage (oder CI-Schritt) hinzu.
Push nach `docker.io/guidedtraffic` (Docker Hub) via `docker/build-push-action`,
nur auf main und Tags; Credentials als GitHub-Secrets (`DOCKERHUB_USERNAME`,
`DOCKERHUB_TOKEN`). Tagging: SemVer (bei Git-Tags) + `sha-<commit>`.

## Konsequenzen

- Ein Werkzeug (Docker/buildx) für Tests und Image-Builds — kein `ko` zu installieren.
- Distroless + non-root + statisches Binary: minimale Angriffsfläche, passt zu den
  PodSecurityContext-Vorgaben aus Phase 11.
- Version/Commit werden als Build-Args in `internal/version` eingebrannt —
  identische Mechanik wie `make build`.
