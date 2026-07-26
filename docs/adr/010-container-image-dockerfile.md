# ADR-010: Container image via Dockerfile (instead of ko)

- Status: accepted
- Date: 2026-07-19

## Context

The plan left `ko` vs. Dockerfile open. `ko` builds Go images without a
Docker daemon, but only handles Go — the Angular build (ADR-003) must run
before `go build`, and the self-hosted runner needs Docker anyway for
Testcontainers.

## Decision

Multi-stage Dockerfile: build stage `golang`, runtime stage
`gcr.io/distroless/static-debian12:nonroot`, static binary, non-root. The
Angular build is added in Phase 8 as an additional stage (or CI step). Push
to `docker.io/guidedtraffic` (Docker Hub) via `docker/build-push-action`,
only on main and tags; credentials as GitHub secrets (`DOCKERHUB_USERNAME`,
`DOCKERHUB_TOKEN`). Tagging: SemVer (on Git tags) + `sha-<commit>`.

## Consequences

- A single tool (Docker/buildx) for tests and image builds — no `ko` to install.
- Distroless + non-root + static binary: minimal attack surface, matching the
  PodSecurityContext requirements from Phase 11.
- Version/commit are baked in as build args in `internal/version` — the same
  mechanism as `make build`.
