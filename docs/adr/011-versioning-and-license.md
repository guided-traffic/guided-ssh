# ADR-011: Versioning (SemVer) and license (Apache-2.0)

- Status: accepted
- Date: 2026-07-19

## Context

Phase 0 requires a fixed versioning scheme and a license. Releases comprise
multiple artifacts (binaries, container image, Helm chart) that must work
together.

## Decision

- **License: Apache-2.0** (LICENSE lives in the repo) — patent clause,
  enterprise-friendly, common in the cloud-native ecosystem.
- **Versioning: Semantic Versioning 2.0.0** via Git tags `vX.Y.Z`.
  `0.x` until the MVP (breaking changes allowed); from `1.0.0` onward, SemVer
  applies strictly to the API, CLI flags, Helm values, and DB migrations
  (forward-only).
- Binaries, container image, and Helm chart (`appVersion`) are tagged
  **together** with the same version per release; the chart's `version` may
  patch independently for chart-only fixes.
- Build metadata (`version`, `commit`, `date`) is baked into
  `internal/version` via `-ldflags` (`git describe --tags`).

## Consequences

- Clear mapping from support request to code state (`gssh-server -version`).
- Release = push a tag; the pipeline builds and publishes all artifacts consistently.
- SemVer discipline from 1.0.0 onward enforces deliberate API evolution
  (OpenAPI diff in review).
