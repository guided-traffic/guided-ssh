# guided-ssh

Zertifikatsbasierte SSH-Zugriffsplattform: kurzlebige SSH-Zertifikate statt statischer
`authorized_keys`, Single Sign-On über den bestehenden Identity Provider, maschinelle
Zugänge für CI-Pipelines (GitLab) und vollständige Auditierbarkeit aller Zugriffe.
Betrieb in Kubernetes via Helm, verwaltet über GitOps (FluxCD).

Plan und Fortschritt: [local_PLAN.md](local_PLAN.md)

## Repository-Struktur

| Pfad | Inhalt |
|---|---|
| `cmd/` | Binaries — `gssh-server` (API/CA); später `gssh`, `gssh-admin`, `gssh-agentd` |
| `internal/` | Go-Pakete (nicht öffentlich importierbar) |
| `api/` | OpenAPI-Spezifikation — Single Source of Truth der REST-API (ab Phase 8) |
| `web/` | Angular-Frontend, eingebettet ins Go-Binary (ab Phase 8) |
| `deploy/helm/` | Helm-Chart (ab Phase 11) |
| `docs/` | [Teststrategie](docs/teststrategie.md), [Bedrohungsmodell](docs/bedrohungsmodell.md), [CI-Runner](docs/ci-runner.md), [ADRs](docs/adr/README.md) |
| `hack/` | Hilfsskripte für Build und CI |

## Entwicklung

Voraussetzungen: Go ≥ 1.26, golangci-lint ≥ 2.x, Docker (Image-Builds, später Testcontainer).

```sh
make build   # Binaries nach bin/ (statisch, versioniert)
make test    # Unit-Tests mit Race-Detector
make cover   # Tests + Coverage-Gate (>= 80 %)
make lint    # golangci-lint
make fmt     # Formatierung (gofumpt/goimports)
make image   # Container-Image lokal bauen
```

CI (GitHub Actions, self-hosted Runner — Anforderungen: [docs/ci-runner.md](docs/ci-runner.md)):
Lint, Test mit Coverage-Gate, Build, Container-Image (Push nach `docker.io/guidedtraffic`
auf `main` und Tags; Tagging SemVer + `sha-<commit>`).

## Lizenz und Versionierung

Apache-2.0 ([LICENSE](LICENSE)). Semantic Versioning über Git-Tags `vX.Y.Z` —
Details in [ADR-011](docs/adr/011-versionierung-und-lizenz.md).
