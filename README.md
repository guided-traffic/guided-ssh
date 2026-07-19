# guided-ssh

![Coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fguided-traffic%2Fguided-ssh%2Fmain%2F.github%2Fbadges%2Fcoverage.json)

Zertifikatsbasierte SSH-Zugriffsplattform: kurzlebige SSH-Zertifikate statt statischer
`authorized_keys`, Single Sign-On über den bestehenden Identity Provider, maschinelle
Zugänge für CI-Pipelines (GitLab) und vollständige Auditierbarkeit aller Zugriffe.
Betrieb in Kubernetes via Helm, verwaltet über GitOps (FluxCD).

Plan und Fortschritt: [INITIAL_PROJECT_PLAN.md](INITIAL_PROJECT_PLAN.md)

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

## gssh-server

API-Server mit integrierter Zertifizierungsstelle (CA). Beim Start laufen die
Datenbank-Migrationen; fehlen CA-Keys, werden sie erzeugt (je ein Ed25519-Key
für Benutzer- und Host-Zertifikate, Private Keys AES-256-GCM-verschlüsselt in
der Datenbank, siehe [ADR-014](docs/adr/014-software-signer-aes-gcm.md)).

```sh
gssh-server -listen :8080    # HTTP-API starten
gssh-server -version         # Version ausgeben
```

Konfiguration über Umgebungsvariablen:

| Variable | Bedeutung |
|---|---|
| `GSSH_DB_DSN` | PostgreSQL-DSN, z. B. `postgres://user:pass@host:5432/db` |
| `GSSH_CA_MASTER_KEY` | Master-Key für die CA-Key-Verschlüsselung: 32 Bytes, Base64 (z. B. `head -c 32 /dev/urandom \| base64`) |

Endpunkte (Phase 2 — Sign-Endpoints folgen ab Phase 3):

| Endpoint | Bedeutung |
|---|---|
| `GET /healthz` | Liveness |
| `GET /v1/ca/bundle/user` | Public Keys der Benutzer-CA (authorized_keys-Format) — Inhalt für `TrustedUserCAKeys` auf Hosts |
| `GET /v1/ca/bundle/host` | Public Keys der Host-CA — für `@cert-authority`-Einträge in `known_hosts` |

Die Bundles enthalten alle aktiven und in Ablösung befindlichen Keys
(Übergangsfenster bei Key-Rotation).

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
