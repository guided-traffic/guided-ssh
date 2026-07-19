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
| `cmd/` | Binaries — `gssh-server` (API/CA), `gssh` (Benutzer-CLI); später `gssh-admin`, `gssh-agentd` |
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

## gssh (Benutzer-CLI)

SSO-Login gegen den IdP, kurzlebiges SSH-Zertifikat vom Server — Schlüsselpaar
und Zertifikat leben ausschließlich im `ssh-agent`, nichts wird auf Platte
persistiert ([ADR-016](docs/adr/016-cli-gssh-agent-only.md)).

```sh
gssh login               # SSO im Browser, Zertifikat in den ssh-agent
gssh login --device      # Device-Flow (headless, ohne Browser)
gssh ssh <host> …        # wie ssh, mit Auto-Login bei fehlendem Zertifikat
gssh status              # Zertifikatsstatus; Exit-Code 1 ohne gültiges Zertifikat
gssh logout              # guided-ssh-Einträge aus dem Agenten entfernen
gssh integrate           # ssh_config-Schnipsel für transparentes natives ssh
```

Konfiguration in `~/.config/guided-ssh/config.yaml` (Override: `--config`
bzw. `GSSH_CONFIG`):

```yaml
api_url: https://gssh.example.com
issuer: https://idp.example.com/realms/example
client_id: gssh-cli
# optional:
# pin_sha256: <Base64-SHA-256 des Server-SPKI — ersetzt die CA-Prüfung>
# validity: 8h        # gewünschte Laufzeit (Policy-Maximum des Servers greift)
```

Pin ermitteln:

```sh
openssl s_client -connect gssh.example.com:443 </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary | base64
```

Transparente Integration in natives `ssh` (`gssh integrate >> ~/.ssh/config`):

```
Match host "*.example.com" exec "gssh login --if-needed"
```

## Entwicklung

Voraussetzungen: Go ≥ 1.26, golangci-lint ≥ 2.x, Docker (Image-Builds, später Testcontainer).

```sh
make build   # Binaries nach bin/ (statisch, versioniert)
make cross   # gssh für linux/amd64, linux/arm64, darwin/arm64
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
