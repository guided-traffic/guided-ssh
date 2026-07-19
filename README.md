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
| `cmd/` | Binaries — `gssh-server` (API/CA), `gssh` (Benutzer-CLI), `gssh-agentd` (Host-Agent), `gssh-admin` (Admin-CLI) |
| `internal/` | Go-Pakete (nicht öffentlich importierbar) |
| `api/` | [OpenAPI-Spezifikation](api/openapi.yaml) — Single Source of Truth der REST-API |
| `web/` | Angular-Frontend, eingebettet ins Go-Binary ([docs/web-ui.md](docs/web-ui.md)) |
| `deploy/helm/` | Helm-Chart (ab Phase 11) |
| `docs/` | [Teststrategie](docs/teststrategie.md), [Bedrohungsmodell](docs/bedrohungsmodell.md), [Zugriffssteuerung](docs/grants.md), [GitLab-CI](docs/gitlab-ci.md), [Web-UI](docs/web-ui.md), [CI-Runner](docs/ci-runner.md), [ADRs](docs/adr/README.md) |
| `hack/` | Hilfsskripte für Build und CI |

## gssh-server

API-Server mit integrierter Zertifizierungsstelle (CA). Beim Start laufen die
Datenbank-Migrationen; fehlen CA-Keys, werden sie erzeugt (je ein Ed25519-Key
für Benutzer- und Host-Zertifikate, Private Keys AES-256-GCM-verschlüsselt in
der Datenbank, siehe [ADR-014](docs/adr/014-software-signer-aes-gcm.md)).

```sh
gssh-server -listen :8080                      # HTTP-API starten
gssh-server -listen :8080 -agent-listen :8443  # zusätzlich Agent-API (mTLS)
gssh-server enroll-token -tags env=prod -ttl 24h  # einmaliges Enrollment-Token
gssh-server -version                           # Version ausgeben
```

Konfiguration über Umgebungsvariablen:

| Variable | Bedeutung |
|---|---|
| `GSSH_DB_DSN` | PostgreSQL-DSN, z. B. `postgres://user:pass@host:5432/db` |
| `GSSH_CA_MASTER_KEY` | Master-Key für die CA-Key-Verschlüsselung: 32 Bytes, Base64 (z. B. `head -c 32 /dev/urandom \| base64`) |
| `GSSH_AGENT_TLS_NAMES` | SANs des mTLS-Server-Zertifikats der Agent-API (Komma-getrennt; Default `localhost,127.0.0.1`) |
| `GSSH_ADMIN_GROUP` | IdP-Gruppe, deren Mitglieder die Admin-API (`/v1/admin/…`) nutzen dürfen; leer ⇒ Admin-API deaktiviert |

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
gssh ci-login            # GitLab-CI: Job-Token gegen CI-Zertifikat tauschen
```

`gssh ci-login` läuft ohne Konfigurationsdatei (Flags/`GSSH_API_URL`,
Job-Token aus `GSSH_CI_TOKEN` via `id_tokens`) — Details und Referenz-Pipeline
in [docs/gitlab-ci.md](docs/gitlab-ci.md).

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

## gssh-admin (Admin-CLI)

Verwaltet die Zugriffsregeln (Grants) über die Admin-API
([docs/grants.md](docs/grants.md), [ADR-018](docs/adr/018-grants-additiv.md)).
Nutzt dieselbe Konfigurationsdatei wie `gssh`; Voraussetzung serverseitig:
`GSSH_ADMIN_GROUP`.

```sh
gssh-admin grant list
gssh-admin grant create --group deployers --tags env=prod \
    --principals deploy --max-validity 8h
gssh-admin grant update <id> --principals deploy,root
gssh-admin grant delete <id>
gssh-admin ci-grant list          # CI-Zugriffsregeln (GitLab-Pipelines)
gssh-admin ci-grant create --project infra/ansible --ref main \
    --tags env=prod --principals deploy --max-validity 1h
gssh-admin apply -f grants.yaml   # deklarativer Vollabgleich (GitOps, inkl. ci_grants)
```

Authentifizierung: OIDC wie `gssh` (Browser bzw. `--device`), alternativ
fertiges ID-Token via `--token` oder `GSSH_ID_TOKEN` (CI).

## gssh-agentd (Host-Agent)

Registriert einen Host bei der CA und hält ihn aktuell
([ADR-017](docs/adr/017-host-enrollment-mtls.md)): Host-Zertifikat
(automatische Erneuerung bei 2/3 der Laufzeit), `TrustedUserCAKeys`-Bundle
und der `AuthorizedPrincipalsCommand`-Helper mit Fail-closed-Cache — bei
nicht erreichbarer API tragen gecachte Principals bis zur `cache_ttl`,
danach wird der Login verweigert.

```sh
# 1. Token auf dem Server erzeugen
gssh-server enroll-token -tags env=prod,role=web -ttl 24h

# 2. Auf dem Host registrieren (schreibt sshd_config.d/guided-ssh.conf,
#    Host-Zertifikat und CA-Bundle; nutzt den vorhandenen sshd-Host-Key)
gssh-agentd enroll --server https://gssh.example.com \
  --agent-url https://gssh.example.com:8443 --token gssh-et-…

# 3. Dienst starten (systemd-Unit im Paket enthalten)
systemctl enable --now gssh-agentd
```

State liegt unter `/var/lib/guided-ssh/` (mTLS-Client-Zertifikat,
Konfiguration, Principals-Cache). Pakete (deb/rpm via nfpm) und
Install-Skript: [deploy/packaging/](deploy/packaging/), Build mit
`make cross packages`.

## Entwicklung

Voraussetzungen: Go ≥ 1.26, golangci-lint ≥ 2.x, Docker (Image-Builds, später Testcontainer).

```sh
make build     # Binaries nach bin/ (statisch, versioniert)
make cross     # gssh (linux/amd64, linux/arm64, darwin/arm64) + gssh-agentd (linux)
make packages  # deb/rpm für gssh-agentd (braucht nfpm)
make test      # Unit-Tests mit Race-Detector
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
