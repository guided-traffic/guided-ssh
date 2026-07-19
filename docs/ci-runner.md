# Self-hosted Runner — Anforderungen

Die CI-Pipeline (`.github/workflows/release.yml`, `build.yml`, `renovate.yml`) läuft vollständig auf self-hosted
Runnern (`runs-on: self-hosted`). Anforderungen an die Runner-Maschine:

## Software

| Komponente | Zweck | Ab wann |
|---|---|---|
| Docker Engine (rootful) oder Podman mit Docker-kompatiblem Socket | Testcontainer (Postgres, Keycloak, sshd-Host), Container-Image-Builds (buildx) | sofort |
| gcc/build-essential | `go test -race` benötigt CGO | sofort |
| git ≥ 2.30 | Checkout, `git describe` | sofort |
| kind + kubectl + helm | E2E-Tests im Wegwerf-Cluster | Phase 13 (nightly/Release) |
| Node.js LTS | Angular-Build (wird via `actions/setup-node` installiert, Netzugriff reicht) | Phase 8 |

Go selbst wird von `actions/setup-go` anhand `go.mod` installiert und gecacht —
keine feste Go-Installation auf dem Runner nötig.

## Ressourcen (Richtwerte)

- ≥ 4 CPU-Kerne, ≥ 8 GB RAM (Testcontainer + kind parallel)
- ≥ 40 GB freier Plattenplatz (Container-Images, Build-Caches)
- Netzzugriff: github.com, registry-1.docker.io (Pull + Push), gcr.io (distroless), proxy.golang.org

## Secrets (GitHub Repository-Secrets)

| Secret | Zweck |
|---|---|
| `DOCKERHUB_PAT` | Docker-Hub-Access-Token für Push nach `docker.io/guidedtraffic` (Scope Read/Write, kein Account-Passwort) |
| `BOT_PAT` | GitHub-PAT für `semantic-release` (Tag + Release + Badge-Commit) und Renovate (PRs anlegen); nötig, damit erzeugte Releases/PRs Workflows triggern — mit `GITHUB_TOKEN` erzeugte Events starten keine Workflows |

## Sicherheit

- **Keine Fork-PRs auf self-hosted Runnern ausführen.** Repo privat halten oder in den
  GitHub-Einstellungen „Require approval for all outside collaborators" erzwingen —
  PR-Workflows führen fremden Code auf dem Runner aus.
- Runner-Benutzer ohne sudo-Rechte; Docker-Gruppenmitgliedschaft genügt (bewusst:
  Docker-Zugriff ≈ root auf der Runner-Maschine — Runner daher nicht auf
  Produktionssystemen betreiben).
- Ephemere Runner (ein Job pro Runner-Instanz) empfohlen, mindestens aber regelmäßige
  Neuinstallation/Updates der Runner-Software.

## Wartung

- Regelmäßig `docker system prune` (Cron), sonst laufen Testcontainer-Reste die Platte voll.
- Runner-Version aktuell halten (GitHub deaktiviert veraltete Runner).
