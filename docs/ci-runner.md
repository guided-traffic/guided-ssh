# Self-hosted Runner — Anforderungen

Die CI-Pipeline (`.github/workflows/release.yml`, `build.yml`, `renovate.yml`) läuft vollständig auf self-hosted
Runnern (`runs-on: self-hosted`). Anforderungen an die Runner-Maschine:

## Software

| Komponente | Zweck | Ab wann |
|---|---|---|
| Docker Engine (rootful) oder Podman mit Docker-kompatiblem Socket | Testcontainer (Postgres, Keycloak, sshd-Host), Container-Image-Builds (buildx) | sofort |
| build-essential (make, gcc) | `make`-Targets, `go test -race` benötigt CGO; Workflow installiert je Job via `sudo apt-get` (valkey-Muster), Vorinstallation beschleunigt nur | sofort |
| git ≥ 2.30 | Checkout, `git describe` | sofort |
| ClamAV (`clamscan`, `freshclam`) | Malware-Scan des Quellcodes (Job `malware-scan`); Workflow installiert via `sudo apt-get`, alternativ vorinstallieren | sofort |
| Trivy | Container-Image-Scan (Job `container-malware-scan`); wird von `aquasecurity/trivy-action` installiert, Netzugriff reicht | sofort |
| kind + kubectl | E2E-Suite im Wegwerf-Cluster (Job `e2e-tests`, PR + main); Workflow installiert beide via curl (kind gepinnt, Renovate-gepflegt), Vorinstallation beschleunigt nur | Phase 13 |
| helm | E2E-Suite + Chart-Lint; wird via `azure/setup-helm` installiert, Netzugriff reicht | Phase 11/13 |
| ansible | Ansible-Provisioning-Pfad der E2E-Suite (Job `e2e-tests`); Workflow installiert via `sudo apt-get`; fehlt es, deckt der Go-SSH-Fallback denselben Zertifikatspfad ab | Phase 13 |
| Node.js LTS | Angular-Build (wird via `actions/setup-node` installiert, Netzugriff reicht) | Phase 8 |

Go selbst wird von `actions/setup-go` anhand `go.mod` installiert und gecacht —
keine feste Go-Installation auf dem Runner nötig.

## Ressourcen (Richtwerte)

- ≥ 4 CPU-Kerne, ≥ 8 GB RAM (Testcontainer + kind parallel)
- ≥ 40 GB freier Plattenplatz (Container-Images, Build-Caches)
- Netzzugriff: github.com, registry-1.docker.io (Pull + Push), gcr.io (distroless), proxy.golang.org,
  ghcr.io (Trivy-DB, Dex-Image), database.clamav.net (freshclam), dl.k8s.io (kubectl),
  kind.sigs.k8s.io (kind)

## Secrets (GitHub Repository-Secrets)

| Secret | Zweck |
|---|---|
| `DOCKERHUB_PAT` | Docker-Hub-Access-Token für Push nach `docker.io/guidedtraffic` (Scope Read/Write, kein Account-Passwort) |
| `BOT_PAT` | GitHub-PAT für `semantic-release` (Tag + Release + Badge-Commit) und Renovate (PRs anlegen); nötig, damit erzeugte Releases/PRs Workflows triggern — mit `GITHUB_TOKEN` erzeugte Events starten keine Workflows |

## Sicherheit

- **Keine Fork-PRs auf self-hosted Runnern ausführen.** Repo privat halten oder in den
  GitHub-Einstellungen „Require approval for all outside collaborators" erzwingen —
  PR-Workflows führen fremden Code auf dem Runner aus.
- Runner-Benutzer möglichst ohne breite sudo-Rechte; Docker-Gruppenmitgliedschaft genügt
  für Tests und Builds (bewusst: Docker-Zugriff ≈ root auf der Runner-Maschine — Runner
  daher nicht auf Produktionssystemen betreiben). Ausnahme: der Job `malware-scan`
  braucht `sudo apt-get`/`sudo freshclam`/`sudo systemctl` für ClamAV (wie auf den
  valkey-operator-Runnern erprobt); wer sudo komplett verbieten will, muss ClamAV samt
  aktueller Signatur-DB vorinstallieren und die sudo-Schritte im Workflow entfernen.
- Ephemere Runner (ein Job pro Runner-Instanz) empfohlen, mindestens aber regelmäßige
  Neuinstallation/Updates der Runner-Software.

## Wartung

- Regelmäßig `docker system prune` (Cron), sonst laufen Testcontainer-Reste die Platte voll.
- Runner-Version aktuell halten (GitHub deaktiviert veraltete Runner).
