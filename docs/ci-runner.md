# Self-hosted Runner — Requirements

The CI pipeline (`.github/workflows/release.yml`, `build.yml`, `renovate.yml`) runs entirely on
self-hosted runners (`runs-on: self-hosted`). Requirements for the runner machine:

## Software

| Component | Purpose | Since when |
|---|---|---|
| Docker Engine (rootful) or Podman with a Docker-compatible socket | Testcontainers (Postgres, Keycloak, sshd host), container image builds (buildx) | immediately |
| build-essential (make, gcc) | `make` targets, `go test -race` requires CGO; the workflow installs it per job via `sudo apt-get` (valkey pattern), pre-installing it only speeds things up | immediately |
| git ≥ 2.30 | checkout, `git describe` | immediately |
| ClamAV (`clamscan`, `freshclam`) | malware scan of the source code (job `malware-scan`); the workflow installs it via `sudo apt-get`, or pre-install it instead | immediately |
| Trivy | container image scan (job `container-malware-scan`); installed by `aquasecurity/trivy-action`, network access suffices | immediately |
| kind + kubectl | E2E suite in the disposable cluster (job `e2e-tests`, PR + main); the workflow installs both via curl (kind pinned, Renovate-maintained), pre-installing only speeds things up | Phase 13 |
| helm | E2E suite + chart lint; installed via `azure/setup-helm`, network access suffices | Phase 11/13 |
| ansible | Ansible provisioning path of the E2E suite (job `e2e-tests`); the workflow installs it via `sudo apt-get`; if missing, the Go SSH fallback covers the same certificate path | Phase 13 |
| Node.js LTS | Angular build (installed via `actions/setup-node`, network access suffices) | Phase 8 |

Go itself is installed and cached by `actions/setup-go` based on `go.mod` —
no fixed Go installation needed on the runner.

## Resources (guideline values)

- ≥ 4 CPU cores, ≥ 8 GB RAM (testcontainers + kind in parallel)
- ≥ 40 GB free disk space (container images, build caches)
- Network access: github.com, registry-1.docker.io (pull + push), gcr.io (distroless), proxy.golang.org,
  ghcr.io (Trivy DB, Dex image), database.clamav.net (freshclam), dl.k8s.io (kubectl),
  kind.sigs.k8s.io (kind)

## Secrets (GitHub repository secrets)

| Secret | Purpose |
|---|---|
| `DOCKERHUB_PAT` | Docker Hub access token for pushing to `docker.io/guidedtraffic` (scope read/write, not an account password) |
| `BOT_PAT` | GitHub PAT for `semantic-release` (tag + release + badge commit) and Renovate (opening PRs); needed so that generated releases/PRs trigger workflows — events created with `GITHUB_TOKEN` do not trigger workflows |

## Security

- **Never run fork PRs on self-hosted runners.** Keep the repo private, or
  enforce "Require approval for all outside collaborators" in the GitHub
  settings — PR workflows execute foreign code on the runner.
- The runner user should have no broad sudo rights where possible; Docker
  group membership is sufficient for tests and builds (deliberately so:
  Docker access is roughly equivalent to root on the runner machine —
  therefore never run runners on production systems). Exception: the
  `malware-scan` job needs `sudo apt-get`/`sudo freshclam`/`sudo systemctl`
  for ClamAV (as proven on the valkey-operator runners); anyone who wants
  to forbid sudo entirely must pre-install ClamAV with an up-to-date
  signature DB and remove the sudo steps from the workflow.
- Ephemeral runners (one job per runner instance) are recommended, or at
  minimum regular reinstallation/updates of the runner software.

## Maintenance

- Regularly run `docker system prune` (cron), otherwise leftover
  testcontainers fill up the disk.
- Keep the runner version up to date (GitHub disables outdated runners).
