# Self-hosted Runner — Requirements

The CI pipeline (`.github/workflows/release.yml`, `build.yml`, `renovate.yml`) runs entirely on
self-hosted runners (`runs-on: self-hosted`).

## Runner model

Container-based and ephemeral: every job gets a fresh container that is used
once and then discarded, together with its own Docker-in-Docker (DinD) sidecar.
Three consequences that the workflows and the rest of this document rely on:

- **No state survives a job.** Nothing written to `/tmp`, `$HOME`, the Docker
  image store or the runner work directory is visible to the next job. Tools
  that the workflow installs per job (`sudo apt-get …`, curl-installed kind) are
  therefore installed again on every job — deliberate, not a leftover.
- **Docker is per job.** The DinD sidecar is reachable only from the job
  container it belongs to and dies with it. The host's Docker socket must never
  be mounted into a job container: that would hand every job root on the runner
  host and reintroduce cross-job persistence, which is what the whole model
  rests on.
- **The requirements below describe the runner image**, not a long-lived
  machine. Wherever this document says "pre-install", it means "bake into the
  runner image".

## Software

| Component | Purpose | Since when |
|---|---|---|
| Docker-in-Docker sidecar (rootful) per job | Testcontainers (Postgres, Keycloak, sshd host), container image builds (buildx) | immediately |
| build-essential (make, gcc) | `make` targets, `go test -race` requires CGO; the workflow installs it per job via `sudo apt-get` (valkey pattern), baking it into the runner image only speeds things up | immediately |
| git ≥ 2.30 | checkout, `git describe` | immediately |
| ClamAV (`clamscan`, `freshclam`) | malware scan of the source code (job `malware-scan`); the workflow installs it via `sudo apt-get`, or bake it into the runner image instead | immediately |
| Trivy | container image scan (job `container-malware-scan`); installed by `aquasecurity/trivy-action`, network access suffices | immediately |
| kind + kubectl | E2E suite in the disposable cluster (job `e2e-tests`, PR + main); the workflow installs both via curl (kind pinned, Renovate-maintained), baking them in only speeds things up | Phase 13 |
| helm | E2E suite + chart lint; installed via `azure/setup-helm`, network access suffices | Phase 11/13 |
| ansible | Ansible provisioning path of the E2E suite (job `e2e-tests`); the workflow installs it via `sudo apt-get`; if missing, the Go SSH fallback covers the same certificate path | Phase 13 |
| Node.js LTS | Angular build (installed via `actions/setup-node`, network access suffices) | Phase 8 |

Go itself is installed and cached by `actions/setup-go` from the `toolchain`
directive in `go.mod` — an exact version that Renovate bumps in its "Go version"
group — so no fixed Go installation is needed in the runner image. The `go`
directive is only the minimum language version: without the `toolchain` line,
setup-go installs exactly that minimum (e.g. 1.26.0), and `govulncheck` then
reports every standard-library fix released since.

## Resources (guideline values)

- ≥ 4 CPU cores, ≥ 8 GB RAM per job (testcontainers + kind in parallel)
- ≥ 40 GB free disk space for the job container plus its DinD sidecar
  (container images, build caches). A per-job DinD daemon starts with an empty
  image store, so every job pulls its images again unless a registry mirror or
  a pull-through cache is configured.
- Network access: github.com, registry-1.docker.io (pull + push), gcr.io (distroless), proxy.golang.org,
  ghcr.io (Trivy DB, Dex image), database.clamav.net (freshclam), dl.k8s.io (kubectl),
  kind.sigs.k8s.io (kind)

## Secrets (GitHub repository secrets)

| Secret | Purpose |
|---|---|
| `DOCKERHUB_PAT` | Docker Hub access token for pushing to `docker.io/guidedtraffic` (scope read/write, not an account password) |
| `APP_CLIENT_ID`, `APP_PRIVATE_KEY` | Client ID and private key of the org GitHub App `guided-traffic-automation`; the `semantic-release` job (tag + release + badge commit) and the Renovate job (opening PRs) each mint their own installation token with `actions/create-github-app-token`, scoped to this repository, valid for 1 h and revoked at the end of the job; needed so that generated releases/PRs trigger workflows — events created with `GITHUB_TOKEN` do not trigger workflows |

## Security

- **Never run fork PRs on self-hosted runners.** Enforce Settings → Actions →
  General → "Fork pull request workflows from outside collaborators" =
  *"Require approval for all external contributors"*. GitHub's default for
  public repositories is *"first-time contributors"*, which auto-runs every
  later PR from a contributor whose first PR was approved. What a fork PR can
  and cannot reach under the runner model above:
  - **cannot** read repository secrets — GitHub does not inject them into
    `pull_request` runs from a fork, and `GITHUB_TOKEN` is read-only there
  - **cannot** persist into a later job — one-shot job container, per-job DinD
  - **can** execute arbitrary code with the job container's network egress, and
    can share a node with jobs running at the same time. The `concurrency` group
    is keyed per ref, so a PR run and the `main` run do overlap.
- Root inside the job container or its DinD sidecar is not a privilege
  escalation: both are discarded with the job, and the trust boundary is the
  container, not the runner user. That is why the per-job `sudo apt-get` steps
  in the workflow are not a weakening — as long as the host Docker socket stays
  out of the job container (see [Runner model](#runner-model)). Still, do not
  schedule runners on nodes that also carry production workloads.
- The `malware-scan` job needs `sudo apt-get` / `sudo freshclam` /
  `sudo systemctl` for ClamAV (as proven on the valkey-operator runners).
  Anyone who wants to forbid `sudo` entirely must bake ClamAV plus an
  up-to-date signature DB into the runner image and remove the sudo steps from
  the workflow.
- A same-repo branch PR is a different case from a fork PR: the workflow
  definition comes from the PR branch **and** repository secrets are available,
  so every secret referenced by a PR-triggered job is readable by whoever can
  push that branch. Keep secrets out of PR-triggered jobs rather than relying
  on the job definition — see the hardening backlog below.

## Hardening backlog

Known gaps, none of them blocking; listed so they are not rediscovered as
findings.

- `container-malware-scan`
  ([release.yml:492](../.github/workflows/release.yml#L492)) has no event guard,
  so it runs on `pull_request`, and it logs into Docker Hub with the
  push-capable `DOCKERHUB_PAT`
  ([:503-507](../.github/workflows/release.yml#L503-L507)) although it builds
  with `push: false`. The login is not required — the base images are public —
  so it can be deleted, or replaced by a read-only pull token if Docker Hub
  rate limits become a problem.
- Actions are pinned to mutable tags (`@v7`, `@v4`), and
  `aquasecurity/trivy-action@master`
  ([:527](../.github/workflows/release.yml#L527)) to a branch. Tags are
  force-pushable, so this is one class of issue, not two: enable Renovate's
  `helpers:pinGitHubActionDigests` and pin every action to a commit SHA.
- `semantic-release` ([release.yml:558](../.github/workflows/release.yml#L558))
  and `build.yml`'s push job are not behind a GitHub `environment:`, so the
  GitHub App key (`APP_PRIVATE_KEY`) and `DOCKERHUB_PAT` are reachable from any
  job definition that runs on `push` or `workflow_dispatch`.

## Maintenance

- No `docker system prune` cron is needed: the DinD sidecar takes its image
  store with it when the job ends. Disk pressure is a node-level concern of the
  container runtime, not of a runner-side job.
- Keep the runner version in the runner image up to date — GitHub disables
  outdated runners.
