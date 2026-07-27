# guided-ssh

![Coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fguided-traffic%2Fguided-ssh%2Fmain%2F.github%2Fbadges%2Fcoverage.json)

Certificate-based SSH access platform: short-lived SSH certificates instead of static
`authorized_keys`, single sign-on against the existing identity provider, machine
access for CI pipelines (GitLab), and full auditability of every access.
Runs on Kubernetes via Helm, managed through GitOps (FluxCD).

Plan and progress: [INITIAL_PROJECT_PLAN.md](INITIAL_PROJECT_PLAN.md)

## Repository layout

| Path | Contents |
|---|---|
| `cmd/` | Binaries — `gssh-server` (API/CA), `gssh` (user CLI), `gssh-agentd` (host agent), `gssh-admin` (admin CLI) |
| `internal/` | Go packages (not importable externally) |
| `api/` | [OpenAPI specification](api/openapi.yaml) — single source of truth for the REST API |
| `web/` | Angular frontend, embedded in the Go binary ([docs/web-ui.md](docs/web-ui.md)) |
| `deploy/helm/` | Helm chart (from phase 11) |
| `docs/` | [Test strategy](docs/test-strategy.md), [threat model](docs/threat-model.md), [access control](docs/grants.md), [GitLab CI](docs/gitlab-ci.md), [web UI](docs/web-ui.md), [CI runner](docs/ci-runner.md), [ADRs](docs/adr/README.md) |
| `hack/` | Helper scripts for build and CI |

## gssh-server

API server with an integrated certificate authority (CA). Database migrations run
at startup; if CA keys are missing, they are generated (one Ed25519 key each
for user and host certificates, private keys AES-256-GCM-encrypted in
the database, see [ADR-014](docs/adr/014-software-signer-aes-gcm.md)).
Alternatively, the operator supplies the CA keys as files
(`GSSH_CA_MODE=self-managed`) — in that case the server writes no private
key material to the database
([docs/self-managed-ca.md](docs/self-managed-ca.md)).

```sh
gssh-server -listen :8080                      # start the HTTP API
gssh-server -listen :8080 -agent-listen :8443  # also start the agent API (mTLS)
gssh-server enroll-token -tags env=prod -ttl 24h  # one-time enrollment token
gssh-server -version                           # print the version
```

Configuration via environment variables:

| Variable | Meaning |
|---|---|
| `GSSH_DB_HOST` / `GSSH_DB_PORT` | PostgreSQL host (required) and port (default 5432) |
| `GSSH_DB_USER` / `GSSH_DB_PASSWORD` | Database user and password (required) |
| `GSSH_DB_NAME` | Database name (required) |
| `GSSH_DB_SSLMODE` | Connection `sslmode` (default `prefer`) |
| `GSSH_CA_MASTER_KEY` | Master key for CA key encryption: 32 bytes, base64 (e.g. `head -c 32 /dev/urandom \| base64`); required in both CA modes |
| `GSSH_CA_MODE` | `managed` (default) or `self-managed`; the latter requires the four `GSSH_CA_*_FILE` variables, which conversely must not be set in `managed` mode |
| `GSSH_CA_USER_KEY_FILE` / `GSSH_CA_HOST_KEY_FILE` | OpenSSH private-key PEM of the user and host CA respectively (`self-managed` only) |
| `GSSH_CA_MTLS_KEY_FILE` / `GSSH_CA_MTLS_CERT_FILE` | PKCS#8 PEM and X.509 CA certificate of the agent mTLS CA (`self-managed` only) |
| `GSSH_AGENT_TLS_NAMES` | SANs of the agent API's mTLS server certificate (comma-separated; default `localhost,127.0.0.1`) |
| `GSSH_ADMIN_GROUP` | IdP group whose members may use the admin API (`/v1/admin/…`); empty ⇒ admin API disabled |
| `GSSH_AGENT_PUBLIC_URL` | External mTLS agent URL for enrolled hosts (host rollout, never derived) |
| `GSSH_PUBLIC_URL` | External public base URL (UI login redirect, host rollout `install_command`, client install gate, pin dial) |
| `GSSH_PUBLIC_PIN` / `GSSH_PUBLIC_PIN_CERT_FILE` | Pin sources for the host rollout: base64 SPKI pin or PEM certificate; without either, the server dials its own public URL |
| `GSSH_PUBLIC_PIN_REFRESH` | Refresh interval for the pin self-dial (Go duration, default 5m) |
| `GSSH_AGENT_DOWNLOAD_RPM` | Binary downloads per client IP and minute (default 10, `0` = off); one shared bucket covers agent (`/v1/agents/…`) and client (`/v1/clients/…`) downloads |

Endpoints (phase 2 — sign endpoints follow from phase 3):

| Endpoint | Meaning |
|---|---|
| `GET /healthz` | Liveness |
| `GET /v1/ca/bundle/user` | Public keys of the user CA (authorized_keys format) — content for `TrustedUserCAKeys` on hosts |
| `GET /v1/ca/bundle/host` | Public keys of the host CA — for `@cert-authority` entries in `known_hosts` |

The bundles contain all active keys and any keys being phased out
(overlap window during key rotation).

## gssh (user CLI)

SSO login against the IdP, short-lived SSH certificate from the server — key pair
and certificate live exclusively in the `ssh-agent`; nothing is
persisted to disk ([ADR-016](docs/adr/016-cli-gssh-agent-only.md)).

```sh
gssh login               # SSO in the browser, certificate into the ssh-agent
gssh login --device      # device flow (headless, no browser)
gssh login --api-url https://<ip> --pin-sha256 <pin>
                         # DNS fallback: ephemeral overrides, config file untouched
                         # (README "Client install" — the pin replaces chain+hostname checks)
gssh ssh <host> …        # like ssh, with auto-login if no certificate is present
gssh status              # certificate status; exit code 1 without a valid certificate
gssh logout              # remove guided-ssh entries from the agent
gssh integrate           # ssh_config snippet for transparent native ssh
gssh ci-login            # GitLab CI: exchange job token for a CI certificate
```

`gssh ci-login` runs without a configuration file (flags/`GSSH_API_URL`,
job token from `GSSH_CI_TOKEN` via `id_tokens`) — details and a reference pipeline
in [docs/gitlab-ci.md](docs/gitlab-ci.md).

Configuration in `~/.config/guided-ssh/config.yaml` (override: `--config`
or `GSSH_CONFIG`):

```yaml
api_url: https://gssh.example.com
issuer: https://idp.example.com/realms/example
client_id: gssh-cli
# optional:
# scopes: [openid, profile, email, groups]
#   default; groups is what grants are matched on, so it is only dropped
#   when the issuer's discovery advertises scopes without it (auth.defaultScopes)
# pin_sha256: <base64 SHA-256 of the server SPKI — replaces the CA check>
# validity: 8h        # desired validity (server policy maximum takes precedence)
```

Determining the pin:

```sh
openssl s_client -connect gssh.example.com:443 </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary | base64
```

Transparent integration into native `ssh` (`gssh integrate >> ~/.ssh/config`):

```
Match host "*.example.com" exec "gssh login --if-needed"
```

## gssh-admin (admin CLI)

Manages the access rules (grants) via the admin API
([docs/grants.md](docs/grants.md), [ADR-018](docs/adr/018-grants-additive.md)).
Uses the same configuration file as `gssh`; server-side prerequisite:
`GSSH_ADMIN_GROUP`.

```sh
gssh-admin grant list
gssh-admin grant create --group deployers --tags env=prod \
    --principals deploy --max-validity 8h
gssh-admin grant update <id> --principals deploy,root
gssh-admin grant delete <id>
gssh-admin ci-grant list          # CI access rules (GitLab pipelines)
gssh-admin ci-grant create --project infra/ansible --ref main \
    --tags env=prod --principals deploy --max-validity 1h
gssh-admin apply -f grants.yaml   # declarative full reconciliation (GitOps, incl. ci_grants)
```

Authentication: OIDC like `gssh` (browser or `--device`), alternatively
a ready-made ID token via `--token` or `GSSH_ID_TOKEN` (CI).

## gssh-agentd (host agent)

Registers a host with the CA and keeps it up to date
([ADR-017](docs/adr/017-host-enrollment-mtls.md)): host certificate
(automatic renewal at 2/3 of its validity), the `TrustedUserCAKeys` bundle,
and the `AuthorizedPrincipalsCommand` helper with a fail-closed cache — if
the API is unreachable, cached principals remain valid until `cache_ttl`,
after which login is refused.

```sh
# 1. Create a token on the server
gssh-server enroll-token -tags env=prod,role=web -ttl 24h

# 2. Register on the host (writes sshd_config.d/guided-ssh.conf,
#    host certificate and CA bundle; uses the existing sshd host key,
#    then validates, reloads, and verifies the running sshd)
gssh-agentd enroll --server https://gssh.example.com \
  --agent-url https://gssh.example.com:8443 --token gssh-et-…

# 3. Start the service (systemd unit included in the package)
systemctl enable --now gssh-agentd
```

State lives under `/var/lib/guided-ssh/` (mTLS client certificate,
configuration, principals cache). Packages (deb/rpm via nfpm) and
install script: [deploy/packaging/](deploy/packaging/), build with
`make cross packages`.

Making the configuration effective is part of enrollment
([internal/agentd/sshd.go](internal/agentd/sshd.go)): sshd parses its
configuration once at startup, so a written snippet means nothing to a
running listener — and `sshd -T` cannot show the difference, because it
reads from disk. Enrollment therefore verifies the `Include`, runs
`sshd -t`, reloads via a detected command (persisted as `reload_command`
for renewals), and then asks the running daemon for its host key: a
certificate proves the snippet is in memory, a plain key proves it is not.
`--no-reload` opts out for immutable images.

## Embedded binaries (`internal/bindist`, `agentdist`, `clientdist`)

The server serves its own binaries: the host agent (one-command install,
user-facing docs: [README](README.md#one-command-host-install)) and the
`gssh` client ([README](README.md#client-install)). Three packages share the
work:

- `internal/bindist` is the generic source: `NewFromFS(fsys, prefix)` scans
  an `fs.FS` for `<prefix><os>-<arch>` files and provides the list, size, and
  hex SHA-256 of each binary (computed once, `sync.Once`). Non-matching names
  and `.gitkeep` are skipped.
- `internal/agentdist` embeds `bin/gssh-agentd-<os>-<arch>` (prefix
  `gssh-agentd-`) and keeps its pre-extraction public API — call sites,
  Dockerfile `COPY`, and `nfpm.yaml` are unchanged. `gssh-agentd.service`
  stays here as the single unit source for both the deb/rpm and the templated
  `install.sh`.
- `internal/clientdist` embeds `bin/gssh-<os>-<arch>` (prefix `gssh-`) for
  the client install. Separate embed directory by design: mixing the two
  families would serve the wrong binary under the right name.

In the repo both `bin/` directories are empty (`.gitkeep`, gitignored) — they
are populated only during the Docker build (stage `agentbuild`, same
`-ldflags` as the server ⇒ hard version lockstep). `NewFromFS` exists for
tests and E2E cases where the embed is empty.

**Dev build degradation:** a `go build`/`make build` outside the Docker
build contains no binaries. Each gate then reports `binaries` as the missing
condition: the manifests (`GET /v1/agents`, `GET /v1/clients`) still respond
with 200 and show the reason, while the downloads, `GET /install.sh`,
`GET /client.sh`, and token minting respond with `503`, and the UI (Add host
button, Client setup page) shows the missing state. To embed locally:

```sh
make cross                                   # builds bin/gssh-agentd-linux-amd64, bin/gssh-linux-amd64, …
cp bin/gssh-agentd-linux-amd64 internal/agentdist/bin/
cp bin/gssh-linux-amd64 internal/clientdist/bin/   # make cross output = embed names
make build                                   # server with the binaries embedded
```

E2E smoke tests (testcontainers, Docker required):

```sh
# host chain: token → install.sh → download → hash check → enroll → running agent
go test -tags integration ./internal/agentd/ -run InstallScript
# client chain: client.sh → download → hash check → binary + config.yaml → gssh version/status
go test -tags integration ./internal/api/ -run ClientInstallScript
```

Both tests build the binary they serve themselves and wire it in via
`NewFromFS`. The host test's `systemctl` branch does not run there
(`--no-systemd`) — a deliberate, documented CI gap (see README).

## Development

Prerequisites: Go ≥ 1.26, golangci-lint ≥ 2.x, Docker (image builds, later test containers).

```sh
make build     # binaries into bin/ (static, versioned)
make cross     # gssh (linux/amd64, linux/arm64, darwin/arm64) + gssh-agentd (linux)
make packages  # deb/rpm for gssh-agentd (requires nfpm)
make test      # unit tests with race detector
make cover   # tests + coverage gate (>= 80 %)
make lint    # golangci-lint
make fmt     # formatting (gofumpt/goimports)
make image   # build the container image locally
```

CI (GitHub Actions, self-hosted runner — requirements: [docs/ci-runner.md](docs/ci-runner.md)):
lint, test with coverage gate, build, container image (push to `docker.io/guidedtraffic`
on `main` and tags; tagging SemVer + `sha-<commit>`).

## License and versioning

Apache-2.0 ([LICENSE](LICENSE)). Semantic versioning via git tags `vX.Y.Z` —
details in [ADR-011](docs/adr/011-versioning-and-license.md).
