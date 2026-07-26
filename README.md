# guided-ssh

![Coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fguided-traffic%2Fguided-ssh%2Fmain%2F.github%2Fbadges%2Fcoverage.json)

**SSH access without key sprawl.** guided-ssh replaces static `authorized_keys`
files with short-lived SSH certificates issued by a central CA: users log in
through your existing identity provider, CI pipelines exchange their OIDC job
token for a certificate, and every access is auditable — nothing long-lived to
distribute, rotate, or leak.

## Key features

- **Short-lived certificates instead of static keys** — key pair and
  certificate live only in the `ssh-agent`, nothing is written to disk.
  Offboarding happens through certificate expiry and group sync, not by
  hunting down keys on servers.
- **Single sign-on** — `gssh login` opens your IdP (Keycloak, Dex, any OIDC
  provider), including a device flow for headless machines. Works
  transparently with native `ssh` via a one-line `ssh_config` snippet.
- **Central, declarative access rules** — grants map IdP groups to host tags
  and Unix accounts (`group devs may log in as deploy on env=prod`), managed
  via CLI, web UI, or a GitOps-reconciled YAML file.
- **Host automation** — `gssh-agentd` enrolls a host with a one-time token,
  configures `sshd`, renews the host certificate automatically, and resolves
  allowed principals live with a fail-closed cache.
- **GitLab CI integration** — pipelines trade their per-job OIDC token for a
  short-lived certificate (`gssh ci-login`); no SSH keys in CI variables.
- **Full auditability** — every issued certificate and every decision in an
  append-only audit log, streamable to your SIEM (JSON logs or webhook).
- **Kubernetes-native** — Helm chart, FluxCD reference manifests, Prometheus
  metrics, embedded web UI for administration and audit.

## How it works

The server embeds an SSH certificate authority. Hosts trust the user CA
(`TrustedUserCAKeys`), clients trust the host CA (`@cert-authority` in
`known_hosts`) — after that, no per-user or per-host key distribution:

1. `gssh login` → SSO against your IdP → the server checks the grants and
   signs a short-lived user certificate (e.g. 8 h) into your `ssh-agent`.
2. `ssh deploy@web-01` works natively; `sshd` validates the certificate and
   the allowed principals against the CA — no `authorized_keys`.
3. Certificates expire on their own. Access removal = group change in the IdP.

## Quick start

### 1. Run the server (5 minutes, local)

You need a PostgreSQL instance and two environment values — no config file.
Grab `gssh-server` from the [releases](https://github.com/guided-traffic/guided-ssh/releases)
(or `make build` from source):

```sh
docker run -d --name gssh-db \
  -e POSTGRES_USER=gssh -e POSTGRES_PASSWORD=gssh -e POSTGRES_DB=gssh \
  -p 5432:5432 postgres:16-alpine

export GSSH_DB_HOST=localhost
export GSSH_DB_USER=gssh
export GSSH_DB_PASSWORD=gssh
export GSSH_DB_NAME=gssh
export GSSH_DB_SSLMODE=disable
export GSSH_CA_MASTER_KEY="$(openssl rand -base64 32)"   # encrypts the CA keys — keep it!

gssh-server -listen :8080
```

The server migrates the database and bootstraps its CA on first start:

```sh
curl localhost:8080/healthz            # → ok
curl localhost:8080/v1/ca/bundle/user  # public key(s) of the user CA
```

### 2. Connect your identity provider

User logins are OIDC. Point the server at your IdP and restart:

```sh
export GSSH_OIDC_ISSUER=https://idp.example.com/realms/acme
export GSSH_OIDC_CLIENT_ID=gssh-cli
export GSSH_ADMIN_GROUP=gssh-admins    # IdP group allowed to manage grants
```

Configure the CLI (`~/.config/guided-ssh/config.yaml`):

```yaml
api_url: http://localhost:8080
issuer: https://idp.example.com/realms/acme
client_id: gssh-cli
```

Log in and create a first access rule:

```sh
gssh login                # SSO in the browser, certificate into the ssh-agent
gssh status               # show the current certificate

gssh-admin grant create --group devs --tags env=dev \
    --principals deploy --max-validity 8h
```

### 3. Enroll a host

```sh
# on the server: create a one-time enrollment token
gssh-server enroll-token -tags env=dev,role=web -ttl 24h

# on the host: registers with the CA, configures sshd, starts renewing
gssh-agentd enroll --server https://gssh.example.com \
  --agent-url https://gssh.example.com:8443 --token gssh-et-…
systemctl enable --now gssh-agentd
```

With the [one-command install](#one-command-host-install) enabled, the web UI
does all of this behind an "Add host" button: it mints the token and hands you
a single line to paste on the host.

### 4. SSH

```sh
gssh ssh deploy@web-01        # like ssh, with auto-login if needed
# or fully transparent for native ssh/scp/rsync:
gssh integrate >> ~/.ssh/config
ssh deploy@web-01
```

## Deploy on Kubernetes

**Try it (test environments)** — no database required. The chart can run an
ephemeral PostgreSQL sidecar (`internalDatabase.enabled=true`, Kubernetes
≥ 1.29); only the CA secret is needed:

```sh
helm repo add guided-ssh https://guided-traffic.github.io/guided-ssh
kubectl create namespace guided-ssh
kubectl -n guided-ssh create secret generic guided-ssh-ca \
  --from-literal=ca-master-key="$(openssl rand -base64 32)"
helm install guided-ssh guided-ssh/guided-ssh -n guided-ssh \
  --set internalDatabase.enabled=true \
  --set secrets.ca.existingSecret=guided-ssh-ca
```

Data is ephemeral — every pod restart starts with an empty database (and a
fresh CA). Setting a database secret at the same time is rejected, so the
test database cannot be used by accident.

**Production** — database credentials and CA master key come from existing
secrets (external-secrets/SOPS compatible, CloudNativePG app secrets work
out of the box):

```sh
helm repo add guided-ssh https://guided-traffic.github.io/guided-ssh
helm install guided-ssh guided-ssh/guided-ssh -n guided-ssh \
  --set secrets.db.existingSecret=guided-ssh-db \
  --set secrets.ca.existingSecret=guided-ssh-ca \
  --set config.oidc.issuer=https://idp.example.com/realms/acme \
  --set config.oidc.clientID=gssh-cli
```

**Bring your own CA keys** — by default the server generates the CA private
keys on first start and keeps them encrypted in the database. Set
`secrets.ca.mode=self-managed` and the three CAs (user, host, agent mTLS) come
from a Secret instead, mounted read-only; nothing secret is written to the
database, and your Git repository (SOPS) becomes the source of truth for the
CA — including rotation, disaster recovery, and cloning an environment:

```sh
ssh-keygen -t ed25519 -f user-ca -N '' -C 'guided-ssh user ca'
ssh-keygen -t ed25519 -f host-ca -N '' -C 'guided-ssh host ca'
gssh-server gen-mtls-ca -out mtls-ca
kubectl -n guided-ssh create secret generic guided-ssh-ca-keys \
  --from-file=user-ca --from-file=host-ca \
  --from-file=mtls-ca.key --from-file=mtls-ca.crt
```

Full walkthrough: [docs/self-managed-ca.md](docs/self-managed-ca.md).

Details (secrets layout, CloudNativePG, ingress, mTLS agent API, metrics):
[deploy/helm/guided-ssh/README.md](deploy/helm/guided-ssh/README.md).
GitOps reference (FluxCD, SOPS, declarative grants):
[deploy/flux-example/](deploy/flux-example/).

## One-command host install

Instead of distributing packages, the server can serve the agent itself. In the
web UI, **Hosts → Add host** asks for TTL, tags, an optional hostname binding
and whether to enable session auditing, mints a one-time enrollment token and
shows the line to run on the target host:

```sh
curl -fsSL https://gssh.example.com/install.sh | sudo sh -s -- --token gssh-et-…
```

The hostname binding is optional and matched **exactly** against the host's own
`hostname` output — bind `web-01` while the host reports `web-01.example.com`
and the enrollment fails. The token is not spent by that failure, so a re-run
with the corrected name works; leave the field empty to mint an unbound token.

The script is templated by the server: public URL, agent URL, SPKI pin, the
SHA-256 of every embedded agent binary and the systemd unit are already baked
in — only the token and the flags are variable. It downloads the matching
`gssh-agentd` binary, verifies its hash, installs it to `/usr/bin`, writes the
unit, enrolls the host **pinned**, and waits (up to 10 s) for the agent socket
before reporting success. Flags: `--arch` (otherwise derived from `uname -m`),
`--session-audit`, `--no-systemd`.

**Enable it** (all four conditions must hold, otherwise the button stays
disabled and the endpoints answer `503` naming what is missing): agent binaries
in the image (they are, in released images), an SPKI pin, `GSSH_AGENT_PUBLIC_URL`
and a public base URL. Both URLs must be `https://` — plain-HTTP URLs never
pass the gate (a cleartext `curl … | sudo sh` would defeat both the hash check
and the pin). With Helm:

```sh
helm upgrade guided-ssh guided-ssh/guided-ssh -n guided-ssh --reuse-values \
  --set hostRollout.enabled=true \
  --set hostRollout.agentPublicUrl=https://gssh-agent.example.com:8443 \
  --set hostRollout.publicUrl=https://gssh.example.com
```

Details, pin sources and the file-based variant:
[chart README](deploy/helm/guided-ssh/README.md#host-rollout-one-command-install).

> **Do not mix script install and deb/rpm.** The script places a
> package-foreign binary in `/usr/bin/gssh-agentd` and a unit in
> `/etc/systemd/system`; a later package install would fight over the same
> files. Pick one path per host. The package route stays available
> ([deploy/packaging/](deploy/packaging/)).

### Security model

This is `curl … | sudo sh` — the classic supply-chain surface. What protects it:

- **HTTPS only.** TLS terminates at the ingress/reverse proxy; script, manifest
  and binary are fetched over `https://` and served with `Cache-Control: no-store`
  (no stale pins, hashes or binaries from intermediate caches).
- **The binary's SHA-256 is templated into the script.** A tampered download
  fails the hash check and the script aborts before anything is installed.
- **SPKI pinning is mandatory, not opt-in.** Three fail-closed sources
  (static > certificate file > verified self-dial). Without a pin the whole
  rollout is disabled. Certificate rotation is picked up automatically (the
  file source is read uncached, the dial source refreshes in the background),
  and a pin mismatch fails the TLS handshake **before** the token is spent.
- **`--require-pin` is footgun protection, not MITM protection.** It stops an
  accidentally un-pinned enrollment (a copied `enroll` line); the actual
  transport protection is HTTPS plus the pin sources.
- **Two-step alternative** for anyone who will not pipe into a shell — the UI
  shows it next to the one-liner:

  ```sh
  curl -fsSLO https://gssh.example.com/install.sh
  less install.sh          # inspect
  sudo sh install.sh --token gssh-et-…
  ```

- **The token is a one-time, short-lived bearer secret** (UI default 1 h,
  single use enforced server-side). Its plaintext exists exactly once, in the
  mint response — never in logs, never in the audit payload.
- **Minting requires the admin role and is audited**
  (`host.enroll_token.created`, without the token).
- **The binary download is public but tightly rate-limited** (10 per client IP
  per minute by default, `hostRollout.downloadRpm`). The token gates the
  enrollment, not the download.

Accepted residual risks:

- **Token in argv and shell history.** `--token` is briefly visible in `ps` /
  `/proc/*/cmdline` on the target host and stays in the operator's shell
  history. The alternatives shift the exposure rather than remove it (an env
  var lands in the history too and `sudo` strips it; stdin is unavailable when
  the script itself arrives via a pipe). The load-bearing control is single use
  plus a short TTL — once used, the token is worthless.
- **Version disclosure.** The public manifest (`GET /v1/agents`) names the
  server version. The binary is identifiable anyway; hiding it would be
  security theatre.
- **The `systemctl` branch is untested in CI.** The end-to-end smoke test runs
  the script with `--no-systemd` in a container without systemd; enable/restart
  and the health check are exercised manually. A systemd container in CI would
  be privileged and flaky, and a `systemctl` stub would only fake the behavior.

Dual-certificate proxies (serving RSA or ECDSA depending on the client) are not
a concern: both pin consumers — the server's self-dial and the agent — are Go
TLS clients with effectively the same cipher preferences, so they see the same
leaf. With the file-based pin source the question does not arise at all.

## GitLab CI

Pipelines authenticate with their per-job OIDC `id_token` — no key material
in CI variables:

```yaml
provision:
  id_tokens:
    GSSH_CI_TOKEN: { aud: guided-ssh }
  variables:
    GSSH_API_URL: https://gssh.example.com
  script:
    - eval $(ssh-agent -s) && gssh ci-login
    - ansible-playbook -i inventory.yml site.yml
```

Reference pipeline and server-side CI grants:
[docs/gitlab-ci.md](docs/gitlab-ci.md).

## Documentation

| Topic | Document |
|---|---|
| Operations manual (config, secrets, backup, CA rotation) | [docs/betriebshandbuch.md](docs/betriebshandbuch.md) |
| Self-managed CA keys (GitOps/SOPS) | [docs/self-managed-ca.md](docs/self-managed-ca.md) |
| Access rules (grants) | [docs/grants.md](docs/grants.md) |
| Host enrollment guide | [docs/enrollment-guide.md](docs/enrollment-guide.md) |
| GitLab CI integration | [docs/gitlab-ci.md](docs/gitlab-ci.md) |
| Troubleshooting | [docs/troubleshooting.md](docs/troubleshooting.md) |
| Threat model | [docs/bedrohungsmodell.md](docs/bedrohungsmodell.md) |
| Architecture decisions (ADRs) | [docs/adr/README.md](docs/adr/README.md) |

Contributing, building from source, repository layout:
[DEVELOPER.md](DEVELOPER.md).

## License

Apache-2.0 ([LICENSE](LICENSE)). Semantic versioning via git tags `vX.Y.Z`.
