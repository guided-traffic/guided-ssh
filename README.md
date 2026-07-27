# gssh — guided-ssh

![Coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fguided-traffic%2Fguided-ssh%2Fmain%2F.github%2Fbadges%2Fcoverage.json)

**SSH access without key sprawl.** gssh (short for *guided-ssh*) replaces
static `authorized_keys` files with short-lived SSH certificates issued by a
central CA: users log in through your existing identity provider, CI pipelines
exchange their OIDC job token for a certificate, and every access is
auditable — nothing long-lived to distribute, rotate, or leak.

## Key features

- 🔑 **Short-lived certificates instead of static keys** — key pair and
  certificate live only in the `ssh-agent`, nothing is written to disk.
  Offboarding happens through certificate expiry and group sync, not by
  hunting down keys on servers.
- 🌐 **Single sign-on** — `gssh login` opens your IdP (Keycloak, Dex, any OIDC
  provider), including a device flow for headless machines. Works
  transparently with native `ssh` via a one-line `ssh_config` snippet.
- 📜 **Central, declarative access rules** — grants map IdP groups to host tags
  and Unix accounts (`group devs may log in as deploy on env=prod`), managed
  via CLI, web UI, or a GitOps-reconciled YAML file.
- 🤖 **Host automation** — `gssh-agentd` enrolls a host with a one-time token,
  configures `sshd`, renews the host certificate automatically, and resolves
  allowed principals live with a fail-closed cache.
- 🦊 **GitLab CI integration** — pipelines trade their per-job OIDC token for a
  short-lived certificate (`gssh ci-login`); no SSH keys in CI variables.
- 🧾 **Full auditability** — every issued certificate and every decision in an
  append-only audit log, streamable to your SIEM (JSON logs or webhook).
- ☸️ **Kubernetes-native** — Helm chart, FluxCD reference manifests, Prometheus
  metrics, embedded web UI for administration and audit.

## What's in a name

Everything ships under the `gssh` prefix — the short form of *guided-ssh*:

| Name | What it is | Runs where |
|---|---|---|
| **`gssh`** | User CLI: SSO login, certificate into the `ssh-agent`, `gssh ssh`, `gssh ci-login` for pipelines | Admin/user workstations, CI jobs |
| **`gssh-admin`** | Admin CLI: manage grants and CI grants, declarative `apply` for GitOps | Operator workstations, sync jobs |
| **`gssh-agentd`** | Host agent daemon: enrollment, certificate renewal, live principals lookup for `sshd` | Every managed host |
| **`gssh-server`** | The server: REST API, certificate authority, embedded web UI, mTLS agent API, metrics | Kubernetes (Helm chart **`guided-ssh`**) or any place a Go binary and PostgreSQL run |

Surrounding conventions: the project, repository, Helm chart, and OS packages
are named **`guided-ssh`**; server environment variables use the `GSSH_*`
prefix; enrollment tokens look like `gssh-et-…`; the client config lives in
`~/.config/guided-ssh/config.yaml` and the host-side sshd drop-in is
`sshd_config.d/guided-ssh.conf`.

## How it works

The server embeds an SSH certificate authority. Hosts trust the user CA
(`TrustedUserCAKeys`), clients trust the host CA (`@cert-authority` in
`known_hosts`) — after that, no per-user or per-host key distribution:

1. `gssh login` → SSO against your IdP → the server checks the grants and
   signs a short-lived user certificate (e.g. 8 h) into your `ssh-agent`.
2. `ssh deploy@web-01` works natively; `sshd` validates the certificate and
   the allowed principals against the CA — no `authorized_keys`.
3. Certificates expire on their own. Access removal = group change in the IdP.

Components, data flows, and the separation of the auth paths:
[docs/architecture.md](docs/architecture.md).

## TL;DR — try it

The fastest path to a running test installation. No IdP at hand? Fake one:
Dex with its built-in mock connector is a one-container OIDC issuer that logs
everyone in as a fixed identity carrying the group `authors` — enough to click
through the whole flow. (Dex's static passwords would look like the more
obvious fake, but they carry no groups claim — and without groups, neither the
admin role nor any grant ever matches.) With a real IdP, substitute its
issuer and client ID below.

```sh
docker run -d --name gssh-idp -p 5556:5556 \
  -v "$PWD/hack/dex-dev.yaml:/etc/dex/config.yaml:ro" \
  ghcr.io/dexidp/dex:latest dex serve /etc/dex/config.yaml
```

([hack/dex-dev.yaml](hack/dex-dev.yaml) — memory storage, no authentication;
never expose it anywhere.)

**On your machine** — a PostgreSQL container, a handful of environment
values, one binary from the [releases](https://github.com/guided-traffic/guided-ssh/releases)
(or `make build`):

```sh
docker run -d --name gssh-db \
  -e POSTGRES_USER=gssh -e POSTGRES_PASSWORD=gssh -e POSTGRES_DB=gssh \
  -p 5432:5432 postgres:16-alpine

export GSSH_DB_HOST=localhost GSSH_DB_USER=gssh GSSH_DB_PASSWORD=gssh \
       GSSH_DB_NAME=gssh GSSH_DB_SSLMODE=disable
export GSSH_CA_MASTER_KEY="$(openssl rand -base64 32)"    # encrypts the CA keys — keep it!
export GSSH_OIDC_ISSUER=http://127.0.0.1:5556/dex         # or your IdP's issuer
export GSSH_CLIENT_OIDC_CLIENT_ID=gssh-cli                # public client of the CLIs (no secret)
export GSSH_ADMIN_GROUP=authors                           # IdP group allowed to manage grants
# Optional — web-UI login. The server authenticates as its own confidential
# client (client secret), separate from the CLIs' public client:
export GSSH_SERVER_OIDC_CLIENT_ID=gssh-server
export GSSH_SERVER_OIDC_CLIENT_SECRET=gssh-server-dev-secret

gssh-server -listen :8080 -agent-listen :8443
```

The server migrates the database and bootstraps its CA on first start
(`curl localhost:8080/healthz` → `ok`).

**Or on Kubernetes** — no database needed, the chart runs an ephemeral
PostgreSQL sidecar (`internalDatabase.enabled=true`, Kubernetes ≥ 1.29,
strictly for trying it out — every pod restart starts with an empty database
and a fresh CA). The host-local Dex above is not reachable from inside a
cluster — point these values at an IdP that is:

```sh
helm repo add guided-ssh https://guided-traffic.github.io/guided-ssh
kubectl create namespace guided-ssh
kubectl -n guided-ssh create secret generic guided-ssh-ca \
  --from-literal=ca-master-key="$(openssl rand -base64 32)"
helm install guided-ssh guided-ssh/guided-ssh -n guided-ssh \
  --set internalDatabase.enabled=true \
  --set secrets.ca.existingSecret=guided-ssh-ca \
  --set config.oidc.issuer=https://idp.example.com/realms/acme \
  --set config.oidc.client.clientID=gssh-cli \
  --set config.groups.admin=gssh-admins
```

**Then, either way** — set up the client. On a real (https) deployment that
is a single line — it installs `gssh` into `~/.local/bin` and writes a
ready-to-use configuration ([client install](#client-install)):

```sh
curl -fsSL https://gssh.example.com/client.sh | sh
```

The plain-HTTP quickstart above stays below that route's https gate — here,
write `~/.config/guided-ssh/config.yaml` by hand instead. Then log in,
create a first access rule, enroll a host, ssh:

```yaml
api_url: http://localhost:8080
issuer: http://127.0.0.1:5556/dex          # must match GSSH_OIDC_ISSUER
client_id: gssh-cli
scopes: [openid, profile, email, groups]   # the default omits groups — Dex only sends what is requested
```

```sh
gssh login                # SSO in the browser, certificate into the ssh-agent
gssh status               # show the current certificate

gssh-admin grant create --group authors --tags env=dev \
    --principals deploy --max-validity 8h

# on the server: one-time enrollment token
gssh-server enroll-token -tags env=dev,role=web -ttl 24h
# on the host: registers with the CA, configures sshd, starts renewing
gssh-agentd enroll --server https://gssh.example.com \
  --agent-url https://gssh.example.com:8443 --token gssh-et-…
systemctl enable --now gssh-agentd

gssh ssh deploy@web-01        # like ssh, with auto-login if needed
# or fully transparent for native ssh/scp/rsync:
gssh integrate >> ~/.ssh/config
ssh deploy@web-01
```

Step-by-step details: [docs/enrollment-guide.md](docs/enrollment-guide.md)
(hosts) and [docs/grants.md](docs/grants.md) (access rules). With the
[one-command host install](#one-command-host-install) enabled, the web UI
replaces the whole enrollment block with an "Add host" button.

## Production deployment

The real thing runs on Kubernetes: external PostgreSQL (CloudNativePG works
out of the box), secrets from external-secrets/SOPS, ≥ 2 replicas, audit
stream to your SIEM:

```sh
helm repo add guided-ssh https://guided-traffic.github.io/guided-ssh
helm install guided-ssh guided-ssh/guided-ssh -n guided-ssh \
  --set secrets.db.existingSecret=guided-ssh-db \
  --set secrets.ca.existingSecret=guided-ssh-ca \
  --set config.oidc.issuer=https://idp.example.com/realms/acme \
  --set config.oidc.client.clientID=gssh-cli
```

By default the server generates the CA private keys on first start and stores
them encrypted in the database. With `secrets.ca.mode=self-managed` the CA
keys come from a Secret you control instead — your Git repository (SOPS)
becomes the source of truth for the CA, including rotation and disaster
recovery ([docs/self-managed-ca.md](docs/self-managed-ca.md)).

What an ideal production setup looks like — reference architecture,
do/don't list, every security-relevant setting explained, go-live checklist:
**[docs/production-setup.md](docs/production-setup.md)**.

All chart values (secrets layout, CloudNativePG, ingress, mTLS agent API,
metrics): [chart README](deploy/helm/guided-ssh/README.md). GitOps reference
(FluxCD, SOPS, declarative grants): [deploy/flux-example/](deploy/flux-example/).

**Rules from Git.** Access rules and CI rules are meant to be managed
declaratively, so in-app editing is **off by default**
(`config.rules.manualProvision: false`). Each domain can additionally be
pointed at a ConfigMap that the server reconciles from — no sync job, no
extra OIDC client. The chart does not create those ConfigMaps; they are
maintained next to your other manifests (kustomize `configMapGenerator`,
Flux, plain YAML):

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: gssh-host-rules
data:
  host-rules.yaml: |
    grants:
      - group: deployers
        tags:
          env: prod
        principals: [deploy]
        sudo: false
        max_validity: 8h
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: gssh-ci-rules
data:
  ci-rules.yaml: |
    ci_grants:
      - project: infra/ansible
        ref: main
        protected_only: true
        tags:
          env: prod
        principals: [deploy]
        max_validity: 1h
```

```yaml
# values.yaml
config:
  rules:
    manualProvision: false   # default; shown for clarity
    host:
      existingConfigMap: gssh-host-rules
      key: host-rules.yaml   # default key; set if your ConfigMap uses another
    ci:
      existingConfigMap: gssh-ci-rules
      key: ci-rules.yaml
```

Each file is the full desired state of its domain: an empty list
(`grants: []`) deletes every rule of that domain — a file *without* the
`grants:` key is a validation error, not "delete everything". Edits
propagate within roughly 1–2 minutes (kubelet ConfigMap sync plus a 30 s
reconcile tick), which doubles as drift correction against out-of-band
database changes. While a domain is file-owned, its pages stay readable in
the UI but every API write for it returns 403 — one writer per domain.
Ownership matrix and file schema: [docs/grants.md](docs/grants.md#declarative-management-gitops).

## One-command host install

Instead of distributing packages, the server can serve the agent itself: in
the web UI, **Hosts → Add host** mints a one-time enrollment token and hands
you a single line to paste on the target host — it downloads the matching
`gssh-agentd`, verifies its SHA-256, enrolls the host pinned to the server's
TLS key, and starts the service:

```sh
curl -fsSL https://gssh.example.com/install.sh | sudo sh -s -- --token gssh-et-…
```

The feature is off by default and fails closed: it requires HTTPS URLs and a
mandatory SPKI pin. Enable it with Helm:

```sh
helm upgrade guided-ssh guided-ssh/guided-ssh -n guided-ssh --reuse-values \
  --set hostRollout.enabled=true \
  --set hostRollout.agentPublicUrl=https://gssh-agent.example.com:8443 \
  --set config.publicURL=https://gssh.example.com
```

Exposing the agent endpoint through a **TLS-passthrough ingress** instead of a
dedicated LoadBalancer IP replaces `agentPublicUrl` with a single
`agent.ingress.host` — that one hostname then feeds the ingress rule, the
agent certificate SANs, and the install command
([chart README](deploy/helm/guided-ssh/README.md#tls-passthrough-ingress-agentingress)).

This is `curl … | sudo sh` — read the security model before enabling it:
what protects the pipeline (templated hashes, mandatory pinning, one-time
tokens), the accepted residual risks, and why script and deb/rpm installs
must not be mixed on one host — **[docs/host-rollout.md](docs/host-rollout.md)**.
Pin sources and rate limits:
[chart README](deploy/helm/guided-ssh/README.md#host-rollout-one-command-install).

## Client install

The server serves the `gssh` client too, version-matched to itself: the web
UI's **Client setup** page (and the per-host **Connect** dialog on the Hosts
page) hand out a single line that installs the client and writes a
ready-to-use configuration — zero to an SSH connection in three steps (fewer
is impossible: `gssh login` needs an interactive browser):

```sh
curl -fsSL https://gssh.example.com/client.sh | sh   # binary + ready config
gssh login                                           # SSO in the browser
gssh ssh <host>
```

No sudo, no token, no secrets: the script refuses to run as root, installs
into `~/.local/bin`, and writes `~/.config/guided-ssh/config.yaml` (mode
0600) only if none exists — an existing configuration is never overwritten,
the binary is still updated. Possessing the binary grants nothing; access is
only ever granted at `gssh login` time (OIDC + grants). Direct binary
downloads (macOS included) and a manual-configuration snippet live on the
same UI page.

Three public routes back this (all served with `Cache-Control: no-store`):

| Route | Serves |
|---|---|
| `GET /client.sh` | templated install script — server URL, OIDC issuer, client ID, and per-platform SHA-256 hashes baked in |
| `GET /v1/clients` | manifest: version, readiness (`missing` conditions), `pin`/`pin_source`, platforms with size and SHA-256 |
| `GET /v1/clients/{os}/{arch}` | client binary (`linux/amd64`, `linux/arm64`, `darwin/arm64`) |

The feature fails closed: script and binary download answer 503 naming the
missing conditions until the public base URL (`GSSH_PUBLIC_URL`) is https
and the OIDC issuer and the clients' client ID are set;
released images always embed the client binaries. Binary downloads share the
host install's rate limit — `GSSH_AGENT_DOWNLOAD_RPM` throttles agent *and*
client downloads from one per-IP bucket.

**Security.** This is again `curl | sh` from the same origin that serves the
hashes — the shared discussion in
[docs/host-rollout.md](docs/host-rollout.md) applies, with a strictly
smaller blast radius: no sudo, no token, no enrollment; the script writes
only to the invoking user's home. The generated configuration trusts WebPKI
— the same trust model as the browser SSO flow the login depends on — and
deliberately contains **no** TLS pin: a pinned default would break every
installed client on the next server key rotation. Hardened or private-CA
setups opt in with `… | sh -s -- --pin`, which requires an
operator-controlled pin source (`GSSH_PUBLIC_PIN` or
`GSSH_PUBLIC_PIN_CERT_FILE`).

**DNS fallback (connect via IP).** For a target host without a (working)
DNS entry, the Connect dialog renders

```sh
gssh ssh -o HostKeyAlias=<host-name> <ip>
```

`HostKeyAlias` makes ssh verify the host certificate against the enrolled
name (its principals are the full and short hostname, not the IP) while
connecting to the address — verification stays fully intact, nothing is
skipped. Without the alias, an IP connect correctly fails the principal
check. The dialog offers the agent's source address from its last
heartbeat (`last_seen_addr`) as a click-to-fill suggestion — labeled as
the egress address, which behind NAT may differ from where sshd listens;
the IP is never silently prefilled, the user always confirms it.

**Login via IP (edge case).** Should the *server's* DNS name be unresolvable
too, `gssh login` accepts ephemeral overrides — the config file is untouched:

```sh
gssh login --api-url https://<server-ip> --pin-sha256 <pin>
```

The pin replaces chain *and* hostname verification — a via-IP login is fully
verified TLS; there is no insecure-skip code path. It requires an
operator-controlled pin source (`GSSH_PUBLIC_PIN` or
`GSSH_PUBLIC_PIN_CERT_FILE`); auto-derived (`dial`) pins rotate with the
certificate and are never handed to clients. A file pin is only as stable as
the deployment's key-rotation policy: a renewal that rotates the private key
changes the SPKI and thus the pin. The login puts a certificate into the
ssh-agent and `gssh ssh` needs no further API contact until it expires;
persistently IP-based setups edit `config.yaml` (`api_url` plus
`pin_sha256`) deliberately. The browser→IdP leg keeps its own DNS
dependency.

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

**Using it**

| Topic | Document |
|---|---|
| Access rules (grants) | [docs/grants.md](docs/grants.md) |
| Host enrollment guide | [docs/enrollment-guide.md](docs/enrollment-guide.md) |
| GitLab CI integration | [docs/gitlab-ci.md](docs/gitlab-ci.md) |
| Web UI | [docs/web-ui.md](docs/web-ui.md) |
| Troubleshooting | [docs/troubleshooting.md](docs/troubleshooting.md) |

**Running it**

| Topic | Document |
|---|---|
| Production setup (do/don't, security settings) | [docs/production-setup.md](docs/production-setup.md) |
| Operations manual (config, secrets, backup, CA rotation) | [docs/operations-manual.md](docs/operations-manual.md) |
| Self-managed CA keys (GitOps/SOPS) | [docs/self-managed-ca.md](docs/self-managed-ca.md) |
| One-command host install & its security model | [docs/host-rollout.md](docs/host-rollout.md) |
| Audit retention | [docs/audit-retention.md](docs/audit-retention.md) |
| Helm chart values | [deploy/helm/guided-ssh/README.md](deploy/helm/guided-ssh/README.md) |
| CI runner setup | [docs/ci-runner.md](docs/ci-runner.md) |

**Security architecture**

| Topic | Document |
|---|---|
| Architecture (components, data flows, auth paths) | [docs/architecture.md](docs/architecture.md) |
| Threat model | [docs/threat-model.md](docs/threat-model.md) |
| Security review: token exchange | [docs/security-review-token-exchange.md](docs/security-review-token-exchange.md) |
| Architecture decisions (ADRs) | [docs/adr/README.md](docs/adr/README.md) |

**Developing it**

Contributing, building from source, repository layout, per-binary internals:
[DEVELOPER.md](DEVELOPER.md). Test approach: [docs/test-strategy.md](docs/test-strategy.md).

## License

Apache-2.0 ([LICENSE](LICENSE)). Semantic versioning via git tags `vX.Y.Z`.
