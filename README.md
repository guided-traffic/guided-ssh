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

Details (secrets layout, CloudNativePG, ingress, mTLS agent API, metrics):
[deploy/helm/guided-ssh/README.md](deploy/helm/guided-ssh/README.md).
GitOps reference (FluxCD, SOPS, declarative grants):
[deploy/flux-example/](deploy/flux-example/).

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
