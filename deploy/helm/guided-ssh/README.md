# guided-ssh Helm Chart

Deploys the guided-ssh server (API + embedded web UI, agent API with mTLS,
Prometheus metrics) on Kubernetes.

For GitOps-based operation (FluxCD: HelmRelease, SOPS secrets, declarative
grants) see the reference manifests in `deploy/flux-example/`.

## Installation

```bash
helm repo add guided-ssh https://guided-traffic.github.io/guided-ssh
helm repo update

kubectl create namespace guided-ssh

# Required secrets (example; use external-secrets/SOPS in production):
# 1. PostgreSQL connection — individual keys, no DSN
kubectl -n guided-ssh create secret generic guided-ssh-db \
  --from-literal=host=db.example.com \
  --from-literal=port=5432 \
  --from-literal=username=gssh \
  --from-literal=password='PASS' \
  --from-literal=database=gssh \
  --from-literal=sslmode=require

# 2. CA master key
kubectl -n guided-ssh create secret generic guided-ssh-ca \
  --from-literal=ca-master-key="$(openssl rand -base64 32)"

helm install guided-ssh guided-ssh/guided-ssh -n guided-ssh \
  --set secrets.db.existingSecret=guided-ssh-db \
  --set secrets.ca.existingSecret=guided-ssh-ca \
  --set config.oidc.issuer=https://idp.example.com/realms/acme \
  --set config.oidc.clientID=guided-ssh \
  --set config.groups.admin=gssh-admins
```

> **Warning:** in the default `managed` mode, `ca-master-key` encrypts the CA
> private keys in the database (AES-256). Losing it renders the CA unusable.
> Store it safely. With `secrets.ca.mode=self-managed` the CA keys come from a
> Secret instead — see [CA mode](#ca-mode-managed-vs-self-managed-secretscamode).

## Secrets

The chart **never creates secrets** — it only references existing ones
(`existingSecret`), which makes it compatible with
[external-secrets](https://external-secrets.io) and
[SOPS](https://github.com/getsops/sops).

There are two independent references. They may point to two different secrets
(recommended: database credentials and CA key usually have different owners
and rotation cycles) or both to the same secret:

| Value | Purpose |
|---|---|
| `secrets.db.existingSecret` (required¹) | PostgreSQL connection values |
| `secrets.ca.existingSecret` (required) | CA master key |
| `secrets.ca.selfManaged.existingSecret` (required with `secrets.ca.mode=self-managed`) | The four CA key files |
| `config.keycloak.existingSecret` (optional) | Keycloak service-account client secret |
| `config.oidc.uiExistingSecret` (optional) | OIDC client secret of the web UI |

¹ Not allowed together with `internalDatabase.enabled=true` (test
environments, see [Internal database](#internal-database-test-environments-only));
setting both is a render error.

### Database secret (`secrets.db`)

The PostgreSQL connection is configured through **individual values instead
of a DSN**. Every value is read from the secret referenced by
`secrets.db.existingSecret`; each key name inside that secret is
configurable via `secrets.db.keys.*`:

| `secrets.db.keys.*` | Default key | Env variable | Required in secret |
|---|---|---|---|
| `host` | `host` | `GSSH_DB_HOST` | yes |
| `port` | `port` | `GSSH_DB_PORT` | no — missing key ⇒ `5432` |
| `username` | `username` | `GSSH_DB_USER` | yes |
| `password` | `password` | `GSSH_DB_PASSWORD` | yes |
| `database` | `database` | `GSSH_DB_NAME` | yes |
| `sslmode` | `sslmode` | `GSSH_DB_SSLMODE` | no — missing key ⇒ driver default `prefer` |

Notes:

- `port` and `sslmode` are mounted with `optional: true`: if the key does not
  exist in the secret, the env variable stays unset and the server falls back
  to its default. All other keys must exist, otherwise the pod does not start.
- Special characters in the password are safe — the server URL-escapes
  username and password when building the connection string.
- The same env variables are injected into the `migrate` init container.

**Remapping keys** — use an existing secret without copying it. Example:
your secret stores the user under `user` and the database under `dbname`:

```yaml
secrets:
  db:
    existingSecret: my-db-secret
    keys:
      username: user
      database: dbname
```

**CloudNativePG** — the `<cluster>-app` secret created by
[CloudNativePG](https://cloudnative-pg.io) works directly, only two keys
differ from the defaults:

```yaml
secrets:
  db:
    existingSecret: guided-ssh-db-app   # created by CNPG
    keys:
      username: user      # CNPG key name
      database: dbname    # CNPG key name
      # host, port, password match the defaults; the CNPG secret has no
      # sslmode key ⇒ driver default "prefer" applies (in-cluster traffic).
  ca:
    existingSecret: guided-ssh-ca       # CA key stays in its own secret
```

**external-secrets** — one `ExternalSecret` per reference:

```yaml
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: guided-ssh-db
spec:
  refreshInterval: 1h
  secretStoreRef: { name: vault, kind: ClusterSecretStore }
  target: { name: guided-ssh-db }
  data:
    - secretKey: host
      remoteRef: { key: guided-ssh/db, property: host }
    - secretKey: port
      remoteRef: { key: guided-ssh/db, property: port }
    - secretKey: username
      remoteRef: { key: guided-ssh/db, property: username }
    - secretKey: password
      remoteRef: { key: guided-ssh/db, property: password }
    - secretKey: database
      remoteRef: { key: guided-ssh/db, property: database }
    - secretKey: sslmode
      remoteRef: { key: guided-ssh/db, property: sslmode }
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: guided-ssh-ca
spec:
  refreshInterval: 1h
  secretStoreRef: { name: vault, kind: ClusterSecretStore }
  target: { name: guided-ssh-ca }
  data:
    - secretKey: ca-master-key
      remoteRef: { key: guided-ssh/ca, property: master-key }
```

### CA secret (`secrets.ca`)

| `secrets.ca.keys.*` | Default key | Env variable |
|---|---|---|
| `masterKey` | `ca-master-key` | `GSSH_CA_MASTER_KEY` |

The value must be 32 random bytes, Base64-encoded
(`openssl rand -base64 32`). It encrypts the CA private keys at rest
(AES-256-GCM); rotation requires re-encrypting the stored CA keys — treat it
as the most sensitive secret of the installation.

`secrets.ca.existingSecret` is **required in both CA modes**: the master key
also derives the session key of the web UI, so it is needed even when no CA
private key is stored in the database.

### CA mode: managed vs. self-managed (`secrets.ca.mode`)

| Mode | CA private keys live in | Source of truth |
|---|---|---|
| `managed` (default) | the database, AES-256-GCM-encrypted with the master key; generated on first start | the database |
| `self-managed` | files mounted from a Secret, read-only; **never** written to the database | your Git repository (SOPS) |

`self-managed` covers all three CAs (SSH user CA, SSH host CA, agent mTLS CA)
at once — there is no per-purpose mixed mode. Background, failure modes and
the rotation procedure: [docs/self-managed-ca.md](../../../docs/self-managed-ca.md).

**Generate the key material** (once, on an operator workstation):

```bash
ssh-keygen -t ed25519 -f user-ca -N '' -C 'guided-ssh user ca'
ssh-keygen -t ed25519 -f host-ca -N '' -C 'guided-ssh host ca'
gssh-server gen-mtls-ca -out mtls-ca      # writes mtls-ca.key (0600) + mtls-ca.crt
```

Only the **private** key files go into the Secret — not the `.pub` files
(the server derives the public keys itself). The keys must be unencrypted;
a passphrase-protected key is a startup error.

```bash
kubectl -n guided-ssh create secret generic guided-ssh-ca-keys \
  --from-file=user-ca \
  --from-file=host-ca \
  --from-file=mtls-ca.key \
  --from-file=mtls-ca.crt
```

```yaml
secrets:
  ca:
    mode: self-managed
    existingSecret: guided-ssh-ca         # master key — still required
    selfManaged:
      existingSecret: guided-ssh-ca-keys
```

The Secret is mounted read-only at `secrets.ca.selfManaged.mountPath`
(default `/etc/gssh/ca`); each key name is also the file name below that
path and thus the value of the corresponding env variable:

| `secrets.ca.selfManaged.keys.*` | Default key = file name | Env variable | Format |
|---|---|---|---|
| `userKey` | `user-ca` | `GSSH_CA_USER_KEY_FILE` | OpenSSH private key PEM |
| `hostKey` | `host-ca` | `GSSH_CA_HOST_KEY_FILE` | OpenSSH private key PEM |
| `mtlsKey` | `mtls-ca.key` | `GSSH_CA_MTLS_KEY_FILE` | PKCS#8 PEM |
| `mtlsCert` | `mtls-ca.crt` | `GSSH_CA_MTLS_CERT_FILE` | X.509 CA certificate PEM |

Notes:

- All four keys must exist in the Secret — a missing key leaves the pod in
  `ContainerCreating`.
- Only these four keys are projected into the volume, so
  `selfManaged.existingSecret` may point at the same Secret as
  `secrets.ca.existingSecret` without the master key ending up on disk.
- Invalid `secrets.ca.mode` or a missing `selfManaged.existingSecret` fails
  the **render**, not the pod (`helm template` reports it).
- In `managed` mode none of the `GSSH_CA_*_FILE` variables are rendered — the
  server rejects them in that mode.

**Rotation** is a Git operation: replace the file content in the Secret and
roll the Deployment. The server adopts the new key as `active` and demotes
the previous one to `retiring`, so its public key stays in the CA bundle and
hosts keep trusting certificates signed by it until they expire. Walkthrough:
[deploy/flux-example/README.md](../../flux-example/README.md).

## Internal database (test environments only)

For trying out guided-ssh or short-lived test deployments you can skip
provisioning PostgreSQL entirely:

```bash
helm install guided-ssh guided-ssh/guided-ssh -n guided-ssh \
  --set internalDatabase.enabled=true \
  --set secrets.ca.existingSecret=guided-ssh-ca
```

`internalDatabase.enabled=true` runs PostgreSQL as a native sidecar container
inside the server pod (requires Kubernetes ≥ 1.29):

- **No database secret needed** — the sidecar listens on `127.0.0.1` only
  (not reachable from outside the pod) and uses fixed dev credentials.
- **Ephemeral by design** — data lives in an `emptyDir`; every pod restart
  starts with an empty database. Since the CA keys are stored in the
  database, a restart also means a **new CA** — fine for tests, fatal for
  anything real.
- **Guard rails** — setting `secrets.db.existingSecret` at the same time is a
  render error (protects against accidentally running on the test database),
  as is `replicaCount > 1` or `autoscaling.enabled=true` (each replica would
  get its own empty database).

Never use this in production or anything you care about.

## PostgreSQL

**Production — external database or CloudNativePG.** The chart deliberately
ships no production database. With [CloudNativePG](https://cloudnative-pg.io):

```yaml
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: guided-ssh-db
spec:
  instances: 3
  storage: { size: 20Gi }
  bootstrap:
    initdb: { database: gssh, owner: gssh }
```

Then reference the generated `guided-ssh-db-app` secret as shown in
[Database secret](#database-secret-secretsdb) above.

**Development — optional subchart** (bitnami/postgresql, not for production):

```bash
kubectl -n guided-ssh create secret generic guided-ssh-dev-db \
  --from-literal=host=guided-ssh-postgresql \
  --from-literal=username=gssh \
  --from-literal=password=dev-only \
  --from-literal=database=gssh \
  --from-literal=sslmode=disable

helm install guided-ssh guided-ssh/guided-ssh -n guided-ssh \
  --set postgresql.enabled=true \
  --set postgresql.auth.password=dev-only \
  --set secrets.db.existingSecret=guided-ssh-dev-db \
  --set secrets.ca.existingSecret=guided-ssh-ca
```

## Database migrations

Run as an init container (`gssh-server migrate`) before every pod start; a
Postgres advisory lock serializes parallel replicas — rollouts with multiple
replicas are safe. Disable via `migrations.enabled=false` (the server also
migrates idempotently on startup, with the same lock).

## Agent API (mTLS)

Host agents (`gssh-agentd`) speak mTLS on port 8443. TLS terminates in the
application — **no** HTTP ingress, instead:

- `agent.service.type=LoadBalancer` (the default service is ClusterIP), or
- an ingress controller with TLS passthrough (e.g. ingress-nginx
  `--enable-ssl-passthrough`).

`agent.tlsNames` must contain the DNS name agents use to reach the server
(default: cluster-internal service name).

## Metrics

`/metrics` listens on its own port (9090) and is not exposed through the
ingress. `metrics.serviceMonitor.enabled=true` creates a ServiceMonitor
(requires the Prometheus operator CRDs). Metrics include:

- `gssh_certificates_issued_total{requester,cert_type}` — issued certificates
- `gssh_http_responses_total{code}` — responses by status (error rates)
- `gssh_agent_heartbeats_total` — agent contacts

## Important values

| Value | Default | Description |
|---|---|---|
| `secrets.db.existingSecret` | `""` (required) | Secret with the PostgreSQL connection values |
| `secrets.db.keys.*` | `host`/`port`/`username`/`password`/`database`/`sslmode` | Key names inside the DB secret |
| `secrets.ca.existingSecret` | `""` (required) | Secret with the CA master key |
| `secrets.ca.keys.masterKey` | `ca-master-key` | Key name inside the CA secret |
| `secrets.ca.mode` | `managed` | `managed` (CA keys generated into the DB) or `self-managed` (CA keys mounted from a Secret) |
| `secrets.ca.selfManaged.existingSecret` | `""` (required with `mode=self-managed`) | Secret with the four CA key files |
| `secrets.ca.selfManaged.keys.*` | `user-ca`/`host-ca`/`mtls-ca.key`/`mtls-ca.crt` | Key names = file names inside the CA key secret |
| `secrets.ca.selfManaged.mountPath` | `/etc/gssh/ca` | Read-only mount path of the CA key files |
| `internalDatabase.enabled` | `false` | **Test only**: ephemeral Postgres sidecar instead of `secrets.db` (mutually exclusive) |
| `internalDatabase.image` / `pullPolicy` | `postgres:16-alpine` / `IfNotPresent` | Sidecar image; pull policy is independent of `image.pullPolicy` |
| `config.oidc.issuer` / `clientID` | `""` | User OIDC; empty ⇒ `/v1/sign/user` disabled |
| `config.ci.issuer` / `audience` | `""` | GitLab CI issuer; empty ⇒ `/v1/sign/ci` disabled |
| `config.groups.admin/auditor/readOnly` | `""` | IdP role groups |
| `config.keycloak.*` | `""` | Group sync via Keycloak admin API |
| `config.rateLimit.trustProxy` | `true` | Client IP from `X-Forwarded-For` (behind ingress) |
| `agent.enabled` / `agent.tlsNames` | `true` / service DNS | Agent API (mTLS) |
| `metrics.serviceMonitor.enabled` | `false` | ServiceMonitor for the Prometheus operator |
| `ingress.enabled` | `false` | Ingress for API/UI |
| `networkPolicy.enabled` | `false` | NetworkPolicy (ports http/agent/metrics) |
| `podDisruptionBudget.enabled` | `false` | PDB (`minAvailable: 1`) |
| `autoscaling.enabled` | `false` | HPA (CPU, optionally memory) |
| `postgresql.enabled` | `false` | Dev-only subchart bitnami/postgresql |

Full list with comments: [values.yaml](values.yaml).

## Chart release (GitHub Pages)

The `helm-chart` job in `.github/workflows/build.yml` publishes the chart
together with binaries and image on every release (`vX.Y.Z`): `helm package`
builds the `.tgz`, which is committed — together with a merged `index.yaml`
(repo URL `https://guided-traffic.github.io/guided-ssh/`) — directly to the
`gh-pages` branch and additionally attached to the release. `version` and
`appVersion` come from the release tag; the Chart.yaml values are only a lint
baseline. One-time setup:

```bash
git checkout --orphan gh-pages
git rm -rf .
git commit --allow-empty -m "chore: init helm repository"
git push origin gh-pages
# GitHub → Settings → Pages → Branch gh-pages
```
