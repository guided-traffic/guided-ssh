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
  --set config.oidc.client.clientID=gssh-cli \
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
| `config.oidc.server.existingSecret` (optional) | Client secret of the server's own OIDC client (server-side UI login/BFF) |

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

Host agents (`gssh-agentd`) speak mTLS on port 8443, served by
`<fullname>-agent` (Service, and — when enabled — Ingress). TLS terminates in
the **server**: it presents a certificate from the internal mTLS CA and
authenticates agents by client certificate.

> **Anything that terminates TLS in front of it breaks the agent path.** A
> normal (TLS-terminating) ingress presents its own certificate and never asks
> for a client certificate — every agent connection fails the handshake. What
> the agent endpoint needs is raw TCP to port 8443.

Four ways to deliver that raw TCP:

| Exposure | Values | Agent source IP seen by the server | `hostRollout.agentPublicUrl` |
|---|---|---|---|
| **In-cluster only** (default) | `agent.service.type: ClusterIP` | real | n/a |
| **Dedicated IP** | `agent.service.type: LoadBalancer` (+ `agent.service.annotations` for LB class/IP) | LB-dependent (often SNAT'ed to a node IP); real via `agent.proxyProtocol` if the LB sends the header | explicit, `https://<host>:8443` |
| **NodePort** behind an external LB/appliance | `agent.service.type: NodePort` | appliance-dependent; real via `agent.proxyProtocol` | explicit |
| **TLS-passthrough ingress** | `agent.ingress.*` (below) | ingress controller pod IP; real via `agent.proxyProtocol` | derived from `agent.ingress.host` |

Restoring the agent's real source IP for the audit log is the job of
[`agent.proxyProtocol`](#real-agent-source-ip-proxy-protocol-agentproxyprotocol)
— it is transport-neutral and works for all three external variants.

### TLS-passthrough ingress (`agent.ingress`)

An ingress controller that does **SSL/TLS passthrough** routes on the SNI of
the ClientHello and forwards the raw stream — the TLS session stays end-to-end
between agent and server, so mTLS works unchanged and the controller never
holds the agent-facing private key. This costs no extra LoadBalancer IP: the
agent hostname points at the same address as the API/UI ingress.

```yaml
# values.yaml
agent:
  ingress:
    enabled: true
    # Class of the passthrough-capable controller — may differ from
    # ingress.className (the API/UI ingress terminates TLS normally).
    className: haproxy
    # Bare DNS name; scheme, port, path or a wildcard fail at render time.
    host: gssh-agent.example.com
    annotations:
      haproxy-ingress.github.io/ssl-passthrough: "true"
```

Passthrough is switched on per controller, by annotation — the chart stays
controller-agnostic and renders a plain `networking.k8s.io/v1` Ingress
(one rule, path `/`, backend `<fullname>-agent:agent`):

| Controller | Annotation | Notes |
|---|---|---|
| haproxy-ingress (jcmoraisjr) | `haproxy-ingress.github.io/ssl-passthrough: "true"` | routes on the Ingress rule host |
| haproxytech kubernetes-ingress | `haproxy.org/ssl-passthrough: "true"` | switches the whole frontend to SNI inspection |
| ingress-nginx | `nginx.ingress.kubernetes.io/ssl-passthrough: "true"` | controller must run with `--enable-ssl-passthrough` |

Quote the value (`"true"`) — an unquoted YAML boolean is not what the
controllers match on. Traefik and Gateway API are not templated: bring your
own `IngressRouteTCP` / `TLSRoute` (passthrough mode) against the same
Service.

The Ingress deliberately carries **no `tls:` block**: there is no controller
certificate on a passthrough vhost, and a `secretName` would make some
controllers start terminating — the exact failure mode described above.

**One hostname, three consumers.** With `agent.ingress.enabled` the host
becomes the single source of truth and feeds two derivations:

| Derived | Value | Overridden by |
|---|---|---|
| `GSSH_AGENT_TLS_NAMES` | default SANs **+** `agent.ingress.host` | explicit `agent.tlsNames` (replaces the whole list) |
| `GSSH_AGENT_PUBLIC_URL` | `https://<agent.ingress.host>` — no port, the passthrough entry is the controller's 443 | explicit `hostRollout.agentPublicUrl` |

An agent URL on any other port (e.g. a LoadBalancer on `:8443`) therefore
stays an explicit `hostRollout.agentPublicUrl`. A **disabled** `agent.ingress`
derives nothing, even with a host set.

**Verify a rollout** — the endpoint must answer with the *internal CA's*
certificate, not the ingress wildcard:

```bash
openssl s_client -connect gssh-agent.example.com:443 \
  -servername gssh-agent.example.com </dev/null 2>/dev/null |
  openssl x509 -noout -issuer -ext subjectAltName
```

A wildcard/Let's Encrypt issuer here means the passthrough annotation is not
in effect — the controller is terminating.

**Known limitation — source IP.** With plain passthrough the server sees the
ingress controller's pod IP, not the agent's; agent-side audit entries record
that IP. Agent authentication is mTLS, not IP-based, so this weakens no access
control. `agent.proxyProtocol` (below) restores the real address; until it is
enabled the controller must **not** be configured to send PROXY headers — the
listener would read them as garbage TLS bytes. (`config.rateLimit.trustProxy`
is HTTP-header based and does not apply to this raw TLS listener.)

**NetworkPolicy.** With `networkPolicy.enabled=true`, agent traffic now
arrives from the controller's pods rather than an LB — `networkPolicy.agentFrom`
takes the peers:

```yaml
networkPolicy:
  enabled: true
  agentFrom:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: ingress-haproxy
```

Design rationale, feasibility and the full rollout checklist:
[docs/major-tickets/AGENT_INGRESS.md](../../../docs/major-tickets/AGENT_INGRESS.md).

### Real agent source IP: PROXY protocol (`agent.proxyProtocol`)

Anything that forwards raw TCP hides the client address. The PROXY protocol
puts it back: the proxy prepends a small header (v1 or v2) *before* the TLS
bytes — which is why it composes with passthrough — and the server reads the
agent's real address out of it.

**Why a trust policy, given mTLS.** mTLS governs *access*: without a valid
client certificate the connection dies in the handshake, header or not. It
does not govern the *integrity of the recorded source address* — an
authenticated but compromised host that may send its own PROXY header writes
any IP it likes into the audit log (hiding its origin, or framing another
host). The policy therefore decides per connection who may speak PROXY
protocol at all:

| Connection from | With PROXY header | Without |
|---|---|---|
| a trusted sender | accepted, address taken from the header | **rejected** — a trusted proxy that stops sending one is a misconfiguration; fail closed rather than silently log the proxy's IP |
| anyone else | **rejected** — spoofing attempt | plain connection, works as before |
| *(empty `trusted` list)* | required from everyone | rejected |

```yaml
# values.yaml
agent:
  proxyProtocol:
    enabled: true
    trusted:
      - haproxy-pods.ingress.svc.cluster.local   # headless Service, see below
      # - 10.42.0.0/16                            # CIDRs and plain IPs work too
```

**Trusted entries: CIDRs, IPs, or DNS names.** A name is resolved to its
A/AAAA records, re-resolved every 15 s, and additionally right after a
connection from an unknown address (rate-limited) so a restarted controller pod
is trusted again immediately instead of after the next tick. An unresolvable
name **aborts startup** (a typo must not degrade into an empty trust set); a
DNS failure later keeps the last known good set and logs a warning. No
Kubernetes API access is involved — the server keeps
`automountServiceAccountToken: false`.

> **It has to be a headless Service.** A normal Service name resolves to the
> ClusterIP, which never appears as a source address — every connection would
> be untrusted. Trusting the whole pod CIDR instead would trust every pod in
> the cluster. If your ingress controller chart ships no headless Service, add
> one next to it:
>
> ```yaml
> apiVersion: v1
> kind: Service
> metadata:
>   name: haproxy-pods
>   namespace: ingress
> spec:
>   clusterIP: None
>   # A terminating-but-still-forwarding controller pod must not drop out of
>   # the trusted set mid-rollout.
>   publishNotReadyAddresses: true
>   selector:
>     app.kubernetes.io/name: haproxy-ingress
>   ports:
>     - name: https
>       port: 443
> ```

**Sender side** — one annotation per controller, on the same Ingress:

| Controller | Annotation | Notes |
|---|---|---|
| haproxy-ingress (jcmoraisjr) | `haproxy-ingress.github.io/proxy-protocol: "v2"` | backend scope; values `v1`, `v2`, `v2-ssl`, `v2-ssl-cn` |
| haproxytech kubernetes-ingress | `haproxy.org/send-proxy-protocol: "proxy-v2"` | |
| ingress-nginx | no documented send-proxy annotation for `ssl-passthrough` backends | verify against your controller version before enabling the server side |

> **Rollout order matters — both directions.** Enable
> `agent.proxyProtocol.enabled` **first**, then the controller's send-proxy
> annotation; disable in the reverse order. Getting it wrong breaks the agent
> endpoint: the listener reads a header it does not expect as garbage TLS
> bytes, or waits for one that never comes. The chart deliberately does not
> couple this to `agent.ingress.enabled` — it cannot know the controller's
> configuration.

> **Health checks must send the header too.** The fail-closed cell above also
> applies to the controller's TCP health checks against the backend (HAProxy:
> `check-send-proxy`). If the controller checks without a header, the checks
> are rejected and the backend flaps down — a full agent-path outage. After
> enabling, watch the backend in the controller's stats over several check
> intervals.

**Transitive trust chain.** If the controller itself sits behind an external
LoadBalancer that gives it the real client IP (accept-proxy), its own header
carries that address onward and the audit log records the *agent's* IP rather
than the LB's. The flip side: the recorded address is only as trustworthy as
the whole chain agent → LB → controller → gssh. Whoever can inject PROXY
protocol at the LB entry writes the audit log. Acceptable for a
provider-managed LB; if it is not for you, keep the chain to one hop.

**Verify** after enabling: an agent heartbeat must log the agent's external IP
— neither the controller's pod IP nor the LB's. A direct in-cluster connection
sending a forged header must be rejected, and a direct connection without one
must still work (unless `trusted` is empty, which requires a header from
everybody).

## Host rollout (one-command install)

`hostRollout.enabled=true` turns on the "Add host" button in the web UI: the
server mints a short-lived enrollment token and serves a templated
`install.sh` that downloads the matching `gssh-agentd` binary (embedded in the
server image), verifies its SHA-256 and enrolls the host — pinned to the
server's public TLS key.

The feature is strictly optional. With `enabled: false` nothing is rendered
and nothing is required. With `enabled: true` the chart **fails to render**
when a mandatory value is missing, so misconfiguration surfaces at
`helm install/upgrade/lint` time instead of on the fleet. The server-side gate
stays authoritative (it also covers non-Helm deployments and drift): without
binaries, pin, agent URL and public URL the rollout endpoints answer `503` and
name the missing conditions.

```bash
helm upgrade guided-ssh guided-ssh/guided-ssh -n guided-ssh --reuse-values \
  --set hostRollout.enabled=true \
  --set hostRollout.agentPublicUrl=https://gssh-agent.example.com:8443 \
  --set config.publicURL=https://gssh.example.com
```

`agentPublicUrl` is only ever derived from `agent.ingress.host` (see
[Agent API](#agent-api-mtls)) — an operator-declared public name whose Ingress
is exactly the path agents take. Nothing else is guessed: a wrong agent URL
would land unnoticed in the `config.yaml` of every enrolled host. With a
passthrough ingress the whole block collapses to one hostname:

```bash
helm upgrade guided-ssh guided-ssh/guided-ssh -n guided-ssh --reuse-values \
  --set hostRollout.enabled=true \
  --set config.publicURL=https://gssh.example.com \
  --set agent.ingress.enabled=true \
  --set agent.ingress.className=haproxy \
  --set agent.ingress.host=gssh-agent.example.com \
  --set-string 'agent.ingress.annotations.haproxy-ingress\.github\.io/ssl-passthrough=true'
# ⇒ Ingress gssh-agent.example.com → agent Service, that name in the
#   certificate SANs, and https://gssh-agent.example.com in every install
#   command — no separate agentPublicUrl.
```

`config.publicURL` is the server's external public URL (also used for the UI
login redirect and the client install) and must be https here.

### Which pin source (`hostRollout.pin.source`)

SPKI pinning is mandatory, not opt-in. All three sources are fail-closed: no
pin ⇒ no rollout.

| Source | When | Rotation |
|---|---|---|
| `dial` (default) | The server can reach its own public URL from inside the cluster | Automatic (background + lazy refresh, `pin.refreshInterval`) |
| `file` | Hairpin/split-horizon DNS, or the certificate is managed by cert-manager anyway | Automatic — the file is read uncached on every pin lookup |
| `static` | Last resort, e.g. a CDN or an external terminator whose certificate the cluster never sees | Manual (operator sets the new pin) |

**`dial`** — the server dials `config.publicURL` and reads the leaf certificate, i.e.
exactly what a host sees during enrollment. Verified against the system roots
(a private CA needs `SSL_CERT_FILE`/`SSL_CERT_DIR` via `config.extraEnv`).
Requires hairpin access: if the cluster cannot resolve or reach its own
external URL from a pod, use `file` or `static`.

**`file`** — mount the ingress TLS secret:

```yaml
config:
  publicURL: https://gssh.example.com
hostRollout:
  enabled: true
  agentPublicUrl: https://gssh-agent.example.com:8443
  pin:
    source: file
    certSecretName: gssh-example-com-tls
```

The chart projects **only `tls.crt`** (the server does not need the key) and
mounts it **without `subPath`** at `/etc/gssh/public-tls/tls.crt` — the kubelet
only updates secret mounts that have no `subPath`, so a renewed certificate is
picked up automatically. The secret must live in the server namespace; a
wildcard certificate from another namespace needs reflector/kubed or its own
`Certificate` resource.

**`static`** — compute the pin from the public endpoint:

```bash
openssl s_client -connect gssh.example.com:443 -servername gssh.example.com < /dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | base64
```

```bash
--set hostRollout.pin.source=static --set hostRollout.pin.static=<base64-pin>
```

Rotating the certificate means rotating this value — a stale static pin breaks
every new enrollment (the TLS handshake fails **before** the token is spent, so
no token is burned).

### Download rate limit

`hostRollout.downloadRpm` (default 10) limits binary downloads per client IP
and minute; `0` disables the limiter. The manifest and the binary are public —
the enrollment token gates the enrollment, not the download. `X-Forwarded-For`
handling is inherited from `config.rateLimit.trustProxy`.

## Rules provisioning (GitOps)

Access rules (host grants) and CI rules are expected to be managed
declaratively. `config.rules` has two independent switches: whether in-app
editing is allowed at all, and where each domain gets its rules from.

| `config.rules.manualProvision` | `existingConfigMap` of the domain | CRUD API | `…/apply` API | UI editing |
|---|---|---|---|---|
| `false` (default) | unset | 403 `manual_rules_disabled` | allowed | hidden |
| `true` | unset | allowed | allowed | shown |
| any | set | 403 `rules_file_managed` | 403 `rules_file_managed` | hidden |

The two domains are independent: host rules can come from a ConfigMap while
CI rules stay on the `…/apply` path. Reading is never gated — the rules pages
stay visible for admins and auditors, only without Add/Edit/Delete.

The chart refuses `manualProvision: true` together with any
`existingConfigMap` at render time: a file-owned domain rejects every API
write, so the buttons would be dead UI. Mixed mode (one domain hand-edited,
the other Git-owned) is deliberately not offered by the chart — set
`GSSH_MANUAL_RULES` via `config.extraEnv` if you really need it.

### ConfigMap sources

The chart does **not** create the rules ConfigMaps — they are maintained
separately (kustomize `configMapGenerator`, Flux, plain manifest). The file
schema is the one `gssh-admin apply` uses, split per domain:

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

Each ConfigMap is mounted as its own volume with an `items:` projection onto
`/etc/guided-ssh/rules/<domain>/rules.yaml`, read-only and **without
`subPath`** — a subPath mount never receives ConfigMap updates. The
`GSSH_HOST_RULES_FILE` / `GSSH_CI_RULES_FILE` env vars are derived from it.

Behavior of a file-owned domain:

- **Startup**: file missing or invalid ⇒ the server exits. A wrong key name
  or broken YAML is a deployment bug and shows up as a crash loop.
- **Runtime**: the file is re-applied every 30 s. Together with the kubelet's
  ConfigMap sync, an edit propagates within roughly 1–2 minutes. The loop is
  also drift correction: rules changed out of band in the database are
  reverted on the next tick.
- An **empty list** (`grants: []`) deletes all rules of that domain; a file
  *without* the `grants:` key is a validation error, not "delete everything".
- A file that turns invalid at runtime keeps the last applied state, logs the
  error and increments `gssh_rules_file_sync_errors_total{domain}` — a bad
  rules push must not stop certificate signing.
- Applies are audited with the actor `system:rules-file`.
- Host entries without an explicit `issuer:` fall back to
  `config.oidc.issuer` (the API path takes it from the admin's token, which
  the reconciler does not have). Without either, the startup apply fails.

`helm test` renders a pod that compares the server's `/v1/ui/config`
editability flags against these values.

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
| `config.publicURL` | `""` | External public base URL (UI login redirect, install command, pin dial); required (https) for host rollout and client install |
| `config.oidc.issuer` | `""` | Shared IdP issuer; empty ⇒ `/v1/sign/user` disabled |
| `config.oidc.client.clientID` | `""` (required with issuer) | Public OIDC client of the gssh/gssh-admin CLIs (no secret); expected bearer audience |
| `config.oidc.server.clientID` / `existingSecret` | `""` | Confidential OIDC client of the server (UI login/BFF); set together, must differ from `oidc.client` — both empty ⇒ UI login disabled |
| `config.oidc.server.existingSecretKey` | `client-secret` | Key inside the server OIDC secret |
| `config.oidc.server.scopes` | `""` (= `openid,profile,email,groups`) | Scopes of the server-side UI login |
| `config.ci.issuer` / `audience` | `""` | GitLab CI issuer; empty ⇒ `/v1/sign/ci` disabled |
| `config.groups.admin/auditor` | `""` | IdP role groups (admin ⊃ auditor; empty ⇒ role granted to nobody) |
| `config.keycloak.*` | `""` | Group sync via Keycloak admin API |
| `config.rules.manualProvision` | `false` | In-app rule editing (UI + CRUD API); see [Rules provisioning](#rules-provisioning-gitops) |
| `config.rules.host.existingConfigMap` / `ci.existingConfigMap` | `""` | ConfigMap with the declarative rules of that domain (chart-external); set ⇒ the domain rejects all API writes |
| `config.rules.host.key` / `ci.key` | `host-rules.yaml` / `ci-rules.yaml` | Key inside that ConfigMap |
| `config.rateLimit.trustProxy` | `true` | Client IP from `X-Forwarded-For` (behind ingress) |
| `agent.enabled` | `true` | Agent API (mTLS) on port 8443 |
| `agent.tlsNames` | `""` (= service DNS, plus `agent.ingress.host`) | SANs of the agent server certificate; an explicit value replaces the whole default list |
| `agent.service.type` / `annotations` | `ClusterIP` / `{}` | Exposure of the agent port — see [Agent API](#agent-api-mtls) |
| `agent.ingress.enabled` | `false` | TLS-**passthrough** ingress for the agent port; requires `agent.enabled` and `agent.service.enabled` |
| `agent.ingress.className` | `""` | Ingress class of the passthrough-capable controller (may differ from `ingress.className`) |
| `agent.ingress.host` | `""` (required with `enabled`) | Public agent hostname, bare DNS name; feeds the certificate SANs and `hostRollout.agentPublicUrl` |
| `agent.ingress.annotations` | `{}` | Controller-specific passthrough annotations (no defaults — see the table above) |
| `agent.proxyProtocol.enabled` | `false` | PROXY protocol (v1/v2) on the agent listener — real agent source IP; roll out **before** the sender's send-proxy annotation |
| `agent.proxyProtocol.trusted` | `[]` | Who may send a PROXY header: CIDRs, IPs, or DNS names (headless Service of the proxy pods). Empty ⇒ header required from **every** connection |
| `hostRollout.enabled` | `false` | One-command host install; `true` requires the values below |
| `hostRollout.agentPublicUrl` | `""` (required with `enabled`, unless derived from `agent.ingress.host`) | External mTLS agent URL written into every enrolled host |
| `hostRollout.pin.source` | `dial` | `dial` / `file` / `static` — see [Which pin source](#which-pin-source-hostrolloutpinsource) |
| `hostRollout.pin.static` / `certSecretName` | `""` | Required for `source=static` / `source=file` |
| `hostRollout.pin.refreshInterval` | `5m` | Refresh interval of the pin self-dial (`source=dial`) |
| `hostRollout.downloadRpm` | `10` | Binary downloads per client IP and minute (`0` = off) |
| `metrics.serviceMonitor.enabled` | `false` | ServiceMonitor for the Prometheus operator |
| `ingress.enabled` | `false` | Ingress for API/UI |
| `networkPolicy.enabled` | `false` | NetworkPolicy (ports http/agent/metrics) |
| `podDisruptionBudget.enabled` | `false` | PDB (`minAvailable: 1`) |
| `autoscaling.enabled` | `false` | HPA (CPU, optionally memory) |
| `postgresql.enabled` | `false` | Dev-only subchart bitnami/postgresql |

Full list with comments: [values.yaml](values.yaml).

## Migration: server/client OIDC split

The OIDC configuration was split into the clients' public client and the
server's confidential client. The old keys make the chart **fail at render
time** with a hint, and the old env variables stop the server at startup —
nothing is silently ignored:

| Old | New |
|---|---|
| `config.oidc.clientID` (`GSSH_OIDC_CLIENT_ID`) | `config.oidc.client.clientID` (`GSSH_CLIENT_OIDC_CLIENT_ID`) |
| `config.oidc.uiClientID` (`GSSH_UI_OIDC_CLIENT_ID`) | `config.oidc.server.clientID` (`GSSH_SERVER_OIDC_CLIENT_ID`) |
| `config.oidc.uiExistingSecret` / `uiExistingSecretKey` (`GSSH_UI_OIDC_CLIENT_SECRET`) | `config.oidc.server.existingSecret` / `existingSecretKey` (`GSSH_SERVER_OIDC_CLIENT_SECRET`) |
| — (`GSSH_UI_OIDC_SCOPES`) | `config.oidc.server.scopes` (`GSSH_SERVER_OIDC_SCOPES`) |
| `config.oidc.uiBaseURL` (`GSSH_UI_BASE_URL`) | `config.publicURL` (`GSSH_PUBLIC_URL`) |
| `hostRollout.publicUrl` | `config.publicURL` |

Semantic changes on top of the renames:

- The server's client (`oidc.server.*`) and the clients' client
  (`oidc.client.clientID`) must be **different IdP clients** — reusing one is
  now a startup error. The server authenticates with a client secret
  (confidential); the CLIs without one (public, authorization code + PKCE).
  Create a separate confidential client in the IdP for the UI login, redirect
  URI `<config.publicURL>/v1/auth/callback`.
- `oidc.server.clientID` no longer falls back to the clients' client ID —
  set it explicitly together with `existingSecret`.
- `/v1/ui/config` and `/client.sh` now always advertise the clients' public
  client to CLI installs (previously they leaked the UI client ID when one
  was configured).

### readonly role removed

The `readonly` role was merged into `auditor` (now the read role for all
views plus the audit log). As above, old keys fail at render/startup time:

| Old | New |
|---|---|
| `config.groups.readOnly` (`GSSH_READONLY_GROUP`) | removed — assign the group to `config.groups.auditor` instead |

Semantic changes:

- Endpoints that accepted the readonly role now require auditor.
- The **web-UI login is rejected** for users with neither the admin nor the
  auditor role (previously a role-less session was created); the login page
  explains the missing role. An empty group value grants the role to nobody.

## Migration: in-app rule editing is off by default

**Breaking change on upgrade.** Rule editing in the web UI (and the CRUD API
behind it) used to be available to every admin. It is now opt-in and disabled
by default:

| Before | After |
|---|---|
| Add/Edit/Delete for grants and CI rules always visible to admins | visible only with `config.rules.manualProvision: true` |
| `POST`/`PUT`/`DELETE` on `/v1/admin/grants…` and `/v1/admin/ci-grants…` open to admins | 403 `manual_rules_disabled` unless `manualProvision` is set |

To keep the previous behavior, set:

```yaml
config:
  rules:
    manualProvision: true
```

Unaffected: reading rules, and the declarative `…/apply` path
(`gssh-admin apply`, the sync CronJob) — those keep working with the new
default. See [Rules provisioning](#rules-provisioning-gitops) for the full
matrix and the ConfigMap-based alternative.

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
