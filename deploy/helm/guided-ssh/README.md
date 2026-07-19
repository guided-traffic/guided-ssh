# guided-ssh Helm-Chart

Deployt den guided-ssh-Server (API + eingebettete Web-UI, Agent-API mit mTLS,
Prometheus-Metriken) auf Kubernetes.

## Installation

```bash
helm repo add guided-ssh https://guided-traffic.github.io/guided-ssh
helm repo update

kubectl create namespace guided-ssh

# Pflicht-Secret: DSN + CA-Master-Key (Beispiel; produktiv external-secrets/SOPS)
kubectl -n guided-ssh create secret generic guided-ssh \
  --from-literal=dsn='postgres://gssh:PASS@db.example.com:5432/gssh?sslmode=require' \
  --from-literal=ca-master-key="$(openssl rand -base64 32)"

helm install guided-ssh guided-ssh/guided-ssh -n guided-ssh \
  --set secrets.existingSecret=guided-ssh \
  --set config.oidc.issuer=https://idp.example.com/realms/acme \
  --set config.oidc.clientID=guided-ssh \
  --set config.groups.admin=gssh-admins
```

> **Achtung:** `ca-master-key` verschlüsselt die CA-Private-Keys in der
> Datenbank (AES-256). Verlust ⇒ CA unbrauchbar. Sicher ablegen.

## Secrets

Das Chart erzeugt **keine** Secrets — ausschließlich `existingSecret`-Referenzen,
kompatibel mit [external-secrets](https://external-secrets.io) und
[SOPS](https://github.com/getsops/sops):

| Wert | Secret-Key (Default) | Env |
|---|---|---|
| `secrets.existingSecret` (Pflicht) | `dsn` | `GSSH_DB_DSN` |
| `secrets.existingSecret` (Pflicht) | `ca-master-key` | `GSSH_CA_MASTER_KEY` |
| `config.keycloak.existingSecret` (optional) | `kc-client-secret` | `GSSH_KC_CLIENT_SECRET` |

Beispiel `ExternalSecret`:

```yaml
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: guided-ssh
spec:
  refreshInterval: 1h
  secretStoreRef: { name: vault, kind: ClusterSecretStore }
  target: { name: guided-ssh }
  data:
    - secretKey: dsn
      remoteRef: { key: guided-ssh/db, property: dsn }
    - secretKey: ca-master-key
      remoteRef: { key: guided-ssh/ca, property: master-key }
```

## PostgreSQL

**Produktion — extern oder CloudNativePG.** Das Chart bringt bewusst keine
produktive Datenbank mit. Mit [CloudNativePG](https://cloudnative-pg.io):

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

CloudNativePG legt das Secret `guided-ssh-db-app` mit dem Key `uri` an — als
DSN direkt nutzbar:

```yaml
secrets:
  existingSecret: guided-ssh-db-app
  keys:
    dsn: uri
    # ca-master-key liegt in einem eigenen Secret? Dann stattdessen ein
    # kombiniertes Secret pflegen — beide Keys müssen im selben Secret liegen.
```

Liegen DSN und CA-Master-Key getrennt, ein kombiniertes Secret erzeugen
(external-secrets kann aus mehreren Quellen zusammenführen).

**Entwicklung — optionales Subchart** (bitnami/postgresql, nicht für Produktion):

```bash
helm install guided-ssh guided-ssh/guided-ssh -n guided-ssh \
  --set postgresql.enabled=true \
  --set postgresql.auth.password=dev-only \
  --set secrets.existingSecret=guided-ssh-dev
# DSN im Dev-Secret: postgres://gssh:dev-only@guided-ssh-postgresql:5432/gssh
```

## DB-Migrationen

Laufen als Init-Container (`gssh-server migrate`) vor jedem Pod-Start;
ein Postgres-Advisory-Lock serialisiert parallele Replikas — Rollouts mit
mehreren Replikas sind sicher. Abschaltbar via `migrations.enabled=false`
(der Server migriert beim Start ohnehin idempotent, ebenfalls mit Lock).

## Agent-API (mTLS)

Host-Agents (`gssh-agentd`) sprechen mTLS auf Port 8443. TLS endet in der
Anwendung — **kein** HTTP-Ingress, sondern:

- `agent.service.type=LoadBalancer` (Default-Service ist ClusterIP), oder
- Ingress-Controller mit TLS-Passthrough (z. B. ingress-nginx
  `--enable-ssl-passthrough`).

`agent.tlsNames` muss den DNS-Namen enthalten, unter dem Agents den Server
erreichen (Default: Cluster-interner Service-Name).

## Metriken

`/metrics` läuft auf eigenem Port (9090), wird nicht über den Ingress
exponiert. `metrics.serviceMonitor.enabled=true` erzeugt einen ServiceMonitor
(Prometheus-Operator-CRDs erforderlich). Metriken u. a.:

- `gssh_certificates_issued_total{requester,cert_type}` — ausgestellte Zertifikate
- `gssh_http_responses_total{code}` — Antworten nach Status (Fehlerraten)
- `gssh_agent_heartbeats_total` — Agent-Kontakte

## Wichtige Values

| Value | Default | Beschreibung |
|---|---|---|
| `secrets.existingSecret` | `""` (Pflicht) | Secret mit `dsn` und `ca-master-key` |
| `config.oidc.issuer` / `clientID` | `""` | Benutzer-OIDC; leer ⇒ `/v1/sign/user` deaktiviert |
| `config.ci.issuer` / `audience` | `""` | GitLab-CI-Issuer; leer ⇒ `/v1/sign/ci` deaktiviert |
| `config.groups.admin/auditor/readOnly` | `""` | IdP-Rollen-Gruppen |
| `config.keycloak.*` | `""` | Gruppen-Sync via Keycloak-Admin-API |
| `config.rateLimit.trustProxy` | `true` | Client-IP aus `X-Forwarded-For` (hinter Ingress) |
| `agent.enabled` / `agent.tlsNames` | `true` / Service-DNS | Agent-API (mTLS) |
| `metrics.serviceMonitor.enabled` | `false` | ServiceMonitor für Prometheus-Operator |
| `ingress.enabled` | `false` | Ingress für API/UI |
| `networkPolicy.enabled` | `false` | NetworkPolicy (Ports http/agent/metrics) |
| `podDisruptionBudget.enabled` | `false` | PDB (`minAvailable: 1`) |
| `autoscaling.enabled` | `false` | HPA (CPU, optional Memory) |
| `postgresql.enabled` | `false` | Dev-only-Subchart bitnami/postgresql |

Vollständige Liste mit Kommentaren: [values.yaml](values.yaml).

## Chart-Release (GitHub Pages)

Der Workflow `.github/workflows/chart-release.yml` veröffentlicht das Chart
bei einem Version-Bump in `Chart.yaml` (Push auf `main`) via
[chart-releaser](https://github.com/helm/chart-releaser-action) auf den
`gh-pages`-Branch. Einmalige Einrichtung:

```bash
git checkout --orphan gh-pages
git rm -rf .
git commit --allow-empty -m "chore: init helm repository"
git push origin gh-pages
# GitHub → Settings → Pages → Branch gh-pages
```
