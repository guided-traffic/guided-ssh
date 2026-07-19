#!/usr/bin/env bash
# Testet den GitOps-Upgrade-Pfad (Phase 12): kind-Cluster mit Flux-
# Controllern, guided-ssh-Chart Version A aus einem lokalen (in-cluster)
# Helm-Repo installieren, HelmRelease auf Version B bumpen — der Bump
# simuliert den Git-Commit im GitOps-Repo — und verifizieren, dass Flux das
# Upgrade ausrollt und die DB-Migrationen automatisch laufen (Init-Container
# migrate, goose mit Advisory-Lock).
#
# Voraussetzungen: docker, kind, kubectl, helm, flux (CLI).
# Aufräumen: Cluster wird am Ende gelöscht (KEEP_CLUSTER=1 verhindert das).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLUSTER="${CLUSTER:-gssh-flux-upgrade}"
IMAGE_TAG="upgrade-test"
VERSION_A="0.1.0"
VERSION_B="0.1.1"
WORKDIR="$(mktemp -d)"

log() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

cleanup() {
  rm -rf "$WORKDIR"
  if [ "${KEEP_CLUSTER:-0}" != "1" ]; then
    kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

for tool in docker kind kubectl helm flux; do
  command -v "$tool" >/dev/null || { echo "fehlt: $tool" >&2; exit 1; }
done

log "Image bauen und in kind laden"
docker build -t "guided-ssh:${IMAGE_TAG}" "$REPO_ROOT"
kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
kind create cluster --name "$CLUSTER" --wait 120s
kind load docker-image "guided-ssh:${IMAGE_TAG}" --name "$CLUSTER"

log "Flux-Controller installieren (source + helm)"
flux install --components=source-controller,helm-controller

log "Chart in Versionen ${VERSION_A} und ${VERSION_B} paketieren"
helm package "$REPO_ROOT/deploy/helm/guided-ssh" --version "$VERSION_A" -d "$WORKDIR/repo" >/dev/null
helm package "$REPO_ROOT/deploy/helm/guided-ssh" --version "$VERSION_B" -d "$WORKDIR/repo" >/dev/null
helm repo index "$WORKDIR/repo"

log "Lokales Helm-Repo in-cluster ausrollen (nginx + ConfigMap)"
kubectl create configmap chart-repo --from-file="$WORKDIR/repo"
kubectl apply -f - <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: chart-repo
spec:
  replicas: 1
  selector: { matchLabels: { app: chart-repo } }
  template:
    metadata: { labels: { app: chart-repo } }
    spec:
      containers:
        - name: nginx
          image: nginx:1.27-alpine
          ports: [{ containerPort: 80 }]
          volumeMounts: [{ name: repo, mountPath: /usr/share/nginx/html }]
      volumes:
        - name: repo
          configMap: { name: chart-repo }
---
apiVersion: v1
kind: Service
metadata:
  name: chart-repo
spec:
  selector: { app: chart-repo }
  ports: [{ port: 80 }]
EOF
kubectl rollout status deploy/chart-repo --timeout=120s

log "Namespace, PostgreSQL und Pflicht-Secret anlegen"
kubectl create namespace guided-ssh
kubectl -n guided-ssh apply -f - <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres
spec:
  replicas: 1
  selector: { matchLabels: { app: postgres } }
  template:
    metadata: { labels: { app: postgres } }
    spec:
      containers:
        - name: postgres
          image: postgres:16-alpine
          env:
            - { name: POSTGRES_USER, value: gssh }
            - { name: POSTGRES_PASSWORD, value: gssh }
            - { name: POSTGRES_DB, value: gssh }
          ports: [{ containerPort: 5432 }]
---
apiVersion: v1
kind: Service
metadata:
  name: postgres
spec:
  selector: { app: postgres }
  ports: [{ port: 5432 }]
EOF
kubectl -n guided-ssh create secret generic guided-ssh \
  --from-literal=dsn='postgres://gssh:gssh@postgres:5432/gssh?sslmode=disable' \
  --from-literal=ca-master-key="$(openssl rand -base64 32)"
kubectl -n guided-ssh rollout status deploy/postgres --timeout=120s

log "HelmRepository + HelmRelease (Version ${VERSION_A}) anlegen"
kubectl apply -f - <<EOF
apiVersion: source.toolkit.fluxcd.io/v1
kind: HelmRepository
metadata:
  name: guided-ssh
  namespace: guided-ssh
spec:
  interval: 1m
  url: http://chart-repo.default.svc.cluster.local
---
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: guided-ssh
  namespace: guided-ssh
spec:
  interval: 1m
  timeout: 3m
  chart:
    spec:
      chart: guided-ssh
      version: "${VERSION_A}"
      sourceRef:
        kind: HelmRepository
        name: guided-ssh
      interval: 1m
  values:
    image:
      repository: guided-ssh
      tag: ${IMAGE_TAG}
      pullPolicy: Never
    secrets:
      existingSecret: guided-ssh
EOF

log "Warten auf Release ${VERSION_A}"
kubectl -n guided-ssh wait helmrelease/guided-ssh \
  --for=condition=Ready --timeout=5m
kubectl -n guided-ssh rollout status deploy/guided-ssh --timeout=180s

# HelmRelease v2: history[0] ist der zuletzt ausgerollte Release-Snapshot.
applied="$(kubectl -n guided-ssh get helmrelease guided-ssh \
  -o jsonpath='{.status.history[0].chartVersion}')"
[ "$applied" = "$VERSION_A" ] || { echo "FEHLER: ausgerollte Chart-Version=$applied, erwartet $VERSION_A" >&2; exit 1; }

pod="$(kubectl -n guided-ssh get pod -l app.kubernetes.io/name=guided-ssh \
  --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[-1:].metadata.name}')"
kubectl -n guided-ssh logs "$pod" -c migrate | tail -3
echo "OK: Release ${VERSION_A} ready, Migrationen gelaufen"

log "Chart-Version-Bump auf ${VERSION_B} (simulierter Git-Commit)"
kubectl -n guided-ssh patch helmrelease guided-ssh --type=merge \
  -p "{\"spec\":{\"chart\":{\"spec\":{\"version\":\"${VERSION_B}\"}}}}"

log "Warten auf Upgrade auf ${VERSION_B}"
# Erst wird Ready kurz False (Upgrade läuft), dann wieder True mit neuer Revision.
for _ in $(seq 60); do
  applied="$(kubectl -n guided-ssh get helmrelease guided-ssh \
    -o jsonpath='{.status.history[0].chartVersion}')"
  [ "$applied" = "$VERSION_B" ] && break
  sleep 5
done
[ "$applied" = "$VERSION_B" ] || { echo "FEHLER: Upgrade auf $VERSION_B nicht angekommen (ausgerollt: $applied)" >&2; exit 1; }
kubectl -n guided-ssh wait helmrelease/guided-ssh \
  --for=condition=Ready --timeout=5m
kubectl -n guided-ssh rollout status deploy/guided-ssh --timeout=180s

# Migrationen sind beim Upgrade erneut gelaufen (neuer Pod, Init-Container
# migrate beendet mit Exit 0; goose meldet "no migrations to run").
pod="$(kubectl -n guided-ssh get pod -l app.kubernetes.io/name=guided-ssh \
  --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[-1:].metadata.name}')"
exit_code="$(kubectl -n guided-ssh get pod "$pod" \
  -o jsonpath='{.status.initContainerStatuses[?(@.name=="migrate")].state.terminated.exitCode}')"
[ "$exit_code" = "0" ] || { echo "FEHLER: migrate-Init-Container Exit-Code $exit_code" >&2; exit 1; }
kubectl -n guided-ssh logs "$pod" -c migrate | tail -3

log "PASS: Chart-Bump ${VERSION_A} -> ${VERSION_B} via Flux, Migrationen automatisch"
