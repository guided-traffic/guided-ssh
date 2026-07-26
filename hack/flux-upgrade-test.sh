#!/usr/bin/env bash
# Tests the GitOps upgrade path (phase 12): install a kind cluster with Flux
# controllers, install the guided-ssh chart version A from a local (in-cluster)
# Helm repo, bump the HelmRelease to version B — the bump simulates the Git
# commit in the GitOps repo — and verify that Flux rolls out the upgrade and
# that the DB migrations run automatically (init container migrate, goose with
# advisory lock).
#
# Prerequisites: docker, kind, kubectl, helm, flux (CLI).
# Cleanup: the cluster is deleted at the end (KEEP_CLUSTER=1 prevents that).
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
  command -v "$tool" >/dev/null || { echo "missing: $tool" >&2; exit 1; }
done

log "Building image and loading into kind"
docker build -t "guided-ssh:${IMAGE_TAG}" "$REPO_ROOT"
kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
kind create cluster --name "$CLUSTER" --wait 120s
kind load docker-image "guided-ssh:${IMAGE_TAG}" --name "$CLUSTER"

log "Installing Flux controllers (source + helm)"
flux install --components=source-controller,helm-controller

log "Packaging chart in versions ${VERSION_A} and ${VERSION_B}"
helm package "$REPO_ROOT/deploy/helm/guided-ssh" --version "$VERSION_A" -d "$WORKDIR/repo" >/dev/null
helm package "$REPO_ROOT/deploy/helm/guided-ssh" --version "$VERSION_B" -d "$WORKDIR/repo" >/dev/null
helm repo index "$WORKDIR/repo"

log "Rolling out local Helm repo in-cluster (nginx + ConfigMap)"
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

log "Creating namespace, PostgreSQL, and required secret"
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
# Postgres access as individual keys + CA master key in the same secret
# (secrets.db and secrets.ca both point at it).
kubectl -n guided-ssh create secret generic guided-ssh \
  --from-literal=host=postgres \
  --from-literal=port=5432 \
  --from-literal=username=gssh \
  --from-literal=password=gssh \
  --from-literal=database=gssh \
  --from-literal=sslmode=disable \
  --from-literal=ca-master-key="$(openssl rand -base64 32)"
kubectl -n guided-ssh rollout status deploy/postgres --timeout=120s

log "Creating HelmRepository + HelmRelease (version ${VERSION_A})"
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
      db:
        existingSecret: guided-ssh
      ca:
        existingSecret: guided-ssh
EOF

log "Waiting for release ${VERSION_A}"
kubectl -n guided-ssh wait helmrelease/guided-ssh \
  --for=condition=Ready --timeout=5m
kubectl -n guided-ssh rollout status deploy/guided-ssh --timeout=180s

# HelmRelease v2: history[0] is the most recently rolled-out release snapshot.
applied="$(kubectl -n guided-ssh get helmrelease guided-ssh \
  -o jsonpath='{.status.history[0].chartVersion}')"
[ "$applied" = "$VERSION_A" ] || { echo "ERROR: rolled-out chart version=$applied, expected $VERSION_A" >&2; exit 1; }

pod="$(kubectl -n guided-ssh get pod -l app.kubernetes.io/name=guided-ssh \
  --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[-1:].metadata.name}')"
kubectl -n guided-ssh logs "$pod" -c migrate | tail -3
echo "OK: release ${VERSION_A} ready, migrations ran"

log "Bumping chart version to ${VERSION_B} (simulated Git commit)"
kubectl -n guided-ssh patch helmrelease guided-ssh --type=merge \
  -p "{\"spec\":{\"chart\":{\"spec\":{\"version\":\"${VERSION_B}\"}}}}"

log "Waiting for upgrade to ${VERSION_B}"
# Ready first goes False briefly (upgrade in progress), then back to True with the new revision.
for _ in $(seq 60); do
  applied="$(kubectl -n guided-ssh get helmrelease guided-ssh \
    -o jsonpath='{.status.history[0].chartVersion}')"
  [ "$applied" = "$VERSION_B" ] && break
  sleep 5
done
[ "$applied" = "$VERSION_B" ] || { echo "ERROR: upgrade to $VERSION_B did not land (rolled out: $applied)" >&2; exit 1; }
kubectl -n guided-ssh wait helmrelease/guided-ssh \
  --for=condition=Ready --timeout=5m
kubectl -n guided-ssh rollout status deploy/guided-ssh --timeout=180s

# Migrations ran again on upgrade (new pod, migrate init container exits 0;
# goose reports "no migrations to run").
pod="$(kubectl -n guided-ssh get pod -l app.kubernetes.io/name=guided-ssh \
  --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[-1:].metadata.name}')"
exit_code="$(kubectl -n guided-ssh get pod "$pod" \
  -o jsonpath='{.status.initContainerStatuses[?(@.name=="migrate")].state.terminated.exitCode}')"
[ "$exit_code" = "0" ] || { echo "ERROR: migrate init container exit code $exit_code" >&2; exit 1; }
kubectl -n guided-ssh logs "$pod" -c migrate | tail -3

log "PASS: chart bump ${VERSION_A} -> ${VERSION_B} via Flux, migrations automatic"
