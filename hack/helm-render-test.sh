#!/usr/bin/env bash
# Golden checks for `helm template` of the guided-ssh chart: renders the chart
# with a handful of value combinations and asserts the resulting Deployment
# (env, volumes, mounts) plus the render guards. Complements `ct lint`, which
# only checks that the chart renders at all.
#
# Currently covered: the rules provisioning (GITOPS_EXTERNAL_RULES, D8).
# Prerequisite: helm. No cluster needed.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CHART="$REPO_ROOT/deploy/helm/guided-ssh"
RELEASE="gssh"
# Minimum for a renderable chart (test database ⇒ no DB secret needed).
BASE=(--set secrets.ca.existingSecret=gssh-ca --set internalDatabase.enabled=true)

failures=0
out=""

# The postgresql dependency is not committed (charts/ is a build artifact),
# but helm refuses to render without it — fetch it on a fresh checkout.
if [ ! -d "$CHART/charts" ]; then
  helm dependency build "$CHART" >/dev/null
fi

# render <case> [--set ...]: template the Deployment (only it carries env and
# volumes; other templates would produce accidental grep matches), abort the
# case on error.
render() {
  local name="$1"
  shift
  if ! out="$(helm template "$RELEASE" "$CHART" -s templates/deployment.yaml "${BASE[@]}" "$@" 2>&1)"; then
    printf 'FAIL %s: helm template failed\n%s\n' "$name" "$out" >&2
    failures=$((failures + 1))
    return 1
  fi
}

# has/hasnt <case> <pattern>: fixed-string assertion on the last render.
has() {
  if ! grep -qF -- "$2" <<<"$out"; then
    printf 'FAIL %s: missing %q\n' "$1" "$2" >&2
    failures=$((failures + 1))
  fi
}
hasnt() {
  if grep -qF -- "$2" <<<"$out"; then
    printf 'FAIL %s: unexpected %q\n' "$1" "$2" >&2
    failures=$((failures + 1))
  fi
}

# fails <case> <substring> [--set ...]: render MUST fail with that message.
fails() {
  local name="$1" want="$2"
  shift 2
  if out="$(helm template "$RELEASE" "$CHART" "${BASE[@]}" "$@" 2>&1)"; then
    printf 'FAIL %s: render succeeded but must fail\n' "$name" >&2
    failures=$((failures + 1))
    return
  fi
  if ! grep -qF -- "$want" <<<"$out"; then
    printf 'FAIL %s: error message without %q:\n%s\n' "$name" "$want" "$out" >&2
    failures=$((failures + 1))
  fi
}

case_name="rules: defaults (no manual editing, no file source)"
if render "$case_name"; then
  hasnt "$case_name" "GSSH_MANUAL_RULES"
  hasnt "$case_name" "GSSH_HOST_RULES_FILE"
  hasnt "$case_name" "GSSH_CI_RULES_FILE"
  hasnt "$case_name" "name: host-rules"
  hasnt "$case_name" "name: ci-rules"
fi

case_name="rules: manualProvision=true"
if render "$case_name" --set config.rules.manualProvision=true; then
  has "$case_name" "name: GSSH_MANUAL_RULES"
  hasnt "$case_name" "GSSH_HOST_RULES_FILE"
  hasnt "$case_name" "name: host-rules"
fi

case_name="rules: host ConfigMap only"
if render "$case_name" --set config.rules.host.existingConfigMap=gssh-host-rules; then
  has "$case_name" "name: GSSH_HOST_RULES_FILE"
  has "$case_name" 'value: "/etc/guided-ssh/rules/host/rules.yaml"'
  has "$case_name" "name: host-rules"
  has "$case_name" "name: gssh-host-rules"
  has "$case_name" "key: host-rules.yaml"
  has "$case_name" "path: rules.yaml"
  has "$case_name" "mountPath: /etc/guided-ssh/rules/host"
  # subPath would freeze the rules at pod start (D8).
  hasnt "$case_name" "subPath:"
  hasnt "$case_name" "GSSH_CI_RULES_FILE"
  hasnt "$case_name" "name: ci-rules"
fi

case_name="rules: both ConfigMaps"
if render "$case_name" \
  --set config.rules.host.existingConfigMap=gssh-host-rules \
  --set config.rules.ci.existingConfigMap=gssh-ci-rules; then
  has "$case_name" "name: GSSH_HOST_RULES_FILE"
  has "$case_name" "name: GSSH_CI_RULES_FILE"
  has "$case_name" 'value: "/etc/guided-ssh/rules/ci/rules.yaml"'
  has "$case_name" "name: ci-rules"
  has "$case_name" "key: ci-rules.yaml"
  has "$case_name" "mountPath: /etc/guided-ssh/rules/ci"
  hasnt "$case_name" "GSSH_MANUAL_RULES"
fi

case_name="rules: custom ConfigMap key"
if render "$case_name" \
  --set config.rules.host.existingConfigMap=gssh-host-rules \
  --set config.rules.host.key=grants.yml; then
  has "$case_name" "key: grants.yml"
  # The env path stays the projected file name, not the key.
  has "$case_name" 'value: "/etc/guided-ssh/rules/host/rules.yaml"'
fi

fails "rules: manualProvision + host ConfigMap" "mutually exclusive" \
  --set config.rules.manualProvision=true \
  --set config.rules.host.existingConfigMap=gssh-host-rules

fails "rules: manualProvision + ci ConfigMap" "mutually exclusive" \
  --set config.rules.manualProvision=true \
  --set config.rules.ci.existingConfigMap=gssh-ci-rules

fails "rules: ConfigMap without key" "config.rules.host.key must name the key" \
  --set config.rules.host.existingConfigMap=gssh-host-rules \
  --set config.rules.host.key=""

if [ "$failures" -eq 0 ]; then
  echo "helm render checks passed"
else
  echo "$failures helm render check(s) failed" >&2
  exit 1
fi
