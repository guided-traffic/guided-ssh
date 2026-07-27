#!/usr/bin/env bash
# Golden checks for `helm template` of the guided-ssh chart: renders the chart
# with a handful of value combinations and asserts the resulting Deployment
# (env, volumes, mounts) plus the render guards. Complements `ct lint`, which
# only checks that the chart renders at all.
#
# Currently covered: the rules provisioning (GITOPS_EXTERNAL_RULES, D8) and
# the agent passthrough ingress incl. its derivations (AGENT_INGRESS, WP1/WP2).
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

# render_tpl <template> <case> [--set ...]: template a single file (an empty
# template renders the whole chart — for "this template stays empty" checks),
# abort the case on error.
render_tpl() {
  local tpl="$1" name="$2"
  shift 2
  local sel=()
  [ -n "$tpl" ] && sel=(-s "$tpl")
  if ! out="$(helm template "$RELEASE" "$CHART" ${sel[@]+"${sel[@]}"} "${BASE[@]}" "$@" 2>&1)"; then
    printf 'FAIL %s: helm template failed\n%s\n' "$name" "$out" >&2
    failures=$((failures + 1))
    return 1
  fi
}

# render <case> [--set ...]: template the Deployment (only it carries env and
# volumes; other templates would produce accidental grep matches), abort the
# case on error.
render() {
  render_tpl templates/deployment.yaml "$@"
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

# --- agent passthrough ingress (AGENT_INGRESS WP1/WP2) ---------------------
AGENT_HOST="gssh-agent.example.com"
# --set-string keeps the annotation value a string: an unquoted YAML bool is
# not what the controllers match on.
INGRESS=(
  --set agent.ingress.enabled=true
  --set-string "agent.ingress.host=$AGENT_HOST"
  --set agent.ingress.className=haproxy
  --set-string 'agent.ingress.annotations.haproxy-ingress\.github\.io/ssl-passthrough=true'
)
# hostRollout needs an https public URL of its own before it renders any env.
ROLLOUT=(--set hostRollout.enabled=true --set config.publicURL=https://gssh.example.com)

case_name="agent ingress: disabled by default"
if render_tpl "" "$case_name"; then
  hasnt "$case_name" "# Source: guided-ssh/templates/ingress-agent.yaml"
fi

case_name="agent ingress: enabled"
if render_tpl templates/ingress-agent.yaml "$case_name" "${INGRESS[@]}"; then
  has "$case_name" "name: gssh-guided-ssh-agent"
  has "$case_name" "ingressClassName: haproxy"
  has "$case_name" 'haproxy-ingress.github.io/ssl-passthrough: "true"'
  has "$case_name" "host: \"$AGENT_HOST\""
  has "$case_name" "path: /"
  has "$case_name" "pathType: Prefix"
  has "$case_name" "name: agent"
  # A tls: block would make the controller terminate — the whole point of
  # passthrough is that it does not (D2).
  hasnt "$case_name" "tls:"
  hasnt "$case_name" "secretName"
fi

case_name="agent ingress: derives SANs and agent public URL"
if render "$case_name" "${INGRESS[@]}" "${ROLLOUT[@]}"; then
  has "$case_name" "gssh-guided-ssh-agent.default.svc.cluster.local,$AGENT_HOST"
  has "$case_name" "value: \"https://$AGENT_HOST\""
fi

case_name="agent ingress: explicit values win over derivation"
if render "$case_name" "${INGRESS[@]}" "${ROLLOUT[@]}" \
  --set-string agent.tlsNames=agents.example.com \
  --set hostRollout.agentPublicUrl=https://lb.example.com:8443; then
  has "$case_name" 'value: "agents.example.com"'
  has "$case_name" 'value: "https://lb.example.com:8443"'
  hasnt "$case_name" "https://$AGENT_HOST"
fi

case_name="agent ingress: disabled ingress does not leak its host"
if render "$case_name" --set-string "agent.ingress.host=$AGENT_HOST"; then
  has "$case_name" 'value: "gssh-guided-ssh-agent.default.svc,gssh-guided-ssh-agent.default.svc.cluster.local"'
  hasnt "$case_name" "$AGENT_HOST"
fi

fails "agent ingress: hostRollout without any agent URL source" \
  "or enable agent.ingress with a host" "${ROLLOUT[@]}"

fails "agent ingress: enabled without host" \
  "requires agent.ingress.host" --set agent.ingress.enabled=true

for bad in "https://$AGENT_HOST" "$AGENT_HOST:8443" "$AGENT_HOST/agent" \
  "*.example.com" "GSSH-Agent.example.com"; do
  fails "agent ingress: malformed host $bad" "must be a bare lowercase DNS name" \
    --set agent.ingress.enabled=true --set-string "agent.ingress.host=$bad"
done

fails "agent ingress: enabled with agent.enabled=false" \
  "requires agent.enabled=true" \
  "${INGRESS[@]}" --set agent.enabled=false

fails "agent ingress: enabled with agent.service.enabled=false" \
  "requires agent.service.enabled=true" \
  "${INGRESS[@]}" --set agent.service.enabled=false

if [ "$failures" -eq 0 ]; then
  echo "helm render checks passed"
else
  echo "$failures helm render check(s) failed" >&2
  exit 1
fi
