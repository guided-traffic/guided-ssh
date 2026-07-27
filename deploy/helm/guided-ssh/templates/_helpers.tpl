{{/* Chart name */}}
{{- define "guided-ssh.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Full name (release + chart) */}}
{{- define "guided-ssh.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/* Chart label */}}
{{- define "guided-ssh.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Common labels */}}
{{- define "guided-ssh.labels" -}}
helm.sh/chart: {{ include "guided-ssh.chart" . }}
{{ include "guided-ssh.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/* Selector labels */}}
{{- define "guided-ssh.selectorLabels" -}}
app.kubernetes.io/name: {{ include "guided-ssh.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/* ServiceAccount name */}}
{{- define "guided-ssh.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "guided-ssh.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/* Image reference */}}
{{- define "guided-ssh.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}

{{/* SANs of the agent mTLS certificate (default: cluster-internal service name) */}}
{{- define "guided-ssh.agentTLSNames" -}}
{{- if .Values.agent.tlsNames }}
{{- .Values.agent.tlsNames }}
{{- else }}
{{- printf "%s-agent.%s.svc,%s-agent.%s.svc.cluster.local" (include "guided-ssh.fullname" .) .Release.Namespace (include "guided-ssh.fullname" .) .Release.Namespace }}
{{- end }}
{{- end }}

{{/* CA mode (managed|self-managed) incl. validation. A render error is
friendlier than a CrashLoop: the server rejects a half-configured
self-managed setup on start. */}}
{{- define "guided-ssh.caMode" -}}
{{- $mode := default "managed" .Values.secrets.ca.mode -}}
{{- if not (has $mode (list "managed" "self-managed")) -}}
{{- fail (printf "secrets.ca.mode must be \"managed\" or \"self-managed\" (got: %q)" $mode) -}}
{{- end -}}
{{- if and (eq $mode "self-managed") (not .Values.secrets.ca.selfManaged.existingSecret) -}}
{{- fail "secrets.ca.mode=self-managed requires secrets.ca.selfManaged.existingSecret (a Secret with the four CA files user-ca/host-ca/mtls-ca.key/mtls-ca.crt, see README)" -}}
{{- end -}}
{{- $mode -}}
{{- end }}

{{/* Path of a CA file below the mount directory (key name = file name) */}}
{{- define "guided-ssh.caFile" -}}
{{- printf "%s/%s" (trimSuffix "/" .mountPath) .key -}}
{{- end }}

{{/* Only set the env entry when the value is not empty */}}
{{- define "guided-ssh.env" -}}
{{- if .value }}
- name: {{ .name }}
  value: {{ .value | quote }}
{{- end }}
{{- end }}

{{/* Fail fast on values keys removed by the server/client OIDC split, so an
upgrade with stale values stops at render time with a migration hint instead
of silently dropping auth configuration. hasKey (not truthiness) also catches
keys left behind with empty values; the parent maps are checked via `with`
because a user can null them. */}}
{{- define "guided-ssh.validateValues" -}}
{{- $legacy := list -}}
{{- with .Values.config -}}
{{- with .oidc -}}
{{- if hasKey . "clientID" }}{{- $legacy = append $legacy "config.oidc.clientID (now config.oidc.client.clientID)" }}{{- end -}}
{{- if hasKey . "uiClientID" }}{{- $legacy = append $legacy "config.oidc.uiClientID (now config.oidc.server.clientID)" }}{{- end -}}
{{- if hasKey . "uiExistingSecret" }}{{- $legacy = append $legacy "config.oidc.uiExistingSecret (now config.oidc.server.existingSecret)" }}{{- end -}}
{{- if hasKey . "uiExistingSecretKey" }}{{- $legacy = append $legacy "config.oidc.uiExistingSecretKey (now config.oidc.server.existingSecretKey)" }}{{- end -}}
{{- if hasKey . "uiBaseURL" }}{{- $legacy = append $legacy "config.oidc.uiBaseURL (now config.publicURL)" }}{{- end -}}
{{- end -}}
{{- end -}}
{{- with .Values.hostRollout -}}
{{- if hasKey . "publicUrl" }}{{- $legacy = append $legacy "hostRollout.publicUrl (now config.publicURL)" }}{{- end -}}
{{- end -}}
{{- if $legacy -}}
{{- fail (printf "the server/client oidc split moved these values — set: %s (migration notes in the chart README)" (join ", " $legacy)) -}}
{{- end -}}
{{- end }}

{{/* Mount path of the public TLS certificate when hostRollout.pin.source=file.
Only tls.crt is projected from the secret (the server doesn't need the
key) and deliberately mounted without subPath — only then does the kubelet
pick up a secret rotation in the running pod. */}}
{{- define "guided-ssh.publicPinDir" -}}/etc/gssh/public-tls{{- end }}
{{- define "guided-ssh.publicPinFile" -}}{{ include "guided-ssh.publicPinDir" . }}/tls.crt{{- end }}

{{/* Host rollout envs (only when hostRollout.enabled). The required values are
checked here: a misconfiguration fails at render time, not only out on the
fleet. The server-side gate remains authoritative (it covers non-Helm
deployments and drift) — this block only controls which envs get set. */}}
{{- define "guided-ssh.hostRolloutEnv" -}}
{{- $rollout := .Values.hostRollout -}}
{{- $source := default "dial" $rollout.pin.source -}}
{{- if not (has $source (list "dial" "file" "static")) -}}
{{- fail (printf "hostRollout.pin.source must be \"dial\", \"file\" or \"static\" (got: %q)" $source) -}}
{{- end -}}
{{/* http is also rejected by the server-side gate (public_url_https/agent_public_url_https) —
here it already fails at render time instead of only out on the fleet. */}}
{{- if and $rollout.agentPublicUrl (not (hasPrefix "https://" $rollout.agentPublicUrl)) -}}
{{- fail (printf "hostRollout.agentPublicUrl must be an https URL (got: %q)" $rollout.agentPublicUrl) -}}
{{- end -}}
{{- if not .Values.config.publicURL -}}
{{- fail "hostRollout.enabled=true requires config.publicURL (external public URL for install_command and pin dial)" -}}
{{- end -}}
{{- if not (hasPrefix "https://" .Values.config.publicURL) -}}
{{- fail (printf "hostRollout needs an https public URL — config.publicURL is %q" .Values.config.publicURL) -}}
{{- end -}}
- name: GSSH_AGENT_PUBLIC_URL
  value: {{ required "hostRollout.enabled=true requires hostRollout.agentPublicUrl (external mTLS agent URL of the agents, e.g. https://gssh-agent.example.com:8443 — deliberately never derived)" $rollout.agentPublicUrl | quote }}
{{- if eq $source "static" }}
- name: GSSH_PUBLIC_PIN
  value: {{ required "hostRollout.pin.source=static requires hostRollout.pin.static (base64 SPKI pin, openssl snippet in the README)" $rollout.pin.static | quote }}
{{- else if eq $source "file" }}
{{- $_ := required "hostRollout.pin.source=file requires hostRollout.pin.certSecretName (TLS secret of the ingress in the server namespace)" $rollout.pin.certSecretName }}
- name: GSSH_PUBLIC_PIN_CERT_FILE
  value: {{ include "guided-ssh.publicPinFile" . | quote }}
{{- else }}
{{- include "guided-ssh.env" (dict "name" "GSSH_PUBLIC_PIN_REFRESH" "value" $rollout.pin.refreshInterval) }}
{{- end }}
- name: GSSH_AGENT_DOWNLOAD_RPM
  value: {{ $rollout.downloadRpm | toString | quote }}
{{- end }}

{{/* Fixed dev credentials of the internal test database (sidecar, reachable
only on 127.0.0.1 within the pod — deliberately not a secret). */}}
{{- define "guided-ssh.internalDBUser" -}}gssh{{- end }}
{{- define "guided-ssh.internalDBPassword" -}}gssh-internal{{- end }}
{{- define "guided-ssh.internalDBName" -}}gssh{{- end }}

{{/* GSSH_DB_* env — for the server and the migrations init container.
Normal case: values from the DB secret (secrets.db), key names freely
assignable via secrets.db.keys (e.g. CloudNativePG app secret); port/sslmode
are optional: if the key is missing from the secret, the server defaults
apply (5432 resp. prefer). With internalDatabase.enabled the connection
points to the Postgres sidecar instead — a DB secret set at the same time is
a render error (protection against accidentally using the test database). */}}
{{- define "guided-ssh.dbEnv" -}}
{{- if .Values.internalDatabase.enabled -}}
{{- if .Values.secrets.db.existingSecret -}}
{{- fail "internalDatabase.enabled and secrets.db.existingSecret are mutually exclusive — the internal database is ONLY for test environments; leave internalDatabase.enabled=false for everything else" -}}
{{- end -}}
{{- if or (gt (int .Values.replicaCount) 1) .Values.autoscaling.enabled -}}
{{- fail "internalDatabase requires replicaCount=1 without autoscaling — every replica would get its own, empty database" -}}
{{- end -}}
- name: GSSH_DB_HOST
  value: "127.0.0.1"
- name: GSSH_DB_PORT
  value: "5432"
- name: GSSH_DB_USER
  value: {{ include "guided-ssh.internalDBUser" . }}
- name: GSSH_DB_PASSWORD
  value: {{ include "guided-ssh.internalDBPassword" . }}
- name: GSSH_DB_NAME
  value: {{ include "guided-ssh.internalDBName" . }}
- name: GSSH_DB_SSLMODE
  value: disable
{{- else -}}
{{- $secret := required "secrets.db.existingSecret is required (a Secret with the Postgres connection data, see README) — for test environments without their own database: internalDatabase.enabled=true" .Values.secrets.db.existingSecret -}}
{{- $keys := .Values.secrets.db.keys -}}
- name: GSSH_DB_HOST
  valueFrom:
    secretKeyRef:
      name: {{ $secret }}
      key: {{ $keys.host }}
- name: GSSH_DB_PORT
  valueFrom:
    secretKeyRef:
      name: {{ $secret }}
      key: {{ $keys.port }}
      optional: true
- name: GSSH_DB_USER
  valueFrom:
    secretKeyRef:
      name: {{ $secret }}
      key: {{ $keys.username }}
- name: GSSH_DB_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ $secret }}
      key: {{ $keys.password }}
- name: GSSH_DB_NAME
  valueFrom:
    secretKeyRef:
      name: {{ $secret }}
      key: {{ $keys.database }}
- name: GSSH_DB_SSLMODE
  valueFrom:
    secretKeyRef:
      name: {{ $secret }}
      key: {{ $keys.sslmode }}
      optional: true
{{- end -}}
{{- end }}
