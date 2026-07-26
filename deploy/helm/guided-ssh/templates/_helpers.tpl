{{/* Chart-Name */}}
{{- define "guided-ssh.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Vollständiger Name (Release + Chart) */}}
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

{{/* Chart-Label */}}
{{- define "guided-ssh.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Gemeinsame Labels */}}
{{- define "guided-ssh.labels" -}}
helm.sh/chart: {{ include "guided-ssh.chart" . }}
{{ include "guided-ssh.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/* Selector-Labels */}}
{{- define "guided-ssh.selectorLabels" -}}
app.kubernetes.io/name: {{ include "guided-ssh.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/* ServiceAccount-Name */}}
{{- define "guided-ssh.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "guided-ssh.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/* Image-Referenz */}}
{{- define "guided-ssh.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}

{{/* SANs des Agent-mTLS-Zertifikats (Default: Cluster-interner Service-Name) */}}
{{- define "guided-ssh.agentTLSNames" -}}
{{- if .Values.agent.tlsNames }}
{{- .Values.agent.tlsNames }}
{{- else }}
{{- printf "%s-agent.%s.svc,%s-agent.%s.svc.cluster.local" (include "guided-ssh.fullname" .) .Release.Namespace (include "guided-ssh.fullname" .) .Release.Namespace }}
{{- end }}
{{- end }}

{{/* CA-Modus (managed|self-managed) inkl. Validierung. Ein Render-Fehler ist
freundlicher als ein CrashLoop: der Server lehnt eine halb konfigurierte
Selbstverwaltung beim Start ab. */}}
{{- define "guided-ssh.caMode" -}}
{{- $mode := default "managed" .Values.secrets.ca.mode -}}
{{- if not (has $mode (list "managed" "self-managed")) -}}
{{- fail (printf "secrets.ca.mode muss \"managed\" oder \"self-managed\" sein (ist: %q)" $mode) -}}
{{- end -}}
{{- if and (eq $mode "self-managed") (not .Values.secrets.ca.selfManaged.existingSecret) -}}
{{- fail "secrets.ca.mode=self-managed erfordert secrets.ca.selfManaged.existingSecret (Secret mit den vier CA-Dateien user-ca/host-ca/mtls-ca.key/mtls-ca.crt, siehe README)" -}}
{{- end -}}
{{- $mode -}}
{{- end }}

{{/* Pfad einer CA-Datei unterhalb des Mount-Verzeichnisses (Key-Name = Dateiname) */}}
{{- define "guided-ssh.caFile" -}}
{{- printf "%s/%s" (trimSuffix "/" .mountPath) .key -}}
{{- end }}

{{/* Env-Eintrag nur setzen, wenn der Wert nicht leer ist */}}
{{- define "guided-ssh.env" -}}
{{- if .value }}
- name: {{ .name }}
  value: {{ .value | quote }}
{{- end }}
{{- end }}

{{/* Mount-Pfad des öffentlichen TLS-Zertifikats bei hostRollout.pin.source=file.
Aus dem Secret wird ausschließlich tls.crt projiziert (der Server braucht den
Key nicht) und bewusst ohne subPath gemountet — nur dann zieht das Kubelet eine
Secret-Rotation im laufenden Pod nach. */}}
{{- define "guided-ssh.publicPinDir" -}}/etc/gssh/public-tls{{- end }}
{{- define "guided-ssh.publicPinFile" -}}{{ include "guided-ssh.publicPinDir" . }}/tls.crt{{- end }}

{{/* Host-Rollout-Envs (nur bei hostRollout.enabled). Die Pflicht-Werte werden
hier geprüft: Misconfig scheitert beim Rendern, nicht erst auf der Flotte. Das
Server-Gate bleibt autoritativ (es deckt Nicht-Helm-Deployments und Drift ab) —
dieser Block steuert nur, welche Envs gesetzt werden. */}}
{{- define "guided-ssh.hostRolloutEnv" -}}
{{- $rollout := .Values.hostRollout -}}
{{- $source := default "dial" $rollout.pin.source -}}
{{- if not (has $source (list "dial" "file" "static")) -}}
{{- fail (printf "hostRollout.pin.source muss \"dial\", \"file\" oder \"static\" sein (ist: %q)" $source) -}}
{{- end -}}
{{/* http lehnt auch das Server-Gate ab (public_url_https/agent_public_url_https) —
hier scheitert es schon beim Rendern statt erst auf der Flotte. */}}
{{- if and $rollout.agentPublicUrl (not (hasPrefix "https://" $rollout.agentPublicUrl)) -}}
{{- fail (printf "hostRollout.agentPublicUrl muss ein https-URL sein (ist: %q)" $rollout.agentPublicUrl) -}}
{{- end -}}
{{- $publicURL := default .Values.config.oidc.uiBaseURL $rollout.publicUrl -}}
{{- if and $publicURL (not (hasPrefix "https://" $publicURL)) -}}
{{- fail (printf "hostRollout braucht eine https-Public-URL — hostRollout.publicUrl bzw. config.oidc.uiBaseURL ist %q" $publicURL) -}}
{{- end -}}
- name: GSSH_AGENT_PUBLIC_URL
  value: {{ required "hostRollout.enabled=true erfordert hostRollout.agentPublicUrl (externe mTLS-Agent-URL der Agenten, z. B. https://gssh-agent.example.com:8443 — wird bewusst nie abgeleitet)" $rollout.agentPublicUrl | quote }}
{{- if $rollout.publicUrl }}
- name: GSSH_PUBLIC_URL
  value: {{ $rollout.publicUrl | quote }}
{{- else if not .Values.config.oidc.uiBaseURL }}
{{- fail "hostRollout.enabled=true erfordert hostRollout.publicUrl oder config.oidc.uiBaseURL (externe Public-URL für install_command und Pin-Dial)" -}}
{{- end }}
{{- if eq $source "static" }}
- name: GSSH_PUBLIC_PIN
  value: {{ required "hostRollout.pin.source=static erfordert hostRollout.pin.static (Base64-SPKI-Pin, openssl-Snippet im README)" $rollout.pin.static | quote }}
{{- else if eq $source "file" }}
{{- $_ := required "hostRollout.pin.source=file erfordert hostRollout.pin.certSecretName (TLS-Secret des Ingress im Server-Namespace)" $rollout.pin.certSecretName }}
- name: GSSH_PUBLIC_PIN_CERT_FILE
  value: {{ include "guided-ssh.publicPinFile" . | quote }}
{{- else }}
{{- include "guided-ssh.env" (dict "name" "GSSH_PUBLIC_PIN_REFRESH" "value" $rollout.pin.refreshInterval) }}
{{- end }}
- name: GSSH_AGENT_DOWNLOAD_RPM
  value: {{ $rollout.downloadRpm | toString | quote }}
{{- end }}

{{/* Feste Dev-Credentials der internen Test-Datenbank (Sidecar, nur 127.0.0.1
im Pod erreichbar — bewusst kein Secret). */}}
{{- define "guided-ssh.internalDBUser" -}}gssh{{- end }}
{{- define "guided-ssh.internalDBPassword" -}}gssh-internal{{- end }}
{{- define "guided-ssh.internalDBName" -}}gssh{{- end }}

{{/* GSSH_DB_*-Env — für Server und Migrations-Init-Container.
Normalfall: Werte aus dem DB-Secret (secrets.db), Key-Namen über
secrets.db.keys frei belegbar (z. B. CloudNativePG-App-Secret); port/sslmode
sind optional: fehlt der Key im Secret, greifen die Server-Defaults (5432
bzw. prefer). Mit internalDatabase.enabled zeigt die Verbindung stattdessen
auf den Postgres-Sidecar — ein gleichzeitig gesetztes DB-Secret ist ein
Render-Fehler (Schutz vor versehentlicher Test-Datenbank). */}}
{{- define "guided-ssh.dbEnv" -}}
{{- if .Values.internalDatabase.enabled -}}
{{- if .Values.secrets.db.existingSecret -}}
{{- fail "internalDatabase.enabled und secrets.db.existingSecret schließen sich gegenseitig aus — die interne Datenbank ist NUR für Test-Umgebungen; für alles andere internalDatabase.enabled=false lassen" -}}
{{- end -}}
{{- if or (gt (int .Values.replicaCount) 1) .Values.autoscaling.enabled -}}
{{- fail "internalDatabase erfordert replicaCount=1 ohne Autoscaling — jede Replika hätte ihre eigene, leere Datenbank" -}}
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
{{- $secret := required "secrets.db.existingSecret ist Pflicht (Secret mit den Postgres-Verbindungsdaten, siehe README) — für Test-Umgebungen ohne eigene Datenbank: internalDatabase.enabled=true" .Values.secrets.db.existingSecret -}}
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
