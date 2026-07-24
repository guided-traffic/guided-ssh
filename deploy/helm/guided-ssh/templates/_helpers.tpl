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

{{/* Env-Eintrag nur setzen, wenn der Wert nicht leer ist */}}
{{- define "guided-ssh.env" -}}
{{- if .value }}
- name: {{ .name }}
  value: {{ .value | quote }}
{{- end }}
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
