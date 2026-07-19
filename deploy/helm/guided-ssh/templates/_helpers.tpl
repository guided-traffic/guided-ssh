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
