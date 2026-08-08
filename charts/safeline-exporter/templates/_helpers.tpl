{{/* Expand the chart name. */}}
{{- define "safeline-exporter.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Create a release-scoped resource name. */}}
{{- define "safeline-exporter.fullname" -}}
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

{{/* Chart name and version for labels. */}}
{{- define "safeline-exporter.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Common labels. */}}
{{- define "safeline-exporter.labels" -}}
helm.sh/chart: {{ include "safeline-exporter.chart" . }}
{{ include "safeline-exporter.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/* Immutable selector labels. */}}
{{- define "safeline-exporter.selectorLabels" -}}
app.kubernetes.io/name: {{ include "safeline-exporter.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/* Resolve the Secret used by the Deployment. */}}
{{- define "safeline-exporter.secretName" -}}
{{- if .Values.secret.create -}}
{{- include "safeline-exporter.fullname" . -}}
{{- else -}}
{{- .Values.existingSecret -}}
{{- end -}}
{{- end }}
