{{/*
Expand the name of the chart.
*/}}
{{- define "ferriscd.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}
{{- define "ferriscd.fullname" -}}
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

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "ferriscd.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "ferriscd.labels" -}}
helm.sh/chart: {{ include "ferriscd.chart" . }}
{{ include "ferriscd.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels for the control-plane server/controller pods.
*/}}
{{- define "ferriscd.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ferriscd.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: server
{{- end }}

{{/*
Common labels for the Web Dashboard.
*/}}
{{- define "ferriscd.webLabels" -}}
helm.sh/chart: {{ include "ferriscd.chart" . }}
{{ include "ferriscd.webSelectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels for the Web Dashboard pods.
*/}}
{{- define "ferriscd.webSelectorLabels" -}}
app.kubernetes.io/name: {{ include "ferriscd.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: web
{{- end }}

{{/*
Create the name of the service account to use.
*/}}
{{- define "ferriscd.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "ferriscd.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Whether leader election must be enabled on `ferriscd server`.
Automatically enabled when replicaCount > 1 or sharding is enabled.
*/}}
{{- define "ferriscd.leaderElectionEnabled" -}}
{{- if or .Values.leaderElection.enabled (gt (int .Values.replicaCount) 1) .Values.sharding.enabled -}}
true
{{- end -}}
{{- end }}

{{/*
Whether PodDisruptionBudget should be rendered.
Automatically enabled when replicaCount > 1 unless explicitly disabled.
*/}}
{{- define "ferriscd.pdbEnabled" -}}
{{- if kindIs "invalid" .Values.podDisruptionBudget.enabled -}}
{{- if gt (int .Values.replicaCount) 1 -}}true{{- end -}}
{{- else if .Values.podDisruptionBudget.enabled -}}
true
{{- end -}}
{{- end }}

{{/*
Validate cross-field chart invariants at template render time.
*/}}
{{- define "ferriscd.validateValues" -}}
{{- if eq (int .Values.server.apiPort) (int .Values.server.metricsPort) -}}
{{- fail "server.metricsPort must differ from server.apiPort: /metrics is always served on a dedicated listener" -}}
{{- end -}}
{{- if include "ferriscd.leaderElectionEnabled" . -}}
{{- $dur := int .Values.leaderElection.leaseDurationSeconds -}}
{{- $renew := int .Values.leaderElection.renewIntervalSeconds -}}
{{- if le $dur (mul 3 $renew) -}}
{{- fail (printf "leaderElection.leaseDurationSeconds (%d) must be strictly greater than 3 * leaderElection.renewIntervalSeconds (%d)" $dur $renew) -}}
{{- end -}}
{{- end -}}
{{- if .Values.sharding.enabled -}}
{{- if or (kindIs "invalid" .Values.sharding.shardId) (kindIs "invalid" .Values.sharding.totalShards) -}}
{{- fail "sharding.enabled=true requires both sharding.shardId and sharding.totalShards" -}}
{{- end -}}
{{- $sid := int .Values.sharding.shardId -}}
{{- $total := int .Values.sharding.totalShards -}}
{{- if or (lt $total 1) (lt $sid 0) (ge $sid $total) -}}
{{- fail (printf "sharding requires 0 <= shardId (%d) < totalShards (%d)" $sid $total) -}}
{{- end -}}
{{- if .Values.leaderElection.leaseName -}}
{{- fail "leaderElection.leaseName cannot be set when sharding.enabled=true (each shard uses ferriscd-leader-shard-<id>)" -}}
{{- end -}}
{{- end -}}
{{- end }}
