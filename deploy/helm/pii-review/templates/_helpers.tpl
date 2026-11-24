{{/* Chart name, at most 63 characters. */}}
{{- define "pii-review.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Release-qualified name; component names add a suffix, so keep room. */}}
{{- define "pii-review.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 50 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 50 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 50 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/* Name of one component: (dict "root" $ "component" "web"). */}}
{{- define "pii-review.componentName" -}}
{{- printf "%s-%s" (include "pii-review.fullname" .root) .component }}
{{- end }}

{{- define "pii-review.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Labels every object of the release carries. */}}
{{- define "pii-review.selectorLabels" -}}
app.kubernetes.io/name: {{ include "pii-review.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "pii-review.labels" -}}
helm.sh/chart: {{ include "pii-review.chart" . }}
{{ include "pii-review.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: pii-review
{{- end }}

{{/* Labels of one component: (dict "root" $ "component" "web"). */}}
{{- define "pii-review.componentSelectorLabels" -}}
{{ include "pii-review.selectorLabels" .root }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{- define "pii-review.componentLabels" -}}
{{ include "pii-review.labels" .root }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{- define "pii-review.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "pii-review.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Image reference: (dict "image" .Values.web.image "root" $).
registry/repository:tag@digest; the registry falls back to
global.imageRegistry, the digest pins the image when set.
*/}}
{{- define "pii-review.image" -}}
{{- $registry := .image.registry | default .root.Values.global.imageRegistry -}}
{{- $ref := .image.repository -}}
{{- if $registry }}{{ $ref = printf "%s/%s" (trimSuffix "/" $registry) $ref }}{{ end -}}
{{- if .image.tag }}{{ $ref = printf "%s:%s" $ref (toString .image.tag) }}{{ end -}}
{{- if .image.digest }}{{ $ref = printf "%s@%s" $ref .image.digest }}{{ end -}}
{{- $ref -}}
{{- end }}

{{/* The analyzer's image, with the GPU build's tag when the GPU is on. */}}
{{- define "pii-review.analyzerImage" -}}
{{- $image := deepCopy .Values.analyzer.image -}}
{{- if .Values.analyzer.gpu.enabled -}}
{{- $_ := set $image "tag" .Values.analyzer.gpu.imageTag -}}
{{- $_ := set $image "digest" .Values.analyzer.gpu.imageDigest -}}
{{- end -}}
{{- include "pii-review.image" (dict "image" $image "root" .) -}}
{{- end }}

{{- define "pii-review.analyzerWorkers" -}}
{{- if .Values.analyzer.gpu.enabled }}{{ .Values.analyzer.gpu.workers }}{{ else }}{{ .Values.analyzer.workers }}{{ end -}}
{{- end }}

{{/* Analyzer requests in flight per analysis: workers × replicas, 1-16. */}}
{{- define "pii-review.analyzeParallel" -}}
{{- if .Values.web.analyzeParallel -}}
{{- .Values.web.analyzeParallel -}}
{{- else -}}
{{- $total := mul (int (include "pii-review.analyzerWorkers" .)) (int .Values.analyzer.replicas) -}}
{{- max 1 (min 16 $total) -}}
{{- end -}}
{{- end }}

{{/*
Pod-level settings shared by every component:
(dict "root" $ "values" .Values.web "uid" 65532 "gid" 65532).
No API token, no service-link variables (a Service named pii-review would
otherwise inject PII_REVIEW_PORT=tcp://…), non-root, default seccomp.
*/}}
{{- define "pii-review.podSpec" -}}
serviceAccountName: {{ include "pii-review.serviceAccountName" .root }}
automountServiceAccountToken: false
enableServiceLinks: false
{{- with .root.Values.global.imagePullSecrets }}
imagePullSecrets:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- if .noDns }}
{{- /*
The backends call nothing, so they get no DNS: a resolver on the pod's own
loopback, where nothing listens, fails a lookup at once, as compose.yml's
internal networks do. With the cluster DNS, a lookup the network policy drops
takes 20 seconds, and Presidio's email recognizer (tldextract) looks up
publicsuffix.org on its first email, past gunicorn's 30-second worker timeout.
*/}}
dnsPolicy: None
dnsConfig:
  nameservers: [127.0.0.1]
  options:
    - name: attempts
      value: "1"
    - name: timeout
      value: "1"
{{- end }}
securityContext:
  runAsNonRoot: true
  runAsUser: {{ .uid }}
  runAsGroup: {{ .gid }}
  seccompProfile:
    type: RuntimeDefault
{{- with .values.nodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .values.tolerations }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .values.affinity }}
affinity:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .values.topologySpreadConstraints }}
topologySpreadConstraints:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}

{{/* Container-level hardening shared by every component. */}}
{{- define "pii-review.containerSecurityContext" -}}
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  privileged: false
  capabilities:
    drop: [ALL]
{{- end }}

{{/*
Pod metadata: (dict "root" $ "component" "web" "values" .Values.web), with
optional "annotations" the chart adds (such as a checksum).
*/}}
{{- define "pii-review.podMetadata" -}}
labels:
  {{- include "pii-review.componentLabels" (dict "root" .root "component" .component) | nindent 2 }}
  {{- with .values.podLabels }}
  {{- toYaml . | nindent 2 }}
  {{- end }}
{{- $annotations := merge (dict) (.annotations | default dict) (.values.podAnnotations | default dict) }}
{{- with $annotations }}
annotations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}
