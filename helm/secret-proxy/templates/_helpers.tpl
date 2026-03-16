{{- define "secret-proxy.fullname" -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "secret-proxy.labels" -}}
app.kubernetes.io/name: secret-proxy
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
