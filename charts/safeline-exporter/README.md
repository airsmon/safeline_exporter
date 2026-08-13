# SafeLine Exporter Helm chart

This chart deploys one or more SafeLine Exporter pods, a `ClusterIP` Service on
port `9719`, and optionally a Prometheus Operator `ServiceMonitor`.

## Prerequisites

- Kubernetes 1.23 or newer
- A built and published `safeline-exporter` container image
- A SafeLine Open API address and token
- Prometheus Operator CRDs when `serviceMonitor.enabled=true`

## Install with an existing Secret (recommended)

Create the Secret without placing the token in `values.yaml`:

```bash
kubectl create namespace monitoring
kubectl -n monitoring create secret generic safeline-exporter \
  --from-file=api-token=/path/to/safeline-token-file
```

Install or upgrade the chart:

```bash
helm upgrade --install safeline-exporter ./charts/safeline-exporter \
  --namespace monitoring \
  --set image.repository=registry.example.com/monitoring/safeline-exporter \
  --set image.tag=0.3.1 \
  --set safeline.address=https://safeline.example.com \
  --set existingSecret=safeline-exporter
```

The Secret key defaults to `api-token`; change `existingSecretKey` if your
Secret uses a different key.

## Prometheus Operator

Enable the optional `ServiceMonitor` and add any label required by your
Prometheus selector:

```yaml
serviceMonitor:
  enabled: true
  interval: 60s
  scrapeTimeout: 30s
  labels:
    release: kube-prometheus-stack
```

## Grafana dashboard sidecar

When Grafana has a dashboard sidecar, Helm can create its ConfigMap without
checking in a second copy of the dashboard JSON:

```bash
helm upgrade --install safeline-exporter ./charts/safeline-exporter \
  --namespace monitoring \
  --reuse-values \
  --set grafanaDashboard.enabled=true \
  --set-file grafanaDashboard.content=./grafana/safeline-exporter-overview.json
```

The default label is `grafana_dashboard: "1"`. Override
`grafanaDashboard.labels` or `grafanaDashboard.namespace` when the Grafana
sidecar watches a different selector or namespace.

## Helm-managed Secret

The chart can create a Secret when `secret.create=true`, but the token will then
be stored in Helm release data. Use an existing Secret in production. For a
temporary installation, supply `secret.apiToken` outside the checked-in values
file:

```bash
helm upgrade --install safeline-exporter ./charts/safeline-exporter \
  --set safeline.address=https://safeline.example.com \
  --set secret.create=true \
  --set-string secret.apiToken="$SAFELINE_API_TOKEN"
```

## Important values

| Value | Default | Description |
|---|---:|---|
| `image.repository` | `safeline-exporter` | Exporter image repository |
| `image.tag` | Chart `appVersion` | Exporter image tag when left empty |
| `hostAliases` | `[]` | Optional pod-level hostname mappings for split-horizon DNS environments |
| `safeline.address` | empty | Required SafeLine base URL |
| `safeline.insecureSkipVerify` | `false` | Skip TLS certificate verification |
| `safeline.allowHTTP` | `false` | Explicitly allow sending the token over plain HTTP |
| `existingSecret` | empty | Existing Secret containing the API token |
| `existingSecretKey` | `api-token` | Token key in the Secret |
| `collector.window` | `24h` | SafeLine statistics window; currently only `24h` |
| `collector.maxEvents` | `10000` | Maximum event/log records read per scrape |
| `collector.scrapeTimeout` | `25s` | Overall exporter scrape deadline; keep ServiceMonitor timeout above it |
| `exporter.port` | `9719` | Exporter container port |
| `service.port` | `9719` | Kubernetes Service port |
| `serviceMonitor.enabled` | `false` | Create a Prometheus Operator ServiceMonitor |
| `grafanaDashboard.enabled` | `false` | Create a Grafana sidecar Dashboard ConfigMap |

See [`values.yaml`](values.yaml) for probes, resource controls, scheduling,
security contexts, ServiceMonitor relabeling, and TLS verification settings.
