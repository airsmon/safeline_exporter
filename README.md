# SafeLine Exporter

Prometheus exporter for the SafeLine WAF Open API. The exporter uses read-only SafeLine endpoints and the official Prometheus Go client for collection, descriptor validation, exposition, Go/process metrics, and HTTP instrumentation.

<img width="2880" height="5034" alt="FireShot Capture 002 - SafeLine Exporter Overview - Dashboards - Grafana_ -  grafana infra daocloud io" src="https://github.com/user-attachments/assets/0e9a8273-c43d-4271-ba86-2348710b3359" />


## Features

- SafeLine health, version, architecture, edition, deployment, detector, semantic-module, password and license state
- Protected applications, upstream health, certificates and expiry
- Rolling requests, visitors, client IPs, page views, intercepts, clients and geography
- UI-compatible current, recent-average, recent-maximum and per-listener QPS converted from SafeLine's 5-second samples
- Independently validated upstream/WAF 4xx, 5xx and individual status-code statistics
- Normal and rule attack events with request counts, source-IP cardinality, duration, geography, protocol and pagination completeness
- Normal and rule detection logs grouped independently by action, attack type, risk, module, country, protocol, status code and normalized HTTP method
- Exact unique attack IPs, security actions, security-posture categories and summed anti-tamper events
- Per-collector status/duration, scrape status/duration, build information and standard Go/process metrics

Rolling metrics are gauges because SafeLine returns a moving 24-hour snapshot. Prometheus creates longer-term time series by scraping these gauges.

## Project layout

```text
.
├── main.go                     # flags, registry and HTTP lifecycle
├── config/                     # environment/flag parsing and validation
├── safeline/                   # authenticated read-only API client
├── collector/                  # prometheus.Collector and API aggregations
├── grafana/                    # import-ready dashboard
├── charts/safeline-exporter/   # Helm deployment
├── deploy/                     # deployment values example and operating notes
├── docs/architecture.md        # design and extension rules
├── Dockerfile
└── Makefile
```

The structure follows the same separation used by Prometheus exporters such as `snmp_exporter`: a small root entry point, isolated configuration and protocol access, and a collector registered with `promhttp`. SafeLine is a fixed single-target exporter, so SNMP-specific dynamic modules, generators and configuration reload endpoints are intentionally not copied.

## Run

```bash
export SAFELINE_ADDRESS='https://safeline.example.com'
export SAFELINE_API_TOKEN='replace-with-api-token'
go run .
```

The exporter listens on `:9719`. Metrics are available at `http://localhost:9719/metrics`, and the process health endpoint is `http://localhost:9719/-/healthy`.

Do not put the API token on a command line in production. Supply it through a secret-backed environment variable.

## Configuration

| Environment variable | Flag | Default |
|---|---|---|
| `SAFELINE_ADDRESS` | `-safeline.address` | required |
| `SAFELINE_API_TOKEN` | `-safeline.token` | required |
| `SAFELINE_EXPORTER_LISTEN_ADDRESS` | `-web.listen-address` | `:9719` |
| `SAFELINE_EXPORTER_METRICS_PATH` | `-web.telemetry-path` | `/metrics` |
| `SAFELINE_EXPORTER_WINDOW` | `-collector.window` | `24h` (only supported value) |
| `SAFELINE_EXPORTER_MAX_EVENTS` | `-collector.max-events` | `10000` |
| `SAFELINE_EXPORTER_SCRAPE_TIMEOUT` | `-collector.scrape-timeout` | `25s` |
| `SAFELINE_TIMEOUT` | `-safeline.timeout` | `15s` |
| `SAFELINE_INSECURE_SKIP_VERIFY` | `-safeline.insecure-skip-verify` | `false` |
| `SAFELINE_ALLOW_HTTP` | `-safeline.allow-http` | `false` |

`collector.max-events` caps normal/rule attack-event and raw-log pagination. The corresponding `*_truncated` metric becomes `1` when SafeLine reports more records than were fetched. Aggregated unique attack-IP and security-posture metrics do not depend on this cap.

SafeLine CE 9.3.11 returns a fixed 24-hour statistics series even when callers request another preset. The exporter rejects non-24h windows instead of publishing a misleading label.

See [METRICS.md](METRICS.md) for the complete metric and API mapping. Conditional per-object, grouped-log and latest-timestamp series appear only when SafeLine returns matching data.

## Build and test

```bash
make check
make test-race
make build
```

`make check` runs formatting checks, `go vet`, tests and Grafana JSON validation. `make helm-lint` additionally requires Helm, and `make docker-build` requires Docker.

## Docker

```bash
docker build -t safeline-exporter:0.3.1 .
docker run --rm -p 9719:9719 \
  -e SAFELINE_ADDRESS='https://safeline.example.com' \
  -e SAFELINE_API_TOKEN \
  safeline-exporter:0.3.1
```

The multi-stage image builds a static binary, includes only CA certificates and that binary in the runtime layer, and runs as numeric user `65532`.

## Prometheus

```yaml
scrape_configs:
  - job_name: safeline
    scrape_interval: 60s
    scrape_timeout: 30s
    static_configs:
      - targets: ['safeline-exporter:9719']
```

## Grafana and Kubernetes

- Import [grafana/safeline-exporter-overview.json](grafana/safeline-exporter-overview.json) for the overview dashboard.
- Deploy with [charts/safeline-exporter](charts/safeline-exporter); use `existingSecret` for the API token, enable its `ServiceMonitor`, and optionally pass the dashboard with `--set-file grafanaDashboard.content=./grafana/safeline-exporter-overview.json` for Grafana sidecar provisioning.

## Security

Use a dedicated SafeLine API token and restrict network access to the exporter. HTTPS and certificate verification are required by default, and redirects are rejected so the token cannot be forwarded to another origin. The insecure TLS and plain-HTTP options require explicit opt-in and are intended only for controlled private deployments.

The exporter does not expose source IP values, URLs, payloads, JA4 values, account data or authorization material as Prometheus labels. Domain/site labels exist only for the explicitly configured site and certificate resources.
