# Grafana dashboards

`safeline-exporter-overview.json` is an import-ready dashboard for Grafana 10.4 or newer. It uses only metrics exported by this repository and covers:

- SafeLine and exporter health, version, architecture, edition, collector state and license
- 24-hour rolling traffic, interceptions, visitors and QPS
- security actions and security-posture aggregates
- normal and rule attack events, detection-log type, risk and action aggregates
- validated upstream/WAF 4xx and 5xx statistics
- certificate counts, state and days until expiry

## Import

1. In Grafana, open **Dashboards → New → Import**.
2. Upload `safeline-exporter-overview.json`.
3. Open the imported dashboard and select a value for the **Prometheus** variable.
4. Select the desired Prometheus `job` and exporter `instance` values.

The dashboard datasource is referenced through the `$datasource` variable, so the JSON does not embed a datasource UID. The `job` and `instance` variables are populated from `safeline_up`.

All selected instances are summed in aggregate panels. If several exporter replicas scrape the same SafeLine API, select one replica in the **Exporter instance** variable to avoid double counting.

Metrics with a `_window` suffix are SafeLine's rolling 24-hour gauges, not Prometheus counters. Panels therefore display their values directly instead of applying `rate()` or `increase()`.

The exporter suppresses inconsistent HTTP status data. Check **状态数据有效性** when an upstream or WAF error panel has no samples. Certificate detail panels are naturally empty when SafeLine has no managed certificates.
