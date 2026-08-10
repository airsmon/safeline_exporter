# Grafana dashboards

`safeline-exporter-overview.json` is an import-ready dashboard for Grafana 10.4 or newer. It uses only metrics exported by this repository and covers:

- SafeLine and exporter health, version, architecture, edition, collector state and license
- 24-hour rolling traffic, interceptions, visitors and QPS converted from SafeLine's 5-second samples
- security actions and security-posture aggregates
- normal and rule attack events, detection-log type, risk and action aggregates
- upstream 4xx errors, WAF 4xx interceptions and combined 5xx errors, with request ratios and independently validated status-code details
- certificate counts, state and days until expiry

## Import

1. In Grafana, open **Dashboards → New → Import**.
2. Upload `safeline-exporter-overview.json`.
3. Open the imported dashboard and select a value for the **Prometheus** variable.
4. Select the desired Prometheus `job` and exporter `instance` values.

The dashboard datasource is referenced through the `$datasource` variable, so the JSON does not embed a datasource UID. The `job` and `instance` variables are populated from `safeline_up`.

All selected instances are summed in aggregate panels. If several exporter replicas scrape the same SafeLine API, select one replica in the **Exporter instance** variable to avoid double counting.

Metrics with a `_window` suffix are SafeLine's rolling 24-hour gauges, not Prometheus counters. Panels therefore display their values directly instead of applying `rate()` or `increase()`.

The QPS panel displays values converted from SafeLine's 5-second request-count samples. Prometheus timestamps those values when it scrapes the exporter, so the chart can lag the SafeLine page by up to one Prometheus scrape interval.

The HTTP section starts with three compact cards: upstream 4xx errors, WAF 4xx interceptions, and the combined upstream/WAF 5xx total. Each card shows both the rolling count and its percentage of all requests. The cards intentionally show **无数据** instead of zero when their aggregate input is suppressed. Use **HTTP 数据质量** to inspect aggregate and status-code validity independently; a zero validity value means the corresponding response family was suppressed and must not be interpreted as zero errors.

Certificate aggregate panels use zero when SafeLine has no managed certificates. Per-certificate expiry details are naturally empty because no certificate series exist.
