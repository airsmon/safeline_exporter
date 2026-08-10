# Metrics

The exporter defines 103 project-specific Prometheus metric families: 102 SafeLine/scrape families plus `safeline_exporter_build_info`. It also registers the standard Prometheus Go, process and HTTP-handler collectors. Metrics ending in `_window` are gauges over the supported 24-hour rolling period. SafeLine CE 9.3.11 returns a fixed `last1Day` statistics series even for other requested presets, so the exporter rejects non-24h `SAFELINE_EXPORTER_WINDOW` values to keep the label truthful. Prometheus builds the long-term time series by scraping these gauges; the exporter does not replay SafeLine's historical buckets as Prometheus samples.

## API coverage

| Collector | SafeLine API | Purpose |
|---|---|---|
| `health` | `/api/open/health` | API health |
| `system` | `/api/open/system` | Version, deployment state, password age, basic license state |
| `extended_system` | `/api/open/system/arch`, `/api/open/system/edition`, `/api/open/system/license/status`, `/api/open/system/protocol`, `/api/open/detector`, `/api/open/global/mode` | Architecture, edition, detailed license, detector and semantic modes |
| `statistics` | `/api/stat/advance/access`, `/api/stat/advance/attack`, `/api/stat/advance/trend/access`, `/api/stat/advance/trend/intercept`, `/api/stat/qps` | Traffic totals, security actions, trends and QPS |
| `extended_statistics` | `/api/open/security_posture/statistics`, `/api/stat/advance/client`, `/api/stat/advance/location` | Security posture, clients and geography |
| `http_status` | `/api/stat/advance/error_status_code`, `/api/stat/advance/status_code` | Independently validated WAF/upstream 4xx, 5xx and status-code statistics |
| `events` | `/api/open/events` | Normal attack events |
| `rule_events` | `/api/open/events/rule` | Blacklist/whitelist rule events |
| `attack_logs` | `/api/open/records` | Normal detection logs |
| `rule_logs` | `/api/open/records/rule` | Blacklist/whitelist rule logs |
| `sites` | `/api/open/site` | Protected applications and upstream health |
| `certificates` | `/api/open/cert` | Certificates and expiry |

## Exporter and system status

| Metric | Meaning |
|---|---|
| `safeline_up` | Health endpoint is reachable and returns `ok` |
| `safeline_exporter_collector_success{collector}` | Individual collector succeeded during the current scrape |
| `safeline_exporter_collector_duration_seconds{collector}` | Duration of each individual collector during the current scrape |
| `safeline_exporter_scrape_success` | All collectors succeeded during the current scrape |
| `safeline_exporter_scrape_duration_seconds` | End-to-end scrape duration |
| `safeline_exporter_build_info{version,revision,build_date,go_version}` | Exporter build identity injected by the release build |
| `safeline_info{version}` | Installed SafeLine version |
| `safeline_outdated` | SafeLine reports that the installed version is outdated |
| `safeline_deprecated` | SafeLine reports that the installed version is deprecated |
| `safeline_system_arch_info{arch}` | Runtime architecture information |
| `safeline_system_edition_info{version,licensed_edition,effective_edition,state}` | Configured and effective edition information |
| `safeline_system_oversea` | Overseas deployment mode |
| `safeline_system_slave` | Slave-node state |
| `safeline_system_staging` | Staging-mode state |
| `safeline_system_created_timestamp_seconds` | SafeLine creation Unix timestamp; omitted if the API returns zero |
| `safeline_password_expiry_days` | Days until the management password expires |
| `safeline_license_valid` | Basic license-valid flag from the system API |
| `safeline_license_info{state,expiry_phase,prompt_type,licensed_edition,effective_edition}` | Detailed low-cardinality license state |
| `safeline_license_days_until_expiry` | Days until license expiry; a negative value means already elapsed |
| `safeline_license_expiry_timestamp_seconds` | License expiry Unix timestamp; omitted when unavailable |
| `safeline_license_river_disconnected_duration_seconds` | Duration reported for disconnection from the SafeLine license service |
| `safeline_management_protocol_enabled` | Management protocol accepted/enabled state |
| `safeline_detector_mode_info{mode}` | Detector mode |
| `safeline_semantic_module_info{module,mode}` | Global mode for each bounded semantic-detection module |

Machine IDs, organization/account identity, authorization keys and management addresses are intentionally not exposed as labels.

Standard `go_*`, `process_*` and `promhttp_metric_handler_*` metrics are provided by `client_golang`; they are not repeated in this document because their schema is owned by that library.

## Traffic, QPS and security statistics

| Metric | Meaning |
|---|---|
| `safeline_requests_window{window}` | Request total reported by SafeLine |
| `safeline_unique_visitors_window{window}` | Session-based unique visitors |
| `safeline_unique_client_ips_window{window}` | Unique client-IP total; IP values are never labels |
| `safeline_page_views_window{window}` | Page-view total |
| `safeline_intercepts_window{window}` | Sum of intercept trend buckets |
| `safeline_requests_latest_bucket` | Request count in the newest returned trend bucket |
| `safeline_intercepts_latest_bucket` | Intercept count in the newest returned trend bucket |
| `safeline_statistics_latest_bucket_timestamp_seconds{series}` | Timestamp of the newest `requests` or `intercepts` bucket |
| `safeline_qps` | Latest total QPS, converted as `ceil(raw 5-second request count / 5)` to match the SafeLine UI |
| `safeline_qps_recent_average` | Average of the converted QPS values over up to 35 samples returned by SafeLine |
| `safeline_qps_recent_max` | Maximum converted QPS value over up to 35 samples returned by SafeLine |
| `safeline_qps_by_listener{listener}` | Latest per-listener QPS, converted independently from the listener's 5-second request count |
| `safeline_client_requests_window{kind,name,window}` | Top client OS/browser request totals; `kind` is `os` or `browser` and the API result is capped at 20 |
| `safeline_traffic_by_location_window{scope,traffic,country,province,window}` | Requests/intercepts by country or province; `scope` is `country` or `province` |
| `safeline_unique_attack_ips_window{window}` | Authoritative aggregated unique attack-IP count |
| `safeline_security_actions_window{type,window}` | Security actions by SafeLine type, such as block, rate limit, challenge, authentication defense, offline or blacklist |
| `safeline_security_actions_total_window{window}` | Sum of all returned security-action categories |
| `safeline_security_posture_events_window{category,action,window}` | Pre-aggregated attack, blacklist, whitelist, ACL, waiting-room, challenge and authentication activity |
| `safeline_anti_tamper_events_window{window}` | Sum of the sole numeric count in each anti-tamper record returned by the security-posture API |

`/api/stat/advance/domain` and `/api/stat/advance/page` are intentionally excluded because domain and URL labels can grow without a safe bound. Dedicated raw ACL, authentication, challenge and waiting-room records are represented through the exact security-posture aggregates because those raw APIs do not provide a reliable rolling-time filter on the tested SafeLine version.

## HTTP responses

| Metric | Meaning |
|---|---|
| `safeline_http_status_data_valid{source}` | Aggregate 4xx/5xx feed passed validation; `source` is `upstream` or `waf` |
| `safeline_http_status_code_data_valid{source}` | Individual status-code feed independently passed validation |
| `safeline_http_responses_window{source,class,window}` | Validated aggregate 4xx/5xx total by source |
| `safeline_http_status_code_responses_window{source,code,window}` | Independently validated individual status-code total by source |

SafeLine 9.3.11 uses `upstream=true` for upstream-service responses and `upstream=false` for WAF-generated responses or interceptions on both status endpoints. The exporter queries both sources explicitly. Aggregate 4xx/5xx values and individual status-code rows are validated independently because SafeLine can return a correct non-zero aggregate while returning an empty status-code list. Aggregate validation accepts finite, non-negative values; status-code validation additionally requires codes in the HTTP 100–599 range. Each invalid feed suppresses only its corresponding response family. Alert on either validity metric being zero, and never interpret a suppressed family as zero errors.

## Normal attack events

| Metric | Meaning |
|---|---|
| `safeline_attack_events_window{window}` | Total events reported by the API |
| `safeline_attack_events_fetched` | Event records fetched for aggregation during the scrape |
| `safeline_attack_requests_window{action,window}` | Requests grouped into events, split into `deny` and `pass` |
| `safeline_attack_event_source_ips_window{window}` | Unique source-IP cardinality within fetched events; no IP label is emitted |
| `safeline_unfinished_attack_events_window{window}` | Fetched events still marked unfinished |
| `safeline_attack_events_by_country_window{country,window}` | Fetched event count by country |
| `safeline_attack_events_by_protocol_window{protocol,window}` | Fetched event count by SafeLine protocol value |
| `safeline_attack_event_duration_samples_window{window}` | Fetched events with a usable duration |
| `safeline_attack_event_duration_seconds{statistic,window}` | Average or maximum event duration |
| `safeline_attack_event_latest_timestamp_seconds` | Latest timestamp represented by fetched events; omitted if unavailable |
| `safeline_attack_events_truncated` | API reported more events than `collector.max-events` allowed the exporter to fetch |

`safeline_unique_attack_ips_window` is the exact global value. `safeline_attack_event_source_ips_window` only describes the records fetched by the exporter and can be partial when truncation is active.

## Normal detection logs

| Metric | Meaning |
|---|---|
| `safeline_attack_logs_window{window}` | Total raw detection-log records reported by the API |
| `safeline_attack_logs_fetched` | Raw records fetched for aggregation during the scrape |
| `safeline_attack_log_records_by_action_window{action,window}` | Records by normalized action |
| `safeline_attack_log_records_by_type_window{attack_type,window}` | Records by SafeLine attack type |
| `safeline_attack_log_records_by_risk_window{risk_level,window}` | Records by risk level |
| `safeline_attack_log_records_by_module_window{module,window}` | Records by detection module |
| `safeline_attack_log_records_by_country_window{country,window}` | Records by country |
| `safeline_attack_log_records_by_protocol_window{protocol,window}` | Records by SafeLine protocol value |
| `safeline_attack_log_records_by_status_code_window{code,window}` | Records by validated HTTP status code; invalid values map to `other` |
| `safeline_attack_log_records_by_method_window{method,window}` | Records by standard HTTP method; non-standard values map to `OTHER` |
| `safeline_attack_log_latest_timestamp_seconds` | Latest fetched raw-log timestamp; omitted if unavailable |
| `safeline_attack_logs_truncated` | API reported more raw records than the configured cap |

Each dimension is aggregated independently. The exporter deliberately avoids cross-products such as attack type × IP × host × URL.

## Blacklist and whitelist rule events

| Metric | Meaning |
|---|---|
| `safeline_rule_attack_events_window{window}` | Total rule events reported by the API |
| `safeline_rule_attack_events_fetched` | Rule events fetched for aggregation during the scrape |
| `safeline_rule_attack_requests_window{action,window}` | Rule-event requests split into `deny` and `pass` |
| `safeline_rule_attack_event_source_ips_window{window}` | Unique source-IP cardinality within fetched rule events |
| `safeline_rule_unfinished_attack_events_window{window}` | Fetched rule events still marked unfinished |
| `safeline_rule_attack_event_duration_samples_window{window}` | Rule events with a usable duration |
| `safeline_rule_attack_event_duration_seconds{statistic,window}` | Average or maximum rule-event duration |
| `safeline_rule_attack_event_latest_timestamp_seconds` | Latest timestamp represented by fetched rule events |
| `safeline_rule_attack_events_truncated` | API reported more rule events than the configured cap |

## Blacklist and whitelist rule logs

| Metric | Meaning |
|---|---|
| `safeline_rule_attack_logs_window{window}` | Total raw rule-log records reported by the API |
| `safeline_rule_attack_logs_fetched` | Rule-log records fetched for aggregation during the scrape |
| `safeline_rule_attack_log_records_by_action_window{action,window}` | Rule records by action |
| `safeline_rule_attack_log_records_by_type_window{attack_type,window}` | Rule records by SafeLine attack type |
| `safeline_rule_attack_log_records_by_risk_window{risk_level,window}` | Rule records by risk level |
| `safeline_rule_attack_log_records_by_module_window{module,window}` | Rule records by module |
| `safeline_rule_attack_log_records_by_country_window{country,window}` | Rule records by country |
| `safeline_rule_attack_log_records_by_protocol_window{protocol,window}` | Rule records by protocol |
| `safeline_rule_attack_log_records_by_status_code_window{code,window}` | Rule records by normalized HTTP status code |
| `safeline_rule_attack_log_records_by_method_window{method,window}` | Rule records by normalized HTTP method |
| `safeline_rule_attack_log_latest_timestamp_seconds` | Latest fetched rule-log timestamp |
| `safeline_rule_attack_logs_truncated` | API reported more rule logs than the configured cap |

IP, host, URL, query string, request/response bodies, payload, JA4 and other unbounded or sensitive raw fields are never exported as labels.

## Sites and certificates

These families are outside the three core categories but retain the requested protected-application and TLS-certificate coverage.

| Metric | Meaning |
|---|---|
| `safeline_sites` | Configured site count |
| `safeline_sites_syncing` | Site-configuration synchronization state |
| `safeline_site_info{id,site,mode}` | Site identity and mode (`defense`, `offline`, `dry_run` or `unknown`) |
| `safeline_site_statistics_enabled{id,site,mode}` | Per-site statistics-enabled state |
| `safeline_site_upstream_health_state{id,site,upstream}` | Raw upstream health state reported by SafeLine |
| `safeline_certificates` | Managed certificate count |
| `safeline_certificate_expired{id,domains}` | Certificate-expired state |
| `safeline_certificate_revoked{id,domains}` | Certificate-revoked state |
| `safeline_certificate_trusted{id,domains}` | Certificate-trust state |
| `safeline_certificate_expiry_parse_success{id,domains}` | Expiry timestamp was parsed successfully |
| `safeline_certificate_expiry_timestamp_seconds{id,domains}` | Certificate expiry Unix timestamp |
| `safeline_certificate_expiry_seconds{id,domains}` | Remaining certificate lifetime; negative means expired |

An empty API list emits `safeline_sites 0` or `safeline_certificates 0`; naturally there are no per-object series in that case.

## Completeness and cardinality rules

- Compare every `*_window` value only with data scraped using the same configured window.
- For normal/rule events and logs, compare `*_fetched` with the API total and check `*_truncated`. Aggregations derived from fetched raw records can be partial; SafeLine's pre-aggregated traffic and security-posture values are not affected by the pagination cap.
- Country/province, protocol, action, risk, module, standard HTTP method, response code and the top-20 client list are the only raw-log/statistical dimensions used. No source IP value, domain, URL or payload becomes a time-series label.
- A family that depends on returned objects or a latest timestamp can be absent when the corresponding API list is empty. Use collector success and aggregate count metrics to distinguish empty data from a failed scrape.
