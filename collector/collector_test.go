package collector

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"safeline_exporter/safeline"
)

func TestExporterMetrics(t *testing.T) {
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-SLCE-API-TOKEN") != "test-token" {
			t.Fatal("missing API token")
		}
		responses := map[string]string{
			"/api/open/health":                      `{"status":"ok"}`,
			"/api/open/system":                      `{"data":{"version":"9.3.11","outdated":false,"deprecated":false,"license":{"valid":true}},"err":null,"msg":""}`,
			"/api/open/system/arch":                 `{"data":"amd64","err":null,"msg":""}`,
			"/api/open/system/edition":              `{"data":{"version":2,"licensed_edition":2,"effective_edition":2,"state":"valid"},"err":null,"msg":""}`,
			"/api/open/system/license/status":       `{"data":{"state":"valid","expired_at":1893456000,"days_until_expiry":30,"license_expiry_phase":"30d","prompt_type":"none","river_disconnected_duration":0,"licensed_edition":2,"effective_edition":2},"err":null,"msg":""}`,
			"/api/open/system/protocol":             `{"data":true,"err":null,"msg":""}`,
			"/api/open/detector":                    `{"data":{"mode":1},"err":null,"msg":""}`,
			"/api/open/global/mode":                 `{"data":{"semantics":{"m_sqli":"default"}},"err":null,"msg":""}`,
			"/api/open/site":                        `{"data":{"data":[{"id":1,"server_names":["example.com"],"mode":0,"stat_enabled":true,"health_state":{"http://backend:8080":{"state":1,"error":""}}}],"total":1,"syncing":false},"err":null,"msg":""}`,
			"/api/open/cert":                        `{"data":{"nodes":[{"id":2,"domains":["example.com"],"valid_before":"2030-01-01T00:00:00Z","expired":false,"revoked":false,"trusted":true}]},"err":null,"msg":""}`,
			"/api/open/events":                      `{"data":{"nodes":[{"ip":"192.0.2.1","country":"CN","protocol":1,"start_at":1700000000000,"end_at":1700000002000,"updated_at":1700000002000,"deny_count":4,"pass_count":1,"finished":true},{"ip":"192.0.2.2","country":"US","protocol":1,"deny_count":2,"pass_count":0,"finished":false}],"total":2},"err":null,"msg":""}`,
			"/api/open/events/rule":                 `{"data":{"nodes":[{"ip":"192.0.2.3","deny_count":3,"pass_count":0,"finished":true,"start_at":100000,"end_at":102000,"updated_at":102000}],"total":1},"err":null,"msg":""}`,
			"/api/open/records":                     `{"data":{"data":[{"attack_type":0,"action":1,"risk_level":3,"module":"m_sqli","country":"CN","protocol":1,"status_code":403,"method":"POST","timestamp":1700000000000},{"attack_type":0,"action":1,"risk_level":3,"module":"m_sqli","country":"CN","protocol":1,"status_code":403,"method":"POST","timestamp":1700000001000}],"total":2},"err":null,"msg":""}`,
			"/api/open/records/rule":                `{"data":{"data":[{"attack_type":0,"action":1,"risk_level":0,"module":"blacklist","country":"CN","protocol":1,"status_code":403,"method":"GET","timestamp":200}],"total":1},"err":null,"msg":""}`,
			"/api/open/security_posture/statistics": `{"data":{"attack_deny":2,"attack_allow":1,"black_hit":3,"black_deny":3,"black_allow":0,"white_hit":1,"acl_hit":1,"waiting_hit":0,"challenge_deny":0,"challenge_allow":0,"auth_deny":0,"auth_allow":0,"anti_tamper":null},"err":null,"msg":""}`,
			"/api/stat/qps":                         `{"data":{"nodes":[{"time":"12:00:00","0.0.0.0:0":7}]},"err":null,"msg":""}`,
			"/api/stat/advance/access":              `{"data":{"access":30,"session":4,"ip":5,"pv":6},"err":null,"msg":""}`,
			"/api/stat/advance/attack":              `{"data":{"attack_ip":9,"intercept":{"block":6,"rate_limit":2,"challenge":1,"auth_defense":0,"offline":0,"blacklist":3}},"err":null,"msg":""}`,
			"/api/stat/advance/location":            `{"data":[{"country":"CN","province":"上海市","count":11}],"err":null,"msg":""}`,
			"/api/stat/advance/client":              `{"data":{"OS":[{"os":"Linux","count":10}],"Browser":[{"browser":"Chrome","count":9}]},"err":null,"msg":""}`,
			"/api/stat/advance/trend/access":        `{"data":[{"time":100,"count":10},{"time":200,"count":20}],"err":null,"msg":""}`,
			"/api/stat/advance/trend/intercept":     `{"data":[{"time":100,"count":2},{"time":200,"count":3}],"err":null,"msg":""}`,
			"/api/stat/advance/error_status_code":   `{"data":{"error_4xx":8,"error_5xx":9},"err":null,"msg":""}`,
			"/api/stat/advance/status_code":         `{"data":[{"status_code":"404","count":8},{"status_code":"502","count":9}],"err":null,"msg":""}`,
		}
		body, ok := responses[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}))
	defer api.Close()

	client, err := safeline.NewClient(safeline.Options{
		Address: api.URL, Token: "test-token", Timeout: time.Second, InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	exp := New(client, 24*time.Hour, 100, 5*time.Second, nil)
	registry := prometheus.NewRegistry()
	registry.MustRegister(exp)
	recorder := httptest.NewRecorder()
	promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := recorder.Body.String()
	for _, expected := range []string{
		`safeline_info{version="9.3.11"} 1`,
		`safeline_system_arch_info{arch="amd64"} 1`,
		`safeline_site_info{id="1",mode="defense",site="example.com"} 1`,
		`safeline_site_upstream_health_state{id="1",site="example.com",upstream="http://backend:8080"} 1`,
		`safeline_requests_window{window="24h0m0s"} 30`,
		`safeline_intercepts_window{window="24h0m0s"} 5`,
		`safeline_qps 7`,
		`safeline_unique_attack_ips_window{window="24h0m0s"} 9`,
		`safeline_attack_events_fetched 2`,
		`safeline_attack_event_source_ips_window{window="24h0m0s"} 2`,
		`safeline_attack_event_duration_samples_window{window="24h0m0s"} 1`,
		`safeline_attack_requests_window{action="deny",window="24h0m0s"} 6`,
		`safeline_security_actions_window{type="blacklist",window="24h0m0s"} 3`,
		`safeline_unique_visitors_window{window="24h0m0s"} 4`,
		`safeline_qps_recent_max 7`,
		`safeline_attack_log_records_by_module_window{module="m_sqli",window="24h0m0s"} 2`,
		`safeline_attack_log_records_by_action_window{action="deny",window="24h0m0s"} 2`,
		`safeline_rule_attack_logs_window{window="24h0m0s"} 1`,
		`safeline_security_posture_events_window{action="deny",category="attack",window="24h0m0s"} 2`,
		`safeline_client_requests_window{kind="os",name="Linux",window="24h0m0s"} 10`,
		`safeline_http_status_data_valid{source="upstream"} 1`,
		`safeline_http_responses_window{class="5xx",source="upstream",window="24h0m0s"} 9`,
		`safeline_certificate_expiry_timestamp_seconds{domains="example.com",id="2"}`,
		`safeline_exporter_scrape_success 1`,
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("missing %q in metrics:\n%s", expected, body)
		}
	}

	cappedExporter := New(client, 24*time.Hour, 1, 5*time.Second, nil)
	eventResult, err := cappedExporter.collectEvents(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	events := eventResult.(eventMetrics)
	if events.Fetched != 1 || !events.Truncated || events.DenyCount != 4 || events.LatestAt != 1700000002 {
		t.Fatalf("event cap not enforced: %+v", events)
	}
	logResult, err := cappedExporter.collectAttackLogs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	logs := logResult.(attackLogMetrics)
	if logs.Fetched != 1 || !logs.Truncated || logs.ByModule["m_sqli"] != 1 || logs.LatestAt != 1700000000 {
		t.Fatalf("attack log cap not enforced: %+v", logs)
	}
}

func TestParseSafeLineTime(t *testing.T) {
	for _, value := range []string{"2030-01-01T00:00:00Z", "2030-01-01 00:00:00", "2030-01-01"} {
		if _, err := parseSafeLineTime(value); err != nil {
			t.Errorf("parseSafeLineTime(%q): %v", value, err)
		}
	}
}

type blockingClient struct{}

func (blockingClient) Get(ctx context.Context, _ string, _ url.Values, _ any) error {
	<-ctx.Done()
	return ctx.Err()
}

func TestScrapeTimeout(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	exp := New(blockingClient{}, 24*time.Hour, 100, 50*time.Millisecond, logger)
	registry := prometheus.NewRegistry()
	registry.MustRegister(exp)
	started := time.Now()
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("scrape did not stop at its overall deadline")
	}
	for _, family := range families {
		if family.GetName() == "safeline_exporter_scrape_success" {
			if len(family.Metric) != 1 || family.Metric[0].GetGauge().GetValue() != 0 {
				t.Fatalf("unexpected scrape success metric: %+v", family.Metric)
			}
			return
		}
	}
	t.Fatal("missing safeline_exporter_scrape_success")
}

type stuckClient struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *stuckClient) Get(_ context.Context, _ string, _ url.Values, _ any) error {
	c.once.Do(func() { close(c.started) })
	<-c.release
	return errors.New("released test request")
}

func TestContendedScrapeStopsAtGateDeadline(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	client := &stuckClient{started: make(chan struct{}), release: make(chan struct{})}
	exp := New(client, 24*time.Hour, 100, 50*time.Millisecond, logger)
	firstRegistry := prometheus.NewRegistry()
	firstRegistry.MustRegister(exp)
	secondRegistry := prometheus.NewRegistry()
	secondRegistry.MustRegister(exp)

	firstDone := make(chan error, 1)
	go func() {
		_, err := firstRegistry.Gather()
		firstDone <- err
	}()
	<-client.started

	families, err := secondRegistry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	found := make(map[string]bool, len(families))
	for _, family := range families {
		found[family.GetName()] = true
	}
	if !found["safeline_exporter_scrape_success"] || !found["safeline_exporter_scrape_duration_seconds"] {
		t.Fatalf("gate timeout omitted scrape status metrics: %v", found)
	}
	for _, unexpected := range []string{"safeline_up", "safeline_exporter_collector_success", "safeline_exporter_collector_duration_seconds"} {
		if found[unexpected] {
			t.Fatalf("gate timeout emitted %s even though no collector ran", unexpected)
		}
	}

	close(client.release)
	select {
	case err := <-firstDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("first scrape did not finish after releasing test client")
	}
}
