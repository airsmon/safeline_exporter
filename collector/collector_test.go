package collector

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
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
			"/api/open/records/rule":                `{"data":{"data":[{"attack_type":-3,"action":1,"risk_level":0,"module":"blacklist","country":"CN","protocol":1,"status_code":403,"method":"GET","timestamp":200}],"total":1},"err":null,"msg":""}`,
			"/api/open/security_posture/statistics": `{"data":{"attack_deny":2,"attack_allow":1,"black_hit":3,"black_deny":3,"black_allow":0,"white_hit":1,"acl_hit":1,"waiting_hit":0,"challenge_deny":0,"challenge_allow":0,"auth_deny":0,"auth_allow":0,"anti_tamper":[{"site-a":"5"},{"site-b":"3"}]},"err":null,"msg":""}`,
			"/api/stat/qps":                         `{"data":{"nodes":[{"time":"11:59:50","listener-a":1},{"time":"11:59:55","listener-a":5},{"time":"12:00:00","listener-a":6,"listener-b":4}]},"err":null,"msg":""}`,
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
		switch r.URL.Path {
		case "/api/stat/qps":
			if got := r.URL.Query().Get("count"); got != "35" {
				t.Errorf("qps count = %q, want 35", got)
			}
		case "/api/stat/advance/error_status_code":
			switch r.URL.Query().Get("upstream") {
			case "true":
				body = `{"data":{"error_4xx":8,"error_5xx":9},"err":null,"msg":""}`
			case "false":
				body = `{"data":{"error_4xx":3,"error_5xx":4},"err":null,"msg":""}`
			default:
				t.Errorf("missing error_status_code upstream query")
			}
		case "/api/stat/advance/status_code":
			if got := r.URL.Query().Get("size"); got != "100" {
				t.Errorf("status_code size = %q, want 100", got)
			}
			switch r.URL.Query().Get("upstream") {
			case "true":
				body = `{"data":[],"err":null,"msg":""}`
			case "false":
				body = `{"data":[{"status_code":"403","count":3},{"status_code":"500","count":4}],"err":null,"msg":""}`
			default:
				t.Errorf("missing status_code upstream query")
			}
		}
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
		`safeline_qps 2`,
		`safeline_qps_by_listener{listener="listener-a"} 2`,
		`safeline_qps_by_listener{listener="listener-b"} 1`,
		`safeline_qps_recent_average 1.3333333333333333`,
		`safeline_unique_attack_ips_window{window="24h0m0s"} 9`,
		`safeline_attack_events_fetched 2`,
		`safeline_attack_event_source_ips_window{window="24h0m0s"} 2`,
		`safeline_attack_event_duration_samples_window{window="24h0m0s"} 1`,
		`safeline_attack_requests_window{action="deny",window="24h0m0s"} 6`,
		`safeline_security_actions_window{type="blacklist",window="24h0m0s"} 3`,
		`safeline_unique_visitors_window{window="24h0m0s"} 4`,
		`safeline_qps_recent_max 2`,
		`safeline_attack_log_records_by_module_window{module="m_sqli",window="24h0m0s"} 2`,
		`safeline_attack_log_records_by_action_window{action="deny",action_name="拦截",window="24h0m0s"} 2`,
		`safeline_attack_log_records_by_type_window{attack_type="0",attack_type_name="SQL 注入",window="24h0m0s"} 2`,
		`safeline_attack_log_records_by_risk_window{risk_level="3",risk_level_name="高危",window="24h0m0s"} 2`,
		`safeline_rule_attack_logs_window{window="24h0m0s"} 1`,
		`safeline_rule_attack_log_records_by_type_window{attack_type="-3",attack_type_name="黑名单",window="24h0m0s"} 1`,
		`safeline_rule_attack_log_records_by_risk_window{risk_level="0",risk_level_name="未分级",window="24h0m0s"} 1`,
		`safeline_security_posture_events_window{action="deny",category="attack",window="24h0m0s"} 2`,
		`safeline_anti_tamper_events_window{window="24h0m0s"} 8`,
		`safeline_client_requests_window{kind="os",name="Linux",window="24h0m0s"} 10`,
		`safeline_http_status_data_valid{source="upstream"} 1`,
		`safeline_http_status_code_data_valid{source="upstream"} 1`,
		`safeline_http_responses_window{class="5xx",source="upstream",window="24h0m0s"} 9`,
		`safeline_http_responses_window{class="4xx",source="waf",window="24h0m0s"} 3`,
		`safeline_http_status_code_responses_window{code="403",source="waf",window="24h0m0s"} 3`,
		`safeline_exporter_scrape_success 1`,
	} {
		if !strings.Contains("\n"+body, "\n"+expected+"\n") {
			t.Errorf("missing %q in metrics:\n%s", expected, body)
		}
	}
	if expectedPrefix := `safeline_certificate_expiry_timestamp_seconds{domains="example.com",id="2"} `; !strings.Contains("\n"+body, "\n"+expectedPrefix) {
		t.Errorf("missing metric prefix %q in metrics:\n%s", expectedPrefix, body)
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

func TestNormalizeQPSCount(t *testing.T) {
	for _, test := range []struct {
		raw  float64
		want float64
	}{
		{raw: 0, want: 0},
		{raw: 1, want: 1},
		{raw: 5, want: 1},
		{raw: 6, want: 2},
		{raw: 77, want: 16},
	} {
		if got := normalizeQPSCount(test.raw); got != test.want {
			t.Errorf("normalizeQPSCount(%v) = %v, want %v", test.raw, got, test.want)
		}
	}
}

func TestPopulateQPSMetrics(t *testing.T) {
	result := statisticsMetrics{}
	err := populateQPSMetrics(&result, []map[string]any{
		{"time": "11:59:50", "listener-a": 1.0},
		{"time": "11:59:55", "listener-a": 5.0},
		{"time": "12:00:00", "listener-a": 6.0, "listener-b": 4.0},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.QPS != 2 || result.QPSMax != 2 || math.Abs(result.QPSAverage-4.0/3.0) > 1e-12 {
		t.Fatalf("unexpected normalized QPS metrics: %+v", result)
	}
	if result.QPSByListener["listener-a"] != 2 || result.QPSByListener["listener-b"] != 1 {
		t.Fatalf("unexpected listener QPS metrics: %v", result.QPSByListener)
	}

	for name, nodes := range map[string][]map[string]any{
		"empty response": nil,
		"empty sample":   {{"time": "12:00:00"}},
		"string count":   {{"time": "12:00:00", "listener": "5"}},
		"negative count": {{"time": "12:00:00", "listener": -1.0}},
		"nan count":      {{"time": "12:00:00", "listener": math.NaN()}},
		"infinite count": {{"time": "12:00:00", "listener": math.Inf(1)}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := populateQPSMetrics(&statisticsMetrics{}, nodes); err == nil {
				t.Fatal("malformed QPS data was accepted")
			}
		})
	}
}

func TestHTTPStatusValidation(t *testing.T) {
	if !validHTTPErrors(httpErrors{Errors4xx: float64Pointer(8), Errors5xx: float64Pointer(9)}) {
		t.Fatal("valid aggregate errors were rejected")
	}
	if validHTTPErrors(httpErrors{}) || validHTTPErrors(httpErrors{Errors4xx: float64Pointer(1)}) {
		t.Fatal("missing aggregate error fields were accepted")
	}
	for _, payload := range []string{
		`{"data":{},"err":null,"msg":""}`,
		`{"data":{"error_4xx":1},"err":null,"msg":""}`,
		`{"data":{"error_5xx":1},"err":null,"msg":""}`,
	} {
		var response apiResponse[httpErrors]
		if err := json.Unmarshal([]byte(payload), &response); err != nil {
			t.Fatal(err)
		}
		if validHTTPErrors(response.Data) {
			t.Errorf("missing HTTP error fields were accepted for %s", payload)
		}
	}
	if !validHTTPStatusCodes(nil) {
		t.Fatal("empty status-code data should be valid independently of aggregate errors")
	}
	if !validHTTPStatusCodes([]httpStatusCode{{Code: "403", Count: 3}}) {
		t.Fatal("valid status-code data was rejected")
	}
	for _, errors := range []httpErrors{
		{Errors4xx: float64Pointer(-1), Errors5xx: float64Pointer(0)},
		{Errors4xx: float64Pointer(math.NaN()), Errors5xx: float64Pointer(0)},
		{Errors4xx: float64Pointer(0), Errors5xx: float64Pointer(math.Inf(1))},
	} {
		if validHTTPErrors(errors) {
			t.Errorf("invalid aggregate errors were accepted: %+v", errors)
		}
	}
	for _, codes := range [][]httpStatusCode{
		{{Code: "99", Count: 1}},
		{{Code: "600", Count: 1}},
		{{Code: "invalid", Count: 1}},
		{{Code: "403", Count: -1}},
		{{Code: "403", Count: math.Inf(1)}},
	} {
		if validHTTPStatusCodes(codes) {
			t.Errorf("invalid status-code data was accepted: %+v", codes)
		}
	}
}

func float64Pointer(value float64) *float64 {
	return &value
}

type collectorFunc func(chan<- prometheus.Metric)

func (collectorFunc) Describe(chan<- *prometheus.Desc) {}

func (collect collectorFunc) Collect(ch chan<- prometheus.Metric) {
	collect(ch)
}

func TestWriteHTTPStatusKeepsFeedsIndependent(t *testing.T) {
	data := httpStatusMetrics{Sources: map[string]httpStatusSource{
		"upstream": {
			Errors:      httpErrors{Errors4xx: float64Pointer(8), Errors5xx: float64Pointer(9)},
			Codes:       []httpStatusCode{{Code: "invalid", Count: 1}},
			ErrorsValid: true,
			CodesValid:  false,
		},
		"waf": {
			Errors:      httpErrors{Errors4xx: float64Pointer(3)},
			Codes:       []httpStatusCode{{Code: "403", Count: 3}},
			ErrorsValid: false,
			CodesValid:  true,
		},
	}}
	registry := prometheus.NewRegistry()
	registry.MustRegister(collectorFunc(func(ch chan<- prometheus.Metric) {
		writeHTTPStatus(&metricWriter{ch: ch}, data, 24*time.Hour)
	}))
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}

	byName := make(map[string]map[string]float64, len(families))
	for _, family := range families {
		values := make(map[string]float64, len(family.Metric))
		for _, metric := range family.Metric {
			labels := make(map[string]string, len(metric.Label))
			for _, label := range metric.Label {
				labels[label.GetName()] = label.GetValue()
			}
			key := labels["source"] + "/" + labels["class"] + "/" + labels["code"]
			values[key] = metric.GetGauge().GetValue()
		}
		byName[family.GetName()] = values
	}

	aggregates := byName["safeline_http_responses_window"]
	if len(aggregates) != 2 || aggregates["upstream/4xx/"] != 8 || aggregates["upstream/5xx/"] != 9 {
		t.Fatalf("aggregate HTTP feed was not isolated: %v", aggregates)
	}
	codes := byName["safeline_http_status_code_responses_window"]
	if len(codes) != 1 || codes["waf//403"] != 3 {
		t.Fatalf("status-code HTTP feed was not isolated: %v", codes)
	}
	if got := byName["safeline_http_status_data_valid"]; got["upstream//"] != 1 || got["waf//"] != 0 {
		t.Fatalf("unexpected aggregate validity metrics: %v", got)
	}
	if got := byName["safeline_http_status_code_data_valid"]; got["upstream//"] != 0 || got["waf//"] != 1 {
		t.Fatalf("unexpected status-code validity metrics: %v", got)
	}
}

func TestSumAntiTamperEvents(t *testing.T) {
	got, err := sumAntiTamperEvents([]map[string]string{{"site-a": "2"}, {"site-b": "3"}, {"site-c": "4"}})
	if err != nil {
		t.Fatal(err)
	}
	if got != 9 {
		t.Fatalf("sumAntiTamperEvents() = %v, want 9", got)
	}
	if got, err := sumAntiTamperEvents(nil); err != nil || got != 0 {
		t.Fatalf("sumAntiTamperEvents(nil) = %v, %v; want 0, nil", got, err)
	}
	for _, raw := range []string{"invalid", "-1", "NaN", "+Inf"} {
		if _, err := sumAntiTamperEvents([]map[string]string{{"site": raw}}); err == nil {
			t.Errorf("sumAntiTamperEvents accepted %q", raw)
		}
	}
	for name, groups := range map[string][]map[string]string{
		"empty record":     {{}},
		"multi-key record": {{"site-a": "1", "site-b": "2"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := sumAntiTamperEvents(groups); err == nil {
				t.Fatal("malformed anti-tamper record was accepted")
			}
		})
	}
}

func TestAttackLogDisplayNames(t *testing.T) {
	for value, want := range map[string]string{
		"-3": "黑名单",
		"-2": "白名单",
		"0":  "SQL 注入",
		"29": "模板注入",
		"64": "Cookie 篡改",
		"65": "未知 (65)",
	} {
		if got := attackTypeDisplayName(value); got != want {
			t.Errorf("attackTypeDisplayName(%q) = %q, want %q", value, got, want)
		}
	}
	for value, want := range map[string]string{"0": "未分级", "1": "低危", "2": "中危", "3": "高危", "4": "未知 (4)"} {
		if got := riskLevelDisplayName(value); got != want {
			t.Errorf("riskLevelDisplayName(%q) = %q, want %q", value, got, want)
		}
	}
	for value, want := range map[string]string{"pass": "放行", "deny": "拦截", "unknown": "未知"} {
		if got := attackActionDisplayName(value); got != want {
			t.Errorf("attackActionDisplayName(%q) = %q, want %q", value, got, want)
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
