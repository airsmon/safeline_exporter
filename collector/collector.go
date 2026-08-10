package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	safeLineStatisticsPreset = "last1Day"
	safeLineQPSSampleCount   = 35
	safeLineQPSSampleSeconds = 5
)

type scrapeTimeKey struct{}

type Client interface {
	Get(context.Context, string, url.Values, any) error
}

type apiResponse[T any] struct {
	Data    T
	Err     *apiErr
	Msg     string
	hasData bool
}

type apiErr struct {
	Code    any    `json:"code"`
	Message string `json:"message"`
}

func (r *apiResponse[T]) UnmarshalJSON(data []byte) error {
	var envelope struct {
		Data json.RawMessage `json:"data"`
		Err  *apiErr         `json:"err"`
		Msg  string          `json:"msg"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return err
	}
	r.Err = envelope.Err
	r.Msg = envelope.Msg
	if len(envelope.Data) == 0 || string(envelope.Data) == "null" {
		return nil
	}
	r.hasData = true
	return json.Unmarshal(envelope.Data, &r.Data)
}

type Exporter struct {
	client    Client
	window    time.Duration
	maxEvents int
	timeout   time.Duration
	logger    *slog.Logger
	gate      chan struct{}
}

type metricWriter struct {
	ch chan<- prometheus.Metric
}

func (m *metricWriter) metric(name, help, kind string, labels map[string]string, value float64) {
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	values := make([]string, len(keys))
	for index, key := range keys {
		values[index] = labels[key]
	}
	valueType := prometheus.GaugeValue
	if kind == "counter" {
		valueType = prometheus.CounterValue
	}
	desc := prometheus.NewDesc(name, help, keys, nil)
	metric, err := prometheus.NewConstMetric(desc, valueType, value, values...)
	if err != nil {
		m.ch <- prometheus.NewInvalidMetric(desc, err)
		return
	}
	m.ch <- metric
}

func New(client Client, window time.Duration, maxEvents int, timeout time.Duration, logger *slog.Logger) *Exporter {
	if logger == nil {
		logger = slog.Default()
	}
	return &Exporter{client: client, window: window, maxEvents: maxEvents, timeout: timeout, logger: logger, gate: make(chan struct{}, 1)}
}

func (*Exporter) Describe(_ chan<- *prometheus.Desc) {}

func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	start := time.Now()
	mw := &metricWriter{ch: ch}
	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()
	ctx = context.WithValue(ctx, scrapeTimeKey{}, start)
	select {
	case e.gate <- struct{}{}:
		defer func() { <-e.gate }()
	case <-ctx.Done():
		e.logger.Error("scrape skipped while another scrape was still running", "err", ctx.Err())
		mw.metric("safeline_exporter_scrape_success", "Whether all collectors in the last scrape succeeded.", "gauge", nil, 0)
		mw.metric("safeline_exporter_scrape_duration_seconds", "Duration of the exporter scrape.", "gauge", nil, time.Since(start).Seconds())
		return
	}

	type result struct {
		name     string
		data     any
		err      error
		duration time.Duration
	}
	collectors := []struct {
		name string
		fn   func(context.Context) (any, error)
	}{
		{"health", e.collectHealth},
		{"system", e.collectSystem},
		{"extended_system", e.collectExtendedSystem},
		{"sites", e.collectSites},
		{"statistics", e.collectStatistics},
		{"extended_statistics", e.collectExtendedStatistics},
		{"http_status", e.collectHTTPStatus},
		{"events", e.collectEvents},
		{"rule_events", e.collectRuleEvents},
		{"attack_logs", e.collectAttackLogs},
		{"rule_logs", e.collectRuleLogs},
		{"certificates", e.collectCertificates},
	}
	results := make(chan result, len(collectors))
	var wg sync.WaitGroup
	for _, collector := range collectors {
		wg.Add(1)
		go func() {
			defer wg.Done()
			started := time.Now()
			data, err := collector.fn(ctx)
			results <- result{name: collector.name, data: data, err: err, duration: time.Since(started)}
		}()
	}
	wg.Wait()
	close(results)

	allOK := true
	for result := range results {
		ok := result.err == nil
		if !ok {
			e.logger.Error("collector failed", "collector", result.name, "err", result.err)
			if result.name == "health" {
				mw.metric("safeline_up", "Whether the SafeLine API is reachable.", "gauge", nil, 0)
			}
		}
		if ok {
			switch data := result.data.(type) {
			case healthMetrics:
				writeHealth(mw, data)
			case systemMetrics:
				writeSystem(mw, data)
			case extendedSystemMetrics:
				writeExtendedSystem(mw, data)
			case siteMetrics:
				writeSites(mw, data)
			case statisticsMetrics:
				writeStatistics(mw, data, e.window)
			case extendedStatisticsMetrics:
				writeExtendedStatistics(mw, data, e.window)
			case httpStatusMetrics:
				writeHTTPStatus(mw, data, e.window)
			case eventMetrics:
				writeEvents(mw, data, e.window)
			case ruleEventMetrics:
				writeRuleEvents(mw, data, e.window)
			case attackLogMetrics:
				writeAttackLogs(mw, data, e.window)
			case ruleLogMetrics:
				writeRuleLogs(mw, data, e.window)
			case certificateMetrics:
				writeCertificates(mw, data)
			default:
				ok = false
				e.logger.Error("collector returned unsupported result type", "collector", result.name, "type", fmt.Sprintf("%T", result.data))
			}
		}
		if !ok {
			allOK = false
		}
		mw.metric("safeline_exporter_collector_success", "Whether the last collector scrape succeeded.", "gauge", map[string]string{"collector": result.name}, boolFloat(ok))
		mw.metric("safeline_exporter_collector_duration_seconds", "Duration of the individual collector scrape.", "gauge", map[string]string{"collector": result.name}, result.duration.Seconds())
	}
	mw.metric("safeline_exporter_scrape_success", "Whether all collectors in the last scrape succeeded.", "gauge", nil, boolFloat(allOK))
	mw.metric("safeline_exporter_scrape_duration_seconds", "Duration of the exporter scrape.", "gauge", nil, time.Since(start).Seconds())
}

func scrapeTime(ctx context.Context) time.Time {
	if value, ok := ctx.Value(scrapeTimeKey{}).(time.Time); ok {
		return value
	}
	return time.Now()
}

func boolFloat(value bool) float64 {
	if value {
		return 1
	}
	return 0
}

func checkAPIError[T any](response apiResponse[T]) error {
	if response.Err != nil {
		return fmt.Errorf("SafeLine API error %v: %s", response.Err.Code, response.Err.Message)
	}
	if !response.hasData {
		return errors.New("SafeLine API response is missing non-null data")
	}
	return nil
}

type systemMetrics struct {
	Version            string
	Outdated           bool
	Deprecated         bool
	License            bool
	Oversea            bool
	Slave              bool
	Staging            bool
	PasswordExpireDays float64
	CreatedAt          int64
}

type healthMetrics struct{ Up bool }

func (e *Exporter) collectHealth(ctx context.Context) (any, error) {
	var response struct {
		Status string `json:"status"`
	}
	if err := e.client.Get(ctx, "/api/open/health", nil, &response); err != nil {
		return nil, err
	}
	if response.Status != "ok" {
		return nil, fmt.Errorf("unexpected SafeLine health status %q", response.Status)
	}
	return healthMetrics{Up: true}, nil
}

func (e *Exporter) collectSystem(ctx context.Context) (any, error) {
	var response apiResponse[struct {
		Version            string  `json:"version"`
		Outdated           bool    `json:"outdated"`
		Deprecated         bool    `json:"deprecated"`
		Oversea            bool    `json:"oversea"`
		Slave              bool    `json:"slave"`
		Staging            bool    `json:"staging"`
		PasswordExpireDays float64 `json:"password_expire_day"`
		CreatedAt          int64   `json:"created_at"`
		License            struct {
			Valid bool `json:"valid"`
		} `json:"license"`
	}]
	if err := e.client.Get(ctx, "/api/open/system", nil, &response); err != nil {
		return nil, err
	}
	if err := checkAPIError(response); err != nil {
		return nil, err
	}
	return systemMetrics{
		Version: response.Data.Version, Outdated: response.Data.Outdated, Deprecated: response.Data.Deprecated,
		License: response.Data.License.Valid, Oversea: response.Data.Oversea, Slave: response.Data.Slave,
		Staging: response.Data.Staging, PasswordExpireDays: response.Data.PasswordExpireDays, CreatedAt: response.Data.CreatedAt,
	}, nil
}

type site struct {
	ID          int                        `json:"id"`
	ServerNames []string                   `json:"server_names"`
	Mode        int                        `json:"mode"`
	StatEnabled bool                       `json:"stat_enabled"`
	HealthState map[string]siteHealthState `json:"health_state"`
}

type siteHealthState struct {
	State int    `json:"state"`
	Error string `json:"error"`
}

type siteMetrics struct {
	Sites   []site
	Total   int
	Syncing bool
}

func (e *Exporter) collectSites(ctx context.Context) (any, error) {
	var response apiResponse[struct {
		Data    []site `json:"data"`
		Total   int    `json:"total"`
		Syncing bool   `json:"syncing"`
	}]
	query := url.Values{"page": {"1"}, "page_size": {"900"}}
	if err := e.client.Get(ctx, "/api/open/site", query, &response); err != nil {
		return nil, err
	}
	if err := checkAPIError(response); err != nil {
		return nil, err
	}
	return siteMetrics{Sites: response.Data.Data, Total: response.Data.Total, Syncing: response.Data.Syncing}, nil
}

type point struct {
	Time  int64   `json:"time"`
	Count float64 `json:"count"`
}

type statisticsMetrics struct {
	Requests        []point
	Intercepts      []point
	Accesses        float64
	Sessions        float64
	ClientIPs       float64
	PageViews       float64
	AttackIPs       float64
	InterceptByType map[string]float64
	QPS             float64
	QPSAverage      float64
	QPSMax          float64
	QPSByListener   map[string]float64
}

type locationCount struct {
	Country  string  `json:"country"`
	Province string  `json:"province"`
	Count    float64 `json:"count"`
}

func (e *Exporter) collectStatistics(ctx context.Context) (any, error) {
	end := scrapeTime(ctx).Unix()
	query := url.Values{"begin_time": {strconv.FormatInt(end-int64(e.window.Seconds()), 10)}, "end_time": {strconv.FormatInt(end, 10)}}
	query.Set("time_preset", safeLineStatisticsPreset)
	var requests, intercepts apiResponse[[]point]
	var access apiResponse[struct {
		Access  float64 `json:"access"`
		Session float64 `json:"session"`
		IP      float64 `json:"ip"`
		PV      float64 `json:"pv"`
	}]
	var attacks apiResponse[struct {
		AttackIP  float64            `json:"attack_ip"`
		Intercept map[string]float64 `json:"intercept"`
	}]
	var qps apiResponse[struct {
		Nodes []map[string]any `json:"nodes"`
	}]
	requestsList := []struct {
		path   string
		query  url.Values
		target any
	}{
		{"/api/stat/advance/trend/access", query, &requests},
		{"/api/stat/advance/trend/intercept", query, &intercepts},
		{"/api/stat/advance/access", query, &access},
		{"/api/stat/advance/attack", query, &attacks},
		{"/api/stat/qps", url.Values{"count": {strconv.Itoa(safeLineQPSSampleCount)}}, &qps},
	}
	for _, request := range requestsList {
		if err := e.client.Get(ctx, request.path, request.query, request.target); err != nil {
			return nil, err
		}
	}
	if err := errors.Join(checkAPIError(requests), checkAPIError(intercepts), checkAPIError(access), checkAPIError(attacks), checkAPIError(qps)); err != nil {
		return nil, err
	}
	result := statisticsMetrics{
		Requests: requests.Data, Intercepts: intercepts.Data,
		Accesses: access.Data.Access, Sessions: access.Data.Session, ClientIPs: access.Data.IP, PageViews: access.Data.PV,
		AttackIPs: attacks.Data.AttackIP, InterceptByType: attacks.Data.Intercept,
		QPSByListener: make(map[string]float64),
	}
	if err := populateQPSMetrics(&result, qps.Data.Nodes); err != nil {
		return nil, err
	}
	return result, nil
}

func populateQPSMetrics(result *statisticsMetrics, nodes []map[string]any) error {
	if len(nodes) == 0 {
		return errors.New("SafeLine QPS response contains no samples")
	}
	if result.QPSByListener == nil {
		result.QPSByListener = make(map[string]float64)
	}
	for index, sample := range nodes {
		var rawSampleTotal float64
		listenerCount := 0
		for key, value := range sample {
			if key == "time" {
				continue
			}
			number, ok := value.(float64)
			if !ok {
				return fmt.Errorf("SafeLine QPS response contains a non-numeric listener count for %q", key)
			}
			listenerCount++
			rawSampleTotal += number
			if !validNonNegativeMetric(number) || !validNonNegativeMetric(rawSampleTotal) {
				return errors.New("SafeLine QPS response contains an invalid count")
			}
			if index == len(nodes)-1 {
				result.QPSByListener[key] = normalizeQPSCount(number)
			}
		}
		if listenerCount == 0 {
			return errors.New("SafeLine QPS sample contains no listener counts")
		}
		sampleTotal := normalizeQPSCount(rawSampleTotal)
		result.QPSAverage += sampleTotal
		if !validNonNegativeMetric(result.QPSAverage) {
			return errors.New("SafeLine QPS response overflows the sample aggregate")
		}
		if sampleTotal > result.QPSMax {
			result.QPSMax = sampleTotal
		}
		if index == len(nodes)-1 {
			result.QPS = sampleTotal
		}
	}
	result.QPSAverage /= float64(len(nodes))
	return nil
}

func normalizeQPSCount(rawCount float64) float64 {
	return math.Ceil(rawCount / safeLineQPSSampleSeconds)
}

type httpErrors struct {
	Errors4xx *float64 `json:"error_4xx"`
	Errors5xx *float64 `json:"error_5xx"`
}

type httpStatusCode struct {
	Code  string  `json:"status_code"`
	Count float64 `json:"count"`
}

type httpStatusSource struct {
	Errors      httpErrors
	Codes       []httpStatusCode
	ErrorsValid bool
	CodesValid  bool
}

type httpStatusMetrics struct {
	Sources map[string]httpStatusSource
}

func (e *Exporter) collectHTTPStatus(ctx context.Context) (any, error) {
	end := scrapeTime(ctx).Unix()
	baseQuery := url.Values{
		"begin_time":  {strconv.FormatInt(end-int64(e.window.Seconds()), 10)},
		"end_time":    {strconv.FormatInt(end, 10)},
		"time_preset": {safeLineStatisticsPreset},
	}
	result := httpStatusMetrics{Sources: make(map[string]httpStatusSource, 2)}
	for _, source := range []struct {
		name         string
		upstreamFlag string
	}{
		{name: "upstream", upstreamFlag: "true"},
		{name: "waf", upstreamFlag: "false"},
	} {
		errorQuery := cloneWith(baseQuery, "upstream", source.upstreamFlag)
		codeQuery := cloneWith(baseQuery, "upstream", source.upstreamFlag)
		codeQuery.Set("size", "100")
		var errorsResponse apiResponse[httpErrors]
		var codesResponse apiResponse[[]httpStatusCode]
		if err := e.client.Get(ctx, "/api/stat/advance/error_status_code", errorQuery, &errorsResponse); err != nil {
			return nil, err
		}
		if err := e.client.Get(ctx, "/api/stat/advance/status_code", codeQuery, &codesResponse); err != nil {
			return nil, err
		}
		if err := errors.Join(checkAPIError(errorsResponse), checkAPIError(codesResponse)); err != nil {
			return nil, err
		}
		entry := httpStatusSource{Errors: errorsResponse.Data, Codes: codesResponse.Data}
		entry.ErrorsValid = validHTTPErrors(entry.Errors)
		entry.CodesValid = validHTTPStatusCodes(entry.Codes)
		result.Sources[source.name] = entry
	}
	return result, nil
}

func validHTTPErrors(data httpErrors) bool {
	return data.Errors4xx != nil && data.Errors5xx != nil &&
		validNonNegativeMetric(*data.Errors4xx) && validNonNegativeMetric(*data.Errors5xx)
}

func validHTTPStatusCodes(codes []httpStatusCode) bool {
	for _, item := range codes {
		code, err := strconv.Atoi(item.Code)
		if err != nil || code < 100 || code > 599 || !validNonNegativeMetric(item.Count) {
			return false
		}
	}
	return true
}

func validNonNegativeMetric(value float64) bool {
	return value >= 0 && !math.IsNaN(value) && !math.IsInf(value, 0)
}

func cloneWith(values url.Values, key, value string) url.Values {
	clone := make(url.Values, len(values)+1)
	for existingKey, existingValues := range values {
		clone[existingKey] = append([]string(nil), existingValues...)
	}
	clone.Set(key, value)
	return clone
}

type event struct {
	IP        string  `json:"ip"`
	Country   string  `json:"country"`
	Protocol  int     `json:"protocol"`
	StartAt   int64   `json:"start_at"`
	EndAt     int64   `json:"end_at"`
	UpdatedAt int64   `json:"updated_at"`
	DenyCount float64 `json:"deny_count"`
	PassCount float64 `json:"pass_count"`
	Finished  bool    `json:"finished"`
}

type eventMetrics struct {
	Total          float64
	Fetched        int
	DenyCount      float64
	PassCount      float64
	EventSourceIPs int
	Unfinished     int
	Truncated      bool
	ByCountry      map[string]float64
	ByProtocol     map[string]float64
	DurationSum    float64
	DurationMax    float64
	DurationCount  int
	LatestAt       float64
}

func (e *Exporter) collectEvents(ctx context.Context) (any, error) {
	const pageSize = 100
	now := scrapeTime(ctx)
	end := now.UnixMilli()
	windowMilliseconds := e.window.Milliseconds()
	result := eventMetrics{ByCountry: make(map[string]float64), ByProtocol: make(map[string]float64)}
	uniqueIPs := make(map[string]struct{})
	for page := 1; ; page++ {
		query := url.Values{
			"start": {strconv.FormatInt(end-windowMilliseconds, 10)},
			"end":   {strconv.FormatInt(end, 10)},
			"page":  {strconv.Itoa(page)}, "page_size": {strconv.Itoa(pageSize)},
		}
		var response apiResponse[struct {
			Nodes []event `json:"nodes"`
			Total int     `json:"total"`
		}]
		if err := e.client.Get(ctx, "/api/open/events", query, &response); err != nil {
			return nil, err
		}
		if err := checkAPIError(response); err != nil {
			return nil, err
		}
		result.Total = float64(response.Data.Total)
		items := response.Data.Nodes
		if remaining := e.maxEvents - result.Fetched; remaining < len(items) {
			if remaining < 0 {
				remaining = 0
			}
			items = items[:remaining]
			result.Truncated = true
		}
		for _, item := range items {
			result.Fetched++
			result.DenyCount += item.DenyCount
			result.PassCount += item.PassCount
			if item.IP != "" {
				uniqueIPs[item.IP] = struct{}{}
			}
			if !item.Finished {
				result.Unfinished++
			}
			country := item.Country
			if country == "" {
				country = "unknown"
			}
			result.ByCountry[country]++
			result.ByProtocol[strconv.Itoa(item.Protocol)]++
			startSeconds := ruleTimestampSeconds(item.StartAt)
			endSeconds := ruleTimestampSeconds(item.EndAt)
			if !item.Finished {
				endSeconds = float64(now.UnixNano()) / 1e9
			}
			if startSeconds > 0 && endSeconds >= startSeconds {
				duration := endSeconds - startSeconds
				result.DurationSum += duration
				result.DurationCount++
				if duration > result.DurationMax {
					result.DurationMax = duration
				}
			}
			latest := maxRuleTimestamp(item.StartAt, item.EndAt, item.UpdatedAt)
			if latest > result.LatestAt {
				result.LatestAt = latest
			}
		}
		if len(response.Data.Nodes) == 0 || page*pageSize >= response.Data.Total {
			break
		}
		if result.Fetched >= e.maxEvents {
			result.Truncated = result.Fetched < response.Data.Total
			break
		}
	}
	result.EventSourceIPs = len(uniqueIPs)
	return result, nil
}

type attackLog struct {
	AttackType int    `json:"attack_type"`
	Action     int    `json:"action"`
	RiskLevel  int    `json:"risk_level"`
	Module     string `json:"module"`
	Country    string `json:"country"`
	Protocol   int    `json:"protocol"`
	StatusCode int    `json:"status_code"`
	Method     string `json:"method"`
	Timestamp  int64  `json:"timestamp"`
}

type attackLogMetrics struct {
	Total      int
	Fetched    int
	Truncated  bool
	ByAction   map[string]float64
	ByType     map[string]float64
	ByRisk     map[string]float64
	ByModule   map[string]float64
	ByCountry  map[string]float64
	ByProtocol map[string]float64
	ByStatus   map[string]float64
	ByMethod   map[string]float64
	LatestAt   float64
}

func (e *Exporter) collectAttackLogs(ctx context.Context) (any, error) {
	const pageSize = 100
	end := scrapeTime(ctx).UnixMilli()
	result := attackLogMetrics{
		ByAction: make(map[string]float64), ByType: make(map[string]float64), ByRisk: make(map[string]float64),
		ByModule: make(map[string]float64), ByCountry: make(map[string]float64), ByProtocol: make(map[string]float64),
		ByStatus: make(map[string]float64), ByMethod: make(map[string]float64),
	}
	for page := 1; ; page++ {
		query := url.Values{
			"start": {strconv.FormatInt(end-e.window.Milliseconds(), 10)},
			"end":   {strconv.FormatInt(end, 10)},
			"page":  {strconv.Itoa(page)}, "page_size": {strconv.Itoa(pageSize)},
		}
		var response apiResponse[struct {
			Data  []attackLog `json:"data"`
			Total int         `json:"total"`
		}]
		if err := e.client.Get(ctx, "/api/open/records", query, &response); err != nil {
			return nil, err
		}
		if err := checkAPIError(response); err != nil {
			return nil, err
		}
		result.Total = response.Data.Total
		items := response.Data.Data
		if remaining := e.maxEvents - result.Fetched; remaining < len(items) {
			if remaining < 0 {
				remaining = 0
			}
			items = items[:remaining]
			result.Truncated = true
		}
		for _, item := range items {
			result.ByAction[attackActionName(item.Action)]++
			result.ByType[strconv.Itoa(item.AttackType)]++
			result.ByRisk[strconv.Itoa(item.RiskLevel)]++
			result.ByModule[nonEmpty(item.Module, "unknown")]++
			result.ByCountry[nonEmpty(item.Country, "unknown")]++
			result.ByProtocol[strconv.Itoa(item.Protocol)]++
			result.ByStatus[httpStatusCodeName(item.StatusCode)]++
			result.ByMethod[httpMethodName(item.Method)]++
			if timestamp := ruleTimestampSeconds(item.Timestamp); timestamp > result.LatestAt {
				result.LatestAt = timestamp
			}
			result.Fetched++
		}
		if len(response.Data.Data) == 0 || page*pageSize >= response.Data.Total {
			break
		}
		if result.Fetched >= e.maxEvents {
			result.Truncated = result.Fetched < response.Data.Total
			break
		}
	}
	return result, nil
}

func attackActionName(action int) string {
	switch action {
	case 0:
		return "pass"
	case 1:
		return "deny"
	default:
		return "unknown"
	}
}

func nonEmpty(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func httpStatusCodeName(code int) string {
	if code < 100 || code > 599 {
		return "other"
	}
	return strconv.Itoa(code)
}

func httpMethodName(method string) string {
	method = strings.ToUpper(method)
	switch method {
	case "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH":
		return method
	default:
		return "OTHER"
	}
}

type certificate struct {
	ID          int      `json:"id"`
	Domains     []string `json:"domains"`
	ValidBefore string   `json:"valid_before"`
	Expired     bool     `json:"expired"`
	Revoked     bool     `json:"revoked"`
	Trusted     bool     `json:"trusted"`
}

type certificateMetrics struct{ Certificates []certificate }

func (e *Exporter) collectCertificates(ctx context.Context) (any, error) {
	var response apiResponse[struct {
		Nodes []certificate `json:"nodes"`
	}]
	if err := e.client.Get(ctx, "/api/open/cert", nil, &response); err != nil {
		return nil, err
	}
	if err := checkAPIError(response); err != nil {
		return nil, err
	}
	return certificateMetrics{response.Data.Nodes}, nil
}

func writeSystem(m *metricWriter, data systemMetrics) {
	m.metric("safeline_info", "SafeLine version information.", "gauge", map[string]string{"version": data.Version}, 1)
	m.metric("safeline_outdated", "Whether SafeLine reports that this version is outdated.", "gauge", nil, boolFloat(data.Outdated))
	m.metric("safeline_deprecated", "Whether SafeLine reports that this version is deprecated.", "gauge", nil, boolFloat(data.Deprecated))
	m.metric("safeline_license_valid", "Whether the SafeLine license is valid.", "gauge", nil, boolFloat(data.License))
	m.metric("safeline_system_oversea", "Whether SafeLine is running in overseas mode.", "gauge", nil, boolFloat(data.Oversea))
	m.metric("safeline_system_slave", "Whether this SafeLine instance is a slave node.", "gauge", nil, boolFloat(data.Slave))
	m.metric("safeline_system_staging", "Whether this SafeLine instance is in staging mode.", "gauge", nil, boolFloat(data.Staging))
	m.metric("safeline_password_expiry_days", "Days until the management password expires, as reported by SafeLine.", "gauge", nil, data.PasswordExpireDays)
	if data.CreatedAt > 0 {
		m.metric("safeline_system_created_timestamp_seconds", "SafeLine system creation time as a Unix timestamp.", "gauge", nil, float64(data.CreatedAt))
	}
}

func writeHealth(m *metricWriter, data healthMetrics) {
	m.metric("safeline_up", "Whether the SafeLine health endpoint is reachable and reports ok.", "gauge", nil, boolFloat(data.Up))
}

func writeSites(m *metricWriter, data siteMetrics) {
	m.metric("safeline_sites", "Number of configured SafeLine sites.", "gauge", nil, float64(data.Total))
	m.metric("safeline_sites_syncing", "Whether SafeLine site configuration is currently syncing.", "gauge", nil, boolFloat(data.Syncing))
	for _, site := range data.Sites {
		name := strings.Join(site.ServerNames, ",")
		labels := map[string]string{"id": strconv.Itoa(site.ID), "site": name, "mode": siteModeName(site.Mode)}
		m.metric("safeline_site_info", "SafeLine site information and current run mode.", "gauge", labels, 1)
		m.metric("safeline_site_statistics_enabled", "Whether statistics are enabled for the SafeLine site.", "gauge", labels, boolFloat(site.StatEnabled))
		for upstream, health := range site.HealthState {
			m.metric("safeline_site_upstream_health_state", "Raw SafeLine upstream health state for a site.", "gauge", map[string]string{"id": strconv.Itoa(site.ID), "site": name, "upstream": upstream}, float64(health.State))
		}
	}
}

func siteModeName(mode int) string {
	switch mode {
	case 0:
		return "defense"
	case 1:
		return "offline"
	case 2:
		return "dry_run"
	default:
		return "unknown"
	}
}

func sumPoints(points []point) float64 {
	var total float64
	for _, item := range points {
		total += item.Count
	}
	return total
}

func latestPoint(points []point) point {
	if len(points) == 0 {
		return point{}
	}
	return points[len(points)-1]
}

func writeStatistics(m *metricWriter, data statisticsMetrics, window time.Duration) {
	windowLabel := map[string]string{"window": window.String()}
	m.metric("safeline_requests_window", "Requests observed in the configured rolling window.", "gauge", windowLabel, data.Accesses)
	m.metric("safeline_unique_visitors_window", "Unique visitors observed in the configured rolling window.", "gauge", windowLabel, data.Sessions)
	m.metric("safeline_unique_client_ips_window", "Unique client IPs observed in the configured rolling window.", "gauge", windowLabel, data.ClientIPs)
	m.metric("safeline_page_views_window", "Page views observed in the configured rolling window.", "gauge", windowLabel, data.PageViews)
	m.metric("safeline_intercepts_window", "Intercepted requests in the configured rolling window.", "gauge", windowLabel, sumPoints(data.Intercepts))
	m.metric("safeline_unique_attack_ips_window", "Unique attack IPs reported by SafeLine in the configured rolling window.", "gauge", windowLabel, data.AttackIPs)
	var securityActions float64
	for action, count := range data.InterceptByType {
		securityActions += count
		m.metric("safeline_security_actions_window", "SafeLine security actions by type in the configured rolling window.", "gauge", map[string]string{"window": window.String(), "type": action}, count)
	}
	m.metric("safeline_security_actions_total_window", "Total SafeLine security actions in the configured rolling window.", "gauge", windowLabel, securityActions)
	m.metric("safeline_qps", "Latest total SafeLine requests per second.", "gauge", nil, data.QPS)
	m.metric("safeline_qps_recent_average", "Average total QPS across samples returned by SafeLine.", "gauge", nil, data.QPSAverage)
	m.metric("safeline_qps_recent_max", "Maximum total QPS across samples returned by SafeLine.", "gauge", nil, data.QPSMax)
	for listener, value := range data.QPSByListener {
		m.metric("safeline_qps_by_listener", "Latest SafeLine QPS by listener.", "gauge", map[string]string{"listener": listener}, value)
	}
	req := latestPoint(data.Requests)
	intercept := latestPoint(data.Intercepts)
	m.metric("safeline_requests_latest_bucket", "Requests in the latest SafeLine statistics bucket.", "gauge", nil, req.Count)
	m.metric("safeline_intercepts_latest_bucket", "Intercepts in the latest SafeLine statistics bucket.", "gauge", nil, intercept.Count)
	m.metric("safeline_statistics_latest_bucket_timestamp_seconds", "Unix timestamp of the latest SafeLine statistics bucket.", "gauge", map[string]string{"series": "requests"}, float64(req.Time))
	m.metric("safeline_statistics_latest_bucket_timestamp_seconds", "Unix timestamp of the latest SafeLine statistics bucket.", "gauge", map[string]string{"series": "intercepts"}, float64(intercept.Time))
}

func writeHTTPStatus(m *metricWriter, data httpStatusMetrics, window time.Duration) {
	for source, item := range data.Sources {
		m.metric("safeline_http_status_data_valid", "Whether SafeLine aggregate HTTP error data passed validation.", "gauge", map[string]string{"source": source}, boolFloat(item.ErrorsValid))
		m.metric("safeline_http_status_code_data_valid", "Whether SafeLine HTTP status-code data passed validation.", "gauge", map[string]string{"source": source}, boolFloat(item.CodesValid))
		if item.ErrorsValid {
			m.metric("safeline_http_responses_window", "HTTP error responses by source and status class in the configured rolling window.", "gauge", map[string]string{"source": source, "window": window.String(), "class": "4xx"}, *item.Errors.Errors4xx)
			m.metric("safeline_http_responses_window", "HTTP error responses by source and status class in the configured rolling window.", "gauge", map[string]string{"source": source, "window": window.String(), "class": "5xx"}, *item.Errors.Errors5xx)
		}
		if item.CodesValid {
			for _, code := range item.Codes {
				m.metric("safeline_http_status_code_responses_window", "HTTP responses by source and status code in the configured rolling window.", "gauge", map[string]string{"source": source, "window": window.String(), "code": code.Code}, code.Count)
			}
		}
	}
}

func writeEvents(m *metricWriter, data eventMetrics, window time.Duration) {
	labels := map[string]string{"window": window.String()}
	m.metric("safeline_attack_events_window", "Attack events in the configured rolling window.", "gauge", labels, data.Total)
	m.metric("safeline_attack_events_fetched", "Attack events fetched for aggregation in the last scrape.", "gauge", nil, float64(data.Fetched))
	m.metric("safeline_attack_requests_window", "Requests grouped into attack events in the configured rolling window.", "gauge", map[string]string{"window": window.String(), "action": "deny"}, data.DenyCount)
	m.metric("safeline_attack_requests_window", "Requests grouped into attack events in the configured rolling window.", "gauge", map[string]string{"window": window.String(), "action": "pass"}, data.PassCount)
	m.metric("safeline_attack_event_source_ips_window", "Unique source IPs represented by fetched attack events.", "gauge", labels, float64(data.EventSourceIPs))
	m.metric("safeline_unfinished_attack_events_window", "Unfinished attack events in the configured rolling window.", "gauge", labels, float64(data.Unfinished))
	m.metric("safeline_attack_events_truncated", "Whether attack event pagination hit the configured limit.", "gauge", nil, boolFloat(data.Truncated))
	for country, count := range data.ByCountry {
		m.metric("safeline_attack_events_by_country_window", "Attack events by source country in the configured rolling window.", "gauge", map[string]string{"window": window.String(), "country": country}, count)
	}
	for protocol, count := range data.ByProtocol {
		m.metric("safeline_attack_events_by_protocol_window", "Attack events by SafeLine protocol value in the configured rolling window.", "gauge", map[string]string{"window": window.String(), "protocol": protocol}, count)
	}
	m.metric("safeline_attack_event_duration_samples_window", "Attack events with a valid duration in the configured rolling window.", "gauge", labels, float64(data.DurationCount))
	durationAverage := float64(0)
	if data.DurationCount > 0 {
		durationAverage = data.DurationSum / float64(data.DurationCount)
	}
	m.metric("safeline_attack_event_duration_seconds", "Attack event duration statistics in the configured rolling window.", "gauge", map[string]string{"window": window.String(), "statistic": "average"}, durationAverage)
	m.metric("safeline_attack_event_duration_seconds", "Attack event duration statistics in the configured rolling window.", "gauge", map[string]string{"window": window.String(), "statistic": "maximum"}, data.DurationMax)
	if data.LatestAt > 0 {
		m.metric("safeline_attack_event_latest_timestamp_seconds", "Timestamp of the latest fetched attack event.", "gauge", nil, data.LatestAt)
	}
}

func writeAttackLogs(m *metricWriter, data attackLogMetrics, window time.Duration) {
	windowLabel := map[string]string{"window": window.String()}
	m.metric("safeline_attack_logs_window", "Raw attack log records in the configured rolling window.", "gauge", windowLabel, float64(data.Total))
	m.metric("safeline_attack_logs_fetched", "Attack log records fetched for aggregation in the last scrape.", "gauge", nil, float64(data.Fetched))
	m.metric("safeline_attack_logs_truncated", "Whether attack log pagination hit the configured limit.", "gauge", nil, boolFloat(data.Truncated))
	for action, count := range data.ByAction {
		m.metric("safeline_attack_log_records_by_action_window", "Attack log records by action in the configured rolling window.", "gauge", map[string]string{"window": window.String(), "action": action}, count)
	}
	for attackType, count := range data.ByType {
		m.metric("safeline_attack_log_records_by_type_window", "Attack log records by SafeLine attack type in the configured rolling window.", "gauge", map[string]string{"window": window.String(), "attack_type": attackType}, count)
	}
	for risk, count := range data.ByRisk {
		m.metric("safeline_attack_log_records_by_risk_window", "Attack log records by risk level in the configured rolling window.", "gauge", map[string]string{"window": window.String(), "risk_level": risk}, count)
	}
	for module, count := range data.ByModule {
		m.metric("safeline_attack_log_records_by_module_window", "Attack log records by detection module in the configured rolling window.", "gauge", map[string]string{"window": window.String(), "module": module}, count)
	}
	for country, count := range data.ByCountry {
		m.metric("safeline_attack_log_records_by_country_window", "Attack log records by source country in the configured rolling window.", "gauge", map[string]string{"window": window.String(), "country": country}, count)
	}
	for protocol, count := range data.ByProtocol {
		m.metric("safeline_attack_log_records_by_protocol_window", "Attack log records by SafeLine protocol value in the configured rolling window.", "gauge", map[string]string{"window": window.String(), "protocol": protocol}, count)
	}
	for code, count := range data.ByStatus {
		m.metric("safeline_attack_log_records_by_status_code_window", "Attack log records by HTTP status code in the configured rolling window.", "gauge", map[string]string{"window": window.String(), "code": code}, count)
	}
	for method, count := range data.ByMethod {
		m.metric("safeline_attack_log_records_by_method_window", "Attack log records by normalized HTTP method in the configured rolling window.", "gauge", map[string]string{"window": window.String(), "method": method}, count)
	}
	if data.LatestAt > 0 {
		m.metric("safeline_attack_log_latest_timestamp_seconds", "Timestamp of the latest fetched attack log record.", "gauge", nil, data.LatestAt)
	}
}

func writeCertificates(m *metricWriter, data certificateMetrics) {
	m.metric("safeline_certificates", "Number of certificates managed by SafeLine.", "gauge", nil, float64(len(data.Certificates)))
	for _, cert := range data.Certificates {
		labels := map[string]string{"id": strconv.Itoa(cert.ID), "domains": strings.Join(cert.Domains, ",")}
		m.metric("safeline_certificate_expired", "Whether the certificate is expired.", "gauge", labels, boolFloat(cert.Expired))
		m.metric("safeline_certificate_revoked", "Whether the certificate is revoked.", "gauge", labels, boolFloat(cert.Revoked))
		m.metric("safeline_certificate_trusted", "Whether the certificate is trusted.", "gauge", labels, boolFloat(cert.Trusted))
		expires, err := parseSafeLineTime(cert.ValidBefore)
		m.metric("safeline_certificate_expiry_parse_success", "Whether the certificate expiration time was parsed successfully.", "gauge", labels, boolFloat(err == nil))
		if err == nil {
			m.metric("safeline_certificate_expiry_timestamp_seconds", "Certificate expiration time as a Unix timestamp.", "gauge", labels, float64(expires.Unix()))
			m.metric("safeline_certificate_expiry_seconds", "Seconds until certificate expiration.", "gauge", labels, time.Until(expires).Seconds())
		}
	}
}

func parseSafeLineTime(value string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, fmt.Errorf("unsupported time %q", value)
}
