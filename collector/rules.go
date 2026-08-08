package collector

import (
	"context"
	"net/url"
	"strconv"
	"time"
)

const ruleLogPageSize = 100

type ruleEvent struct {
	IP        string `json:"ip"`
	DenyCount int    `json:"deny_count"`
	PassCount int    `json:"pass_count"`
	Finished  bool   `json:"finished"`
	StartAt   int64  `json:"start_at"`
	EndAt     int64  `json:"end_at"`
	UpdatedAt int64  `json:"updated_at"`
}

type ruleEventMetrics struct {
	Total                  int
	Fetched                int
	DenyCount              int
	PassCount              int
	EventSourceIPs         int
	Unfinished             int
	LatestTimestampSeconds float64
	DurationSamples        int
	DurationAverageSeconds float64
	DurationMaxSeconds     float64
	Truncated              bool
}

func (e *Exporter) collectRuleEvents(ctx context.Context) (any, error) {
	now := scrapeTime(ctx)
	end := now.UnixMilli()
	result := ruleEventMetrics{}
	uniqueIPs := make(map[string]struct{})
	var durationTotal float64

	for page := 1; ; page++ {
		query := url.Values{
			"start":     {strconv.FormatInt(end-e.window.Milliseconds(), 10)},
			"end":       {strconv.FormatInt(end, 10)},
			"page":      {strconv.Itoa(page)},
			"page_size": {strconv.Itoa(ruleLogPageSize)},
		}
		var response apiResponse[struct {
			Nodes []ruleEvent `json:"nodes"`
			Total int         `json:"total"`
		}]
		if err := e.client.Get(ctx, "/api/open/events/rule", query, &response); err != nil {
			return nil, err
		}
		if err := checkAPIError(response); err != nil {
			return nil, err
		}

		result.Total = response.Data.Total
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

			latest := maxRuleTimestamp(item.StartAt, item.EndAt, item.UpdatedAt)
			if latest > result.LatestTimestampSeconds {
				result.LatestTimestampSeconds = latest
			}
			if duration, ok := ruleEventDurationSeconds(item, now); ok {
				result.DurationSamples++
				durationTotal += duration
				if duration > result.DurationMaxSeconds {
					result.DurationMaxSeconds = duration
				}
			}
		}

		if len(response.Data.Nodes) == 0 || page*ruleLogPageSize >= response.Data.Total {
			break
		}
		if result.Fetched >= e.maxEvents {
			result.Truncated = result.Fetched < response.Data.Total
			break
		}
	}

	result.EventSourceIPs = len(uniqueIPs)
	if result.DurationSamples > 0 {
		result.DurationAverageSeconds = durationTotal / float64(result.DurationSamples)
	}
	return result, nil
}

func writeRuleEvents(m *metricWriter, data ruleEventMetrics, window time.Duration) {
	windowLabel := map[string]string{"window": window.String()}
	m.metric("safeline_rule_attack_events_window", "Black- or white-list rule attack events in the configured rolling window.", "gauge", windowLabel, float64(data.Total))
	m.metric("safeline_rule_attack_events_fetched", "Rule attack events fetched for aggregation in the last scrape.", "gauge", nil, float64(data.Fetched))
	m.metric("safeline_rule_attack_requests_window", "Requests grouped into rule attack events in the configured rolling window.", "gauge", map[string]string{"window": window.String(), "action": "deny"}, float64(data.DenyCount))
	m.metric("safeline_rule_attack_requests_window", "Requests grouped into rule attack events in the configured rolling window.", "gauge", map[string]string{"window": window.String(), "action": "pass"}, float64(data.PassCount))
	m.metric("safeline_rule_attack_event_source_ips_window", "Unique source IPs represented by fetched rule attack events.", "gauge", windowLabel, float64(data.EventSourceIPs))
	m.metric("safeline_rule_unfinished_attack_events_window", "Unfinished rule attack events in the configured rolling window.", "gauge", windowLabel, float64(data.Unfinished))
	m.metric("safeline_rule_attack_event_duration_samples_window", "Rule attack events with a valid duration in the configured rolling window.", "gauge", windowLabel, float64(data.DurationSamples))
	m.metric("safeline_rule_attack_event_duration_seconds", "Rule attack event duration calculated over fetched events.", "gauge", map[string]string{"window": window.String(), "statistic": "average"}, data.DurationAverageSeconds)
	m.metric("safeline_rule_attack_event_duration_seconds", "Rule attack event duration calculated over fetched events.", "gauge", map[string]string{"window": window.String(), "statistic": "maximum"}, data.DurationMaxSeconds)
	if data.LatestTimestampSeconds > 0 {
		m.metric("safeline_rule_attack_event_latest_timestamp_seconds", "Latest timestamp represented by fetched rule attack events.", "gauge", nil, data.LatestTimestampSeconds)
	}
	m.metric("safeline_rule_attack_events_truncated", "Whether rule attack event pagination hit the configured limit.", "gauge", nil, boolFloat(data.Truncated))
}

type ruleLog struct {
	Action     int    `json:"action"`
	AttackType int    `json:"attack_type"`
	RiskLevel  int    `json:"risk_level"`
	Module     string `json:"module"`
	Country    string `json:"country"`
	Protocol   int    `json:"protocol"`
	StatusCode int    `json:"status_code"`
	Method     string `json:"method"`
	Timestamp  int64  `json:"timestamp"`
}

type ruleLogMetrics struct {
	Total                  int
	Fetched                int
	LatestTimestampSeconds float64
	ByAction               map[string]float64
	ByType                 map[string]float64
	ByRisk                 map[string]float64
	ByModule               map[string]float64
	ByCountry              map[string]float64
	ByProtocol             map[string]float64
	ByStatusCode           map[string]float64
	ByMethod               map[string]float64
	Truncated              bool
}

func newRuleLogMetrics() ruleLogMetrics {
	return ruleLogMetrics{
		ByAction:     make(map[string]float64),
		ByType:       make(map[string]float64),
		ByRisk:       make(map[string]float64),
		ByModule:     make(map[string]float64),
		ByCountry:    make(map[string]float64),
		ByProtocol:   make(map[string]float64),
		ByStatusCode: make(map[string]float64),
		ByMethod:     make(map[string]float64),
	}
}

func (e *Exporter) collectRuleLogs(ctx context.Context) (any, error) {
	end := scrapeTime(ctx).UnixMilli()
	result := newRuleLogMetrics()

	for page := 1; ; page++ {
		query := url.Values{
			"start":     {strconv.FormatInt(end-e.window.Milliseconds(), 10)},
			"end":       {strconv.FormatInt(end, 10)},
			"page":      {strconv.Itoa(page)},
			"page_size": {strconv.Itoa(ruleLogPageSize)},
		}
		var response apiResponse[struct {
			Data  []ruleLog `json:"data"`
			Total int       `json:"total"`
		}]
		if err := e.client.Get(ctx, "/api/open/records/rule", query, &response); err != nil {
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
			result.Fetched++
			result.ByAction[attackActionName(item.Action)]++
			result.ByType[strconv.Itoa(item.AttackType)]++
			result.ByRisk[strconv.Itoa(item.RiskLevel)]++
			result.ByModule[nonEmpty(item.Module, "unknown")]++
			result.ByCountry[nonEmpty(item.Country, "unknown")]++
			result.ByProtocol[strconv.Itoa(item.Protocol)]++
			result.ByStatusCode[httpStatusCodeName(item.StatusCode)]++
			result.ByMethod[httpMethodName(item.Method)]++
			if timestamp := ruleTimestampSeconds(item.Timestamp); timestamp > result.LatestTimestampSeconds {
				result.LatestTimestampSeconds = timestamp
			}
		}

		if len(response.Data.Data) == 0 || page*ruleLogPageSize >= response.Data.Total {
			break
		}
		if result.Fetched >= e.maxEvents {
			result.Truncated = result.Fetched < response.Data.Total
			break
		}
	}

	return result, nil
}

func writeRuleLogs(m *metricWriter, data ruleLogMetrics, window time.Duration) {
	windowLabel := map[string]string{"window": window.String()}
	m.metric("safeline_rule_attack_logs_window", "Black- or white-list rule attack log records in the configured rolling window.", "gauge", windowLabel, float64(data.Total))
	m.metric("safeline_rule_attack_logs_fetched", "Rule attack log records fetched for aggregation in the last scrape.", "gauge", nil, float64(data.Fetched))
	writeRuleLogDimension(m, "safeline_rule_attack_log_records_by_action_window", "Rule attack log records by action in the configured rolling window.", "action", data.ByAction, window)
	writeRuleLogDimension(m, "safeline_rule_attack_log_records_by_type_window", "Rule attack log records by SafeLine attack type in the configured rolling window.", "attack_type", data.ByType, window)
	writeRuleLogDimension(m, "safeline_rule_attack_log_records_by_risk_window", "Rule attack log records by risk level in the configured rolling window.", "risk_level", data.ByRisk, window)
	writeRuleLogDimension(m, "safeline_rule_attack_log_records_by_module_window", "Rule attack log records by detection module in the configured rolling window.", "module", data.ByModule, window)
	writeRuleLogDimension(m, "safeline_rule_attack_log_records_by_country_window", "Rule attack log records by source country in the configured rolling window.", "country", data.ByCountry, window)
	writeRuleLogDimension(m, "safeline_rule_attack_log_records_by_protocol_window", "Rule attack log records by protocol in the configured rolling window.", "protocol", data.ByProtocol, window)
	writeRuleLogDimension(m, "safeline_rule_attack_log_records_by_status_code_window", "Rule attack log records by HTTP status code in the configured rolling window.", "code", data.ByStatusCode, window)
	writeRuleLogDimension(m, "safeline_rule_attack_log_records_by_method_window", "Rule attack log records by normalized HTTP method in the configured rolling window.", "method", data.ByMethod, window)
	if data.LatestTimestampSeconds > 0 {
		m.metric("safeline_rule_attack_log_latest_timestamp_seconds", "Latest timestamp represented by fetched rule attack logs.", "gauge", nil, data.LatestTimestampSeconds)
	}
	m.metric("safeline_rule_attack_logs_truncated", "Whether rule attack log pagination hit the configured limit.", "gauge", nil, boolFloat(data.Truncated))
}

func writeRuleLogDimension(m *metricWriter, name, help, labelName string, values map[string]float64, window time.Duration) {
	for value, count := range values {
		m.metric(name, help, "gauge", map[string]string{"window": window.String(), labelName: value}, count)
	}
}

func maxRuleTimestamp(values ...int64) float64 {
	var latest float64
	for _, value := range values {
		if seconds := ruleTimestampSeconds(value); seconds > latest {
			latest = seconds
		}
	}
	return latest
}

func ruleTimestampSeconds(value int64) float64 {
	switch {
	case value <= 0:
		return 0
	case value >= 1e18:
		return float64(value) / 1e9
	case value >= 1e15:
		return float64(value) / 1e6
	case value >= 1e12:
		return float64(value) / 1e3
	default:
		return float64(value)
	}
}

func ruleEventDurationSeconds(item ruleEvent, now time.Time) (float64, bool) {
	start := ruleTimestampSeconds(item.StartAt)
	if start <= 0 {
		return 0, false
	}
	end := ruleTimestampSeconds(item.EndAt)
	if !item.Finished {
		end = float64(now.UnixNano()) / 1e9
	}
	if end < start {
		return 0, false
	}
	return end - start, true
}
