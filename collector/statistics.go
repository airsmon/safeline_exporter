package collector

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"time"
)

type extendedStatisticsMetrics struct {
	SecurityPosture []extendedSecurityPostureCount
	AntiTamper      float64
	Clients         []extendedClientCount
	Locations       []extendedLocationCount
}

type extendedSecurityPostureCount struct {
	Category string
	Action   string
	Count    float64
}

type extendedClientCount struct {
	Kind  string
	Name  string
	Count float64
}

type extendedLocationCount struct {
	Scope    string
	Traffic  string
	Country  string
	Province string
	Count    float64
}

type securityPostureStatistics struct {
	ACLHit         float64             `json:"acl_hit"`
	AntiTamper     []map[string]string `json:"anti_tamper"`
	AttackAllow    float64             `json:"attack_allow"`
	AttackDeny     float64             `json:"attack_deny"`
	AuthAllow      float64             `json:"auth_allow"`
	AuthDeny       float64             `json:"auth_deny"`
	BlackAllow     float64             `json:"black_allow"`
	BlackDeny      float64             `json:"black_deny"`
	BlackHit       float64             `json:"black_hit"`
	ChallengeAllow float64             `json:"challenge_allow"`
	ChallengeDeny  float64             `json:"challenge_deny"`
	WaitingHit     float64             `json:"waiting_hit"`
	WhiteHit       float64             `json:"white_hit"`
}

type extendedClientStatistics struct {
	OS []struct {
		Name  string  `json:"os"`
		Count float64 `json:"count"`
	} `json:"OS"`
	Browser []struct {
		Name  string  `json:"browser"`
		Count float64 `json:"count"`
	} `json:"Browser"`
}

func (e *Exporter) collectExtendedStatistics(ctx context.Context) (any, error) {
	end := scrapeTime(ctx).Unix()
	baseQuery := url.Values{
		"begin_time":  {strconv.FormatInt(end-int64(e.window.Seconds()), 10)},
		"end_time":    {strconv.FormatInt(end, 10)},
		"time_preset": {safeLineStatisticsPreset},
	}

	var posture apiResponse[securityPostureStatistics]
	if err := e.client.Get(ctx, "/api/open/security_posture/statistics", baseQuery, &posture); err != nil {
		return nil, err
	}
	if err := checkAPIError(posture); err != nil {
		return nil, err
	}

	clientQuery := cloneWith(baseQuery, "size", "20")
	var clients apiResponse[extendedClientStatistics]
	if err := e.client.Get(ctx, "/api/stat/advance/client", clientQuery, &clients); err != nil {
		return nil, err
	}
	if err := checkAPIError(clients); err != nil {
		return nil, err
	}

	antiTamper, err := sumAntiTamperEvents(posture.Data.AntiTamper)
	if err != nil {
		return nil, err
	}

	result := extendedStatisticsMetrics{
		SecurityPosture: []extendedSecurityPostureCount{
			{Category: "attack", Action: "allow", Count: posture.Data.AttackAllow},
			{Category: "attack", Action: "deny", Count: posture.Data.AttackDeny},
			{Category: "blacklist", Action: "allow", Count: posture.Data.BlackAllow},
			{Category: "blacklist", Action: "deny", Count: posture.Data.BlackDeny},
			{Category: "blacklist", Action: "hit", Count: posture.Data.BlackHit},
			{Category: "whitelist", Action: "hit", Count: posture.Data.WhiteHit},
			{Category: "acl", Action: "hit", Count: posture.Data.ACLHit},
			{Category: "waiting_room", Action: "hit", Count: posture.Data.WaitingHit},
			{Category: "challenge", Action: "allow", Count: posture.Data.ChallengeAllow},
			{Category: "challenge", Action: "deny", Count: posture.Data.ChallengeDeny},
			{Category: "auth", Action: "allow", Count: posture.Data.AuthAllow},
			{Category: "auth", Action: "deny", Count: posture.Data.AuthDeny},
		},
		AntiTamper: antiTamper,
	}
	for _, item := range clients.Data.OS {
		result.Clients = append(result.Clients, extendedClientCount{Kind: "os", Name: labelOrUnknown(item.Name), Count: item.Count})
	}
	for _, item := range clients.Data.Browser {
		result.Clients = append(result.Clients, extendedClientCount{Kind: "browser", Name: labelOrUnknown(item.Name), Count: item.Count})
	}

	locationQueries := []struct {
		global  bool
		action  int
		scope   string
		traffic string
	}{
		{global: false, action: -1, scope: "province", traffic: "requests"},
		{global: false, action: 1, scope: "province", traffic: "intercepts"},
		{global: true, action: -1, scope: "country", traffic: "requests"},
		{global: true, action: 1, scope: "country", traffic: "intercepts"},
	}
	for _, locationQuery := range locationQueries {
		query := cloneWith(baseQuery, "global", strconv.FormatBool(locationQuery.global))
		query.Set("action", strconv.Itoa(locationQuery.action))
		query.Set("page", "1")
		query.Set("size", "-1")
		var locations apiResponse[[]locationCount]
		if err := e.client.Get(ctx, "/api/stat/advance/location", query, &locations); err != nil {
			return nil, err
		}
		if err := checkAPIError(locations); err != nil {
			return nil, err
		}
		for _, item := range locations.Data {
			result.Locations = append(result.Locations, extendedLocationCount{
				Scope:    locationQuery.scope,
				Traffic:  locationQuery.traffic,
				Country:  labelOrUnknown(item.Country),
				Province: item.Province,
				Count:    item.Count,
			})
		}
	}

	return result, nil
}

func sumAntiTamperEvents(groups []map[string]string) (float64, error) {
	var total float64
	for _, group := range groups {
		if len(group) != 1 {
			return 0, fmt.Errorf("invalid SafeLine anti-tamper record with %d fields", len(group))
		}
		for _, rawCount := range group {
			count, err := strconv.ParseFloat(rawCount, 64)
			if err != nil || !validNonNegativeMetric(count) {
				return 0, fmt.Errorf("invalid SafeLine anti-tamper count %q", rawCount)
			}
			total += count
			if !validNonNegativeMetric(total) {
				return 0, fmt.Errorf("SafeLine anti-tamper count overflow")
			}
		}
	}
	return total, nil
}

func labelOrUnknown(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}

func writeExtendedStatistics(m *metricWriter, data extendedStatisticsMetrics, window time.Duration) {
	windowValue := window.String()
	for _, item := range data.SecurityPosture {
		m.metric("safeline_security_posture_events_window", "Security posture events by category and action in the configured rolling window.", "gauge", map[string]string{
			"window": windowValue, "category": item.Category, "action": item.Action,
		}, item.Count)
	}
	m.metric("safeline_anti_tamper_events_window", "Anti-tamper events in the configured rolling window.", "gauge", map[string]string{"window": windowValue}, data.AntiTamper)
	for _, item := range data.Clients {
		m.metric("safeline_client_requests_window", "Requests grouped by parsed client type in the configured rolling window.", "gauge", map[string]string{
			"window": windowValue, "kind": item.Kind, "name": item.Name,
		}, item.Count)
	}
	for _, item := range data.Locations {
		m.metric("safeline_traffic_by_location_window", "Traffic grouped by geographic scope and request disposition in the configured rolling window.", "gauge", map[string]string{
			"window": windowValue, "scope": item.Scope, "traffic": item.Traffic, "country": item.Country, "province": item.Province,
		}, item.Count)
	}
}
