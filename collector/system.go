package collector

import (
	"context"
	"strconv"
)

type extendedSystemMetrics struct {
	Arch                      string
	EditionVersion            int
	LicensedEdition           *int
	EffectiveEdition          *int
	EditionState              string
	LicenseState              string
	LicenseExpiredAt          int64
	LicenseDaysUntilExpiry    float64
	LicenseExpiryPhase        string
	LicensePromptType         string
	RiverDisconnectedDuration float64
	ProtocolEnabled           bool
	DetectorMode              int
	SemanticModuleModes       map[string]string
}

func (e *Exporter) collectExtendedSystem(ctx context.Context) (any, error) {
	var arch apiResponse[string]
	if err := e.client.Get(ctx, "/api/open/system/arch", nil, &arch); err != nil {
		return nil, err
	}
	if err := checkAPIError(arch); err != nil {
		return nil, err
	}

	var edition apiResponse[struct {
		Version          int    `json:"version"`
		LicensedEdition  *int   `json:"licensed_edition"`
		EffectiveEdition *int   `json:"effective_edition"`
		State            string `json:"state"`
	}]
	if err := e.client.Get(ctx, "/api/open/system/edition", nil, &edition); err != nil {
		return nil, err
	}
	if err := checkAPIError(edition); err != nil {
		return nil, err
	}

	var license apiResponse[struct {
		State                     string  `json:"state"`
		ExpiredAt                 int64   `json:"expired_at"`
		DaysUntilExpiry           float64 `json:"days_until_expiry"`
		LicenseExpiryPhase        string  `json:"license_expiry_phase"`
		PromptType                string  `json:"prompt_type"`
		RiverDisconnectedDuration float64 `json:"river_disconnected_duration"`
		LicensedEdition           *int    `json:"licensed_edition"`
		EffectiveEdition          *int    `json:"effective_edition"`
	}]
	if err := e.client.Get(ctx, "/api/open/system/license/status", nil, &license); err != nil {
		return nil, err
	}
	if err := checkAPIError(license); err != nil {
		return nil, err
	}

	var protocol apiResponse[bool]
	if err := e.client.Get(ctx, "/api/open/system/protocol", nil, &protocol); err != nil {
		return nil, err
	}
	if err := checkAPIError(protocol); err != nil {
		return nil, err
	}

	var detector apiResponse[struct {
		Mode int `json:"mode"`
	}]
	if err := e.client.Get(ctx, "/api/open/detector", nil, &detector); err != nil {
		return nil, err
	}
	if err := checkAPIError(detector); err != nil {
		return nil, err
	}

	var globalMode apiResponse[struct {
		Semantics map[string]string `json:"semantics"`
	}]
	if err := e.client.Get(ctx, "/api/open/global/mode", nil, &globalMode); err != nil {
		return nil, err
	}
	if err := checkAPIError(globalMode); err != nil {
		return nil, err
	}

	licensedEdition := license.Data.LicensedEdition
	if licensedEdition == nil {
		licensedEdition = edition.Data.LicensedEdition
	}
	effectiveEdition := license.Data.EffectiveEdition
	if effectiveEdition == nil {
		effectiveEdition = edition.Data.EffectiveEdition
	}

	return extendedSystemMetrics{
		Arch:                      arch.Data,
		EditionVersion:            edition.Data.Version,
		LicensedEdition:           licensedEdition,
		EffectiveEdition:          effectiveEdition,
		EditionState:              edition.Data.State,
		LicenseState:              license.Data.State,
		LicenseExpiredAt:          license.Data.ExpiredAt,
		LicenseDaysUntilExpiry:    license.Data.DaysUntilExpiry,
		LicenseExpiryPhase:        license.Data.LicenseExpiryPhase,
		LicensePromptType:         license.Data.PromptType,
		RiverDisconnectedDuration: license.Data.RiverDisconnectedDuration,
		ProtocolEnabled:           protocol.Data,
		DetectorMode:              detector.Data.Mode,
		SemanticModuleModes:       globalMode.Data.Semantics,
	}, nil
}

func writeExtendedSystem(m *metricWriter, data extendedSystemMetrics) {
	m.metric("safeline_system_arch_info", "SafeLine system architecture information.", "gauge", map[string]string{"arch": data.Arch}, 1)
	m.metric("safeline_system_edition_info", "SafeLine configured and effective edition information.", "gauge", map[string]string{
		"version":           strconv.Itoa(data.EditionVersion),
		"licensed_edition":  optionalIntMetricLabel(data.LicensedEdition),
		"effective_edition": optionalIntMetricLabel(data.EffectiveEdition),
		"state":             data.EditionState,
	}, 1)
	m.metric("safeline_license_info", "SafeLine license state information.", "gauge", map[string]string{
		"state":             data.LicenseState,
		"expiry_phase":      data.LicenseExpiryPhase,
		"prompt_type":       data.LicensePromptType,
		"licensed_edition":  optionalIntMetricLabel(data.LicensedEdition),
		"effective_edition": optionalIntMetricLabel(data.EffectiveEdition),
	}, 1)
	m.metric("safeline_license_days_until_expiry", "Days until the SafeLine license expires; negative values indicate elapsed days.", "gauge", nil, data.LicenseDaysUntilExpiry)
	if data.LicenseExpiredAt > 0 {
		m.metric("safeline_license_expiry_timestamp_seconds", "Unix timestamp when the SafeLine license expires.", "gauge", nil, float64(data.LicenseExpiredAt))
	}
	m.metric("safeline_license_river_disconnected_duration_seconds", "Duration for which the SafeLine license service has been disconnected.", "gauge", nil, data.RiverDisconnectedDuration)
	m.metric("safeline_management_protocol_enabled", "Whether the SafeLine management protocol has been accepted or enabled.", "gauge", nil, boolFloat(data.ProtocolEnabled))
	m.metric("safeline_detector_mode_info", "SafeLine detector mode information.", "gauge", map[string]string{"mode": strconv.Itoa(data.DetectorMode)}, 1)
	for module, mode := range data.SemanticModuleModes {
		m.metric("safeline_semantic_module_info", "SafeLine global semantic detection mode by bounded module.", "gauge", map[string]string{"module": module, "mode": mode}, 1)
	}
}

func optionalIntMetricLabel(value *int) string {
	if value == nil {
		return "unknown"
	}
	return strconv.Itoa(*value)
}
