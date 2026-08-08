package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"testing"
	"time"
)

type responseClient map[string]string

func (c responseClient) Get(_ context.Context, path string, _ url.Values, target any) error {
	body, ok := c[path]
	if !ok {
		return fmt.Errorf("unexpected path %s", path)
	}
	return json.Unmarshal([]byte(body), target)
}

func TestCollectExtendedSystem(t *testing.T) {
	client := responseClient{
		"/api/open/system/arch":           `{"data":"amd64","err":null,"msg":""}`,
		"/api/open/system/edition":        `{"data":{"version":2,"licensed_edition":2,"effective_edition":1,"state":"valid"},"err":null,"msg":""}`,
		"/api/open/system/license/status": `{"data":{"state":"valid","expired_at":1893456000,"days_until_expiry":30,"license_expiry_phase":"30d","prompt_type":"expiring_30d","river_disconnected_duration":12,"licensed_edition":2,"effective_edition":1},"err":null,"msg":""}`,
		"/api/open/system/protocol":       `{"data":true,"err":null,"msg":""}`,
		"/api/open/detector":              `{"data":{"mode":1},"err":null,"msg":""}`,
		"/api/open/global/mode":           `{"data":{"semantics":{"m_sqli":"block","m_xss":"audit"}},"err":null,"msg":""}`,
	}

	result, err := New(client, 0, 0, time.Second, nil).collectExtendedSystem(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	metrics := result.(extendedSystemMetrics)
	if metrics.Arch != "amd64" || metrics.EditionVersion != 2 || metrics.LicenseState != "valid" {
		t.Fatalf("unexpected system metrics: %+v", metrics)
	}
	if metrics.LicenseDaysUntilExpiry != 30 || metrics.LicenseExpiredAt != 1893456000 || !metrics.ProtocolEnabled {
		t.Fatalf("unexpected license/protocol metrics: %+v", metrics)
	}
	if metrics.SemanticModuleModes["m_sqli"] != "block" || metrics.SemanticModuleModes["m_xss"] != "audit" {
		t.Fatalf("unexpected semantic modes: %+v", metrics.SemanticModuleModes)
	}
}

func TestAPIResponseRequiresData(t *testing.T) {
	var response apiResponse[map[string]any]
	if err := json.Unmarshal([]byte(`{"err":null,"msg":""}`), &response); err != nil {
		t.Fatal(err)
	}
	if err := checkAPIError(response); err == nil {
		t.Fatal("missing data accepted as a successful API response")
	}
}
