package config

import (
	"io"
	"testing"
	"time"
)

func TestParseAndValidate(t *testing.T) {
	t.Setenv("SAFELINE_ADDRESS", "https://safeline.example")
	t.Setenv("SAFELINE_API_TOKEN", "test-token")

	cfg, showVersion, err := Parse(nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if showVersion {
		t.Fatal("unexpected version mode")
	}
	if cfg.Window != SupportedStatisticsWindow || cfg.ListenAddress != ":9719" || cfg.MaxEvents != 10000 || cfg.ScrapeTimeout != 25*time.Second || cfg.AllowHTTP {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}

	cfg.Window = 48 * time.Hour
	if err := cfg.Validate(); err == nil {
		t.Fatal("unsupported statistics window accepted")
	}
}

func TestParseRejectsInvalidEnvironment(t *testing.T) {
	t.Setenv("SAFELINE_EXPORTER_MAX_EVENTS", "not-a-number")
	if _, _, err := Parse(nil, io.Discard); err == nil {
		t.Fatal("invalid max-events environment value accepted")
	}
}
