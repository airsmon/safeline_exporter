package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

const SupportedStatisticsWindow = 24 * time.Hour

type Config struct {
	Address       string
	Token         string
	ListenAddress string
	MetricsPath   string
	Window        time.Duration
	Timeout       time.Duration
	ScrapeTimeout time.Duration
	MaxEvents     int
	Insecure      bool
	AllowHTTP     bool
}

func Parse(args []string, output io.Writer) (Config, bool, error) {
	window, err := envDuration("SAFELINE_EXPORTER_WINDOW", SupportedStatisticsWindow)
	if err != nil {
		return Config{}, false, err
	}
	timeout, err := envDuration("SAFELINE_TIMEOUT", 15*time.Second)
	if err != nil {
		return Config{}, false, err
	}
	scrapeTimeout, err := envDuration("SAFELINE_EXPORTER_SCRAPE_TIMEOUT", 25*time.Second)
	if err != nil {
		return Config{}, false, err
	}
	maxEvents, err := envInt("SAFELINE_EXPORTER_MAX_EVENTS", 10000)
	if err != nil {
		return Config{}, false, err
	}
	insecure, err := envBool("SAFELINE_INSECURE_SKIP_VERIFY", false)
	if err != nil {
		return Config{}, false, err
	}
	allowHTTP, err := envBool("SAFELINE_ALLOW_HTTP", false)
	if err != nil {
		return Config{}, false, err
	}

	cfg := Config{}
	flags := flag.NewFlagSet("safeline_exporter", flag.ContinueOnError)
	flags.SetOutput(output)
	flags.StringVar(&cfg.Address, "safeline.address", env("SAFELINE_ADDRESS", ""), "SafeLine base URL")
	flags.StringVar(&cfg.Token, "safeline.token", env("SAFELINE_API_TOKEN", ""), "SafeLine API token")
	flags.StringVar(&cfg.ListenAddress, "web.listen-address", env("SAFELINE_EXPORTER_LISTEN_ADDRESS", ":9719"), "HTTP listen address")
	flags.StringVar(&cfg.MetricsPath, "web.telemetry-path", env("SAFELINE_EXPORTER_METRICS_PATH", "/metrics"), "Metrics path")
	flags.DurationVar(&cfg.Window, "collector.window", window, "Rolling statistics window (currently 24h only)")
	flags.DurationVar(&cfg.Timeout, "safeline.timeout", timeout, "SafeLine request timeout")
	flags.DurationVar(&cfg.ScrapeTimeout, "collector.scrape-timeout", scrapeTimeout, "Maximum duration of one complete SafeLine scrape")
	flags.IntVar(&cfg.MaxEvents, "collector.max-events", maxEvents, "Maximum events read per scrape")
	flags.BoolVar(&cfg.Insecure, "safeline.insecure-skip-verify", insecure, "Skip SafeLine TLS certificate verification")
	flags.BoolVar(&cfg.AllowHTTP, "safeline.allow-http", allowHTTP, "Allow the API token to be sent over plain HTTP")
	showVersion := flags.Bool("version", false, "Print version")
	if err := flags.Parse(args); err != nil {
		return Config{}, false, err
	}
	if *showVersion {
		return cfg, true, nil
	}
	return cfg, false, cfg.Validate()
}

func (c Config) Validate() error {
	if c.Address == "" || c.Token == "" {
		return errors.New("safeline.address and safeline.token are required")
	}
	if c.Window != SupportedStatisticsWindow {
		return errors.New("collector.window must be 24h: the tested SafeLine statistics APIs return a fixed last1Day window")
	}
	if c.Timeout <= 0 {
		return errors.New("safeline.timeout must be greater than zero")
	}
	if c.ScrapeTimeout <= 0 {
		return errors.New("collector.scrape-timeout must be greater than zero")
	}
	if c.MaxEvents <= 0 {
		return errors.New("collector.max-events must be greater than zero")
	}
	if c.ListenAddress == "" {
		return errors.New("web.listen-address must not be empty")
	}
	if !strings.HasPrefix(c.MetricsPath, "/") {
		return errors.New("web.telemetry-path must start with /")
	}
	if c.MetricsPath == "/-/healthy" {
		return errors.New("web.telemetry-path conflicts with /-/healthy")
	}
	return nil
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func envDuration(name string, fallback time.Duration) (time.Duration, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %w", name, err)
	}
	return parsed, nil
}

func envInt(name string, fallback int) (int, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %w", name, err)
	}
	return parsed, nil
}

func envBool(name string, fallback bool) (bool, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("invalid %s: %w", name, err)
	}
	return parsed, nil
}
