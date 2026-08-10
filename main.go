package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	prometheusCollectors "github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"safeline_exporter/collector"
	"safeline_exporter/config"
	"safeline_exporter/safeline"
)

var (
	version   = "0.3.0"
	revision  = "unknown"
	buildDate = "unknown"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	cfg, showVersion, err := config.Parse(os.Args[1:], os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	if showVersion {
		fmt.Printf("safeline_exporter %s (revision=%s, build_date=%s)\n", version, revision, buildDate)
		return nil
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	client, err := safeline.NewClient(safeline.Options{
		Address:            cfg.Address,
		Token:              cfg.Token,
		Timeout:            cfg.Timeout,
		InsecureSkipVerify: cfg.Insecure,
		AllowHTTP:          cfg.AllowHTTP,
		UserAgent:          "safeline_exporter/" + version,
	})
	if err != nil {
		return err
	}

	registry := prometheus.NewRegistry()
	registry.MustRegister(
		collector.New(client, cfg.Window, cfg.MaxEvents, cfg.ScrapeTimeout, logger),
		prometheusCollectors.NewGoCollector(),
		prometheusCollectors.NewProcessCollector(prometheusCollectors.ProcessCollectorOpts{}),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Namespace: "safeline_exporter",
			Name:      "build_info",
			Help:      "Build information for safeline_exporter.",
			ConstLabels: prometheus.Labels{
				"version":    version,
				"revision":   revision,
				"build_date": buildDate,
				"go_version": runtime.Version(),
			},
		}, func() float64 { return 1 }),
	)

	metricsHandler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{EnableOpenMetrics: true})
	metricsHandler = promhttp.InstrumentMetricHandler(registry, metricsHandler)
	mux := http.NewServeMux()
	mux.Handle(cfg.MetricsPath, metricsHandler)
	mux.HandleFunc("/-/healthy", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ok\n")
	})
	if cfg.MetricsPath != "/" {
		mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = fmt.Fprintf(w, "SafeLine Exporter\n\nVersion: %s\nMetrics: %s\n", version, cfg.MetricsPath)
		})
	}

	server := &http.Server{
		Addr:              cfg.ListenAddress,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("starting safeline_exporter", "version", version, "listen_address", cfg.ListenAddress)
		serverErrors <- server.ListenAndServe()
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdownContext)
	case err := <-serverErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
