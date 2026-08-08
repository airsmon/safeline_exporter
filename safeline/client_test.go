package safeline

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientGet(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-SLCE-API-TOKEN") != "test-token" {
			t.Error("missing API token")
		}
		if r.Header.Get("User-Agent") != "safeline_exporter/test" {
			t.Errorf("unexpected user agent %q", r.Header.Get("User-Agent"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
	}))
	defer server.Close()

	client, err := NewClient(Options{Address: server.URL, Token: "test-token", Timeout: time.Second, AllowHTTP: true, UserAgent: "safeline_exporter/test"})
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		Status string `json:"status"`
	}
	if err := client.Get(context.Background(), "/api/open/health", nil, &response); err != nil {
		t.Fatal(err)
	}
	if response.Status != "ok" {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func TestClientRejectsPlainHTTPByDefault(t *testing.T) {
	if _, err := NewClient(Options{Address: "http://safeline.example", Timeout: time.Second}); err == nil {
		t.Fatal("plain HTTP address accepted without explicit opt-in")
	}
}

func TestClientDoesNotFollowRedirects(t *testing.T) {
	var redirectedRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectedRequests.Add(1)
		if r.Header.Get("X-SLCE-API-TOKEN") != "" {
			t.Error("API token was forwarded to redirect target")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	source := httptest.NewServer(http.RedirectHandler(target.URL, http.StatusFound))
	defer source.Close()
	client, err := NewClient(Options{Address: source.URL, Token: "test-token", Timeout: time.Second, AllowHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	var response any
	err = client.Get(context.Background(), "/api/open/health", nil, &response)
	if err == nil || !strings.Contains(err.Error(), "HTTP 302") {
		t.Fatalf("expected redirect rejection, got %v", err)
	}
	if redirectedRequests.Load() != 0 {
		t.Fatalf("redirect target received %d requests", redirectedRequests.Load())
	}
}
