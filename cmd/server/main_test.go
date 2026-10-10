package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthProbeAcceptsHealthyServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" || r.Method != http.MethodGet {
			t.Errorf("probe request = %s %s, want GET /health", r.Method, r.URL.Path)
		}
		if _, err := io.WriteString(w, `{"status":"ok"}`); err != nil {
			t.Errorf("write health: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	if err := probeHealth(server.URL + "/health"); err != nil {
		t.Fatalf("healthy probe failed: %v", err)
	}
}

func TestHealthProbeRejectsUnreadyServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)
	if err := probeHealth(server.URL + "/health"); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("probe error = %v, want unhealthy HTTP 503", err)
	}
}

func TestHealthProbeRejectsInvalidURL(t *testing.T) {
	if err := probeHealth("://invalid"); err == nil {
		t.Fatal("invalid probe URL unexpectedly succeeded")
	}
}
