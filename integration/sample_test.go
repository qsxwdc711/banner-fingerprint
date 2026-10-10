// Package integration verifies the shipped example through the real HTTP API.
package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"bannerfingerprint/internal/fingerprint"
	"bannerfingerprint/internal/httpapi"
)

func TestShippedSampleThroughHTTP(t *testing.T) {
	engine, err := fingerprint.Load("../rules/fingerprints.json")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("../samples/banners.json")
	if err != nil {
		t.Fatal(err)
	}
	var inputs []fingerprint.Input
	if err := json.Unmarshal(data, &inputs); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(httpapi.New(engine, httpapi.DefaultLimits(), nil))
	defer server.Close()
	resp, err := server.Client().Post(server.URL+"/fingerprint", "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var results []fingerprint.Result
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		t.Fatal(err)
	}
	if len(results) != 20 || len(results) != len(inputs) {
		t.Fatalf("result length = %d, inputs = %d, want 20", len(results), len(inputs))
	}
	want := []fingerprint.Result{
		{IP: "1.2.3.4", Port: 22, Protocol: "SSH", Product: "OpenSSH", Version: "8.9p1", OSHint: "Ubuntu", Confidence: 0.95},
		{IP: "1.2.3.5", Port: 80, Protocol: "HTTP", Product: "nginx", Version: "1.24.0", Confidence: 0.9},
		{IP: "1.2.3.6", Port: 443, Protocol: "HTTP", Product: "Apache", Version: "2.4.57", Confidence: 0.9},
		{IP: "1.2.3.7", Port: 3306, Protocol: "MySQL", Product: "MySQL", Version: "8.0.32", Confidence: 0.9},
		{IP: "1.2.3.8", Port: 6379, Protocol: "Redis", Product: "Redis", Confidence: 0.7},
		{IP: "1.2.3.9", Port: 21, Protocol: "FTP", Product: "ProFTPD", Version: "1.3.7", Confidence: 0.9},
		{IP: "1.2.3.10", Port: 8080, Protocol: "HTTP", Product: "Jetty", Version: "9.4.51", Confidence: 0.85},
	}
	for i, expected := range want {
		if results[i] != expected {
			t.Errorf("result[%d] = %+v, want %+v", i, results[i], expected)
		}
	}
	for i, result := range results {
		if result.IP != inputs[i].IP || result.Port != inputs[i].Port {
			t.Errorf("result[%d] changed endpoint or input order: %+v", i, result)
		}
		if result.Confidence < 0 || result.Confidence > 1 {
			t.Errorf("result[%d] confidence = %g, want [0,1]", i, result.Confidence)
		}
	}
	for _, index := range []int{15, 19} {
		result := results[index]
		if result.Protocol != "unknown" || result.Product != "" || result.Version != "" || result.OSHint != "" || result.Confidence != 0 {
			t.Errorf("unrecognized result[%d] = %+v, want unknown with empty details", index, result)
		}
	}
}
