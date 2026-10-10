package httpapi

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"bannerfingerprint/internal/fingerprint"
)

type testIdentifier struct {
	calls atomic.Int64
}

func (id *testIdentifier) Identify(input fingerprint.Input) fingerprint.Result {
	id.calls.Add(1)
	result := fingerprint.Result{IP: input.IP, Port: input.Port, Protocol: "unknown"}
	if strings.HasPrefix(input.Banner, "SSH-") {
		result.Protocol = "SSH"
		result.Product = "OpenSSH"
		result.Version = "8.9p1"
		result.Confidence = 0.95
	}
	return result
}

func testHandler(id Identifier, limits Limits) http.Handler {
	return New(id, limits, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestBatchPreservesOrderAndUnknown(t *testing.T) {
	id := &testIdentifier{}
	server := httptest.NewServer(testHandler(id, DefaultLimits()))
	t.Cleanup(server.Close)
	response, err := server.Client().Post(server.URL+"/fingerprint", "application/json", strings.NewReader(`[{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1"},{"ip":"2001:db8::1","port":12345,"banner":"QUIT\r\n"}]`))
	if err != nil {
		t.Fatal(err)
	}
	defer closeBody(t, response.Body)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}
	var results []fingerprint.Result
	if err := json.NewDecoder(response.Body).Decode(&results); err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || results[0].IP != "1.2.3.4" || results[0].Protocol != "SSH" || results[1].IP != "2001:db8::1" || results[1].Protocol != "unknown" {
		t.Fatalf("unexpected results: %+v", results)
	}
	if id.calls.Load() != 2 {
		t.Fatalf("recognition calls = %d, want 2", id.calls.Load())
	}
}

func TestEmptyBatchIsJSONArray(t *testing.T) {
	w := httptest.NewRecorder()
	testHandler(&testIdentifier{}, DefaultLimits()).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/fingerprint", strings.NewReader("[]")))
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatalf("response = %d %q, want 200 []", w.Code, w.Body.String())
	}
}

func TestInvalidRequestsDoNotRecognizeAnyItem(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		limits Limits
		status int
	}{
		{name: "null", body: "null", status: 400},
		{name: "object", body: `{}`, status: 400},
		{name: "empty body", body: "", status: 400},
		{name: "bad JSON", body: `[`, status: 400},
		{name: "trailing value", body: `[] {}`, status: 400},
		{name: "trailing garbage", body: `[] garbage`, status: 400},
		{name: "invalid IP", body: `[{"ip":"invalid","port":22,"banner":"SSH-2.0-x"}]`, status: 400},
		{name: "missing IP", body: `[{"port":22,"banner":"SSH-2.0-x"}]`, status: 400},
		{name: "zero port", body: `[{"ip":"1.2.3.4","port":0,"banner":"SSH-2.0-x"}]`, status: 400},
		{name: "large port", body: `[{"ip":"1.2.3.4","port":65536,"banner":"SSH-2.0-x"}]`, status: 400},
		{name: "fractional port", body: `[{"ip":"1.2.3.4","port":22.5,"banner":"SSH-2.0-x"}]`, status: 400},
		{name: "bad base64", body: `[{"ip":"1.2.3.4","port":22,"banner_base64":"%%%"}]`, status: 400},
		{name: "two encodings", body: `[{"ip":"1.2.3.4","port":22,"banner":"x","banner_base64":"eA=="}]`, status: 400},
		{name: "unknown field", body: `[{"ip":"1.2.3.4","port":22,"baner":"SSH-2.0-x"}]`, status: 400},
		{name: "null item", body: `[null]`, status: 400},
		{name: "invalid second item", body: `[{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-x"},{"ip":"invalid","port":22,"banner":"x"}]`, status: 400},
		{name: "banner too large", body: `[{"ip":"1.2.3.4","port":22,"banner":"12345"}]`, limits: Limits{MaxBannerBytes: 4}, status: 400},
		{name: "decoded banner too large", body: `[{"ip":"1.2.3.4","port":22,"banner_base64":"MTIzNDU="}]`, limits: Limits{MaxBannerBytes: 4}, status: 400},
		{name: "batch too large", body: `[{},{}]`, limits: Limits{MaxBatchSize: 1}, status: 413},
		{name: "body too large", body: `[{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-x"}]`, limits: Limits{MaxBodyBytes: 16}, status: 413},
		{name: "padding too large", body: `[]` + strings.Repeat(" ", 20), limits: Limits{MaxBodyBytes: 16}, status: 413},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			id := &testIdentifier{}
			w := httptest.NewRecorder()
			testHandler(id, test.limits).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/fingerprint", strings.NewReader(test.body)))
			if w.Code != test.status {
				t.Fatalf("status = %d, want %d; body = %s", w.Code, test.status, w.Body.String())
			}
			if id.calls.Load() != 0 {
				t.Fatalf("recognition called %d times on invalid batch", id.calls.Load())
			}
			var errorResponse struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &errorResponse); err != nil || errorResponse.Error == "" {
				t.Fatalf("expected helpful JSON error, got %q (%v)", w.Body.String(), err)
			}
		})
	}
}

func TestBase64IsDecodedBeforeRecognition(t *testing.T) {
	w := httptest.NewRecorder()
	testHandler(&testIdentifier{}, DefaultLimits()).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/fingerprint", strings.NewReader(`[{"ip":"1.2.3.4","port":22,"banner_base64":"U1NILTIuMC1PcGVuU1NIXzguOXAx"}]`)))
	var results []fingerprint.Result
	if err := json.Unmarshal(w.Body.Bytes(), &results); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK || len(results) != 1 || results[0].Protocol != "SSH" {
		t.Fatalf("base64 response = %d %s", w.Code, w.Body.String())
	}
}

func TestHealthAndMethods(t *testing.T) {
	handler := testHandler(&testIdentifier{}, DefaultLimits())
	for _, test := range []struct {
		method string
		path   string
		status int
	}{
		{method: http.MethodGet, path: "/health", status: 200},
		{method: http.MethodPost, path: "/health", status: 405},
		{method: http.MethodGet, path: "/fingerprint", status: 405},
		{method: http.MethodGet, path: "/missing", status: 404},
	} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(test.method, test.path, nil))
		if w.Code != test.status {
			t.Errorf("%s %s status = %d, want %d", test.method, test.path, w.Code, test.status)
		}
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/fingerprint", strings.NewReader("[]"))
	r.Header.Set("Content-Type", "text/plain")
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("invalid content type status = %d, want 415", w.Code)
	}
}

type blockingIdentifier struct {
	started chan struct{}
	release chan struct{}
}

func (id *blockingIdentifier) Identify(input fingerprint.Input) fingerprint.Result {
	close(id.started)
	<-id.release
	return fingerprint.Result{IP: input.IP, Port: input.Port, Protocol: "unknown"}
}

func TestAdmissionLimitDoesNotBlockHealth(t *testing.T) {
	id := &blockingIdentifier{started: make(chan struct{}), release: make(chan struct{})}
	handler := testHandler(id, Limits{MaxConcurrent: 1})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/fingerprint", strings.NewReader(`[{"ip":"1.2.3.4","port":1234,"banner":"x"}]`)))
	}()
	<-id.started
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/fingerprint", strings.NewReader("[]")))
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") == "" {
		t.Errorf("overloaded response = %d, want 503 with Retry-After", w.Code)
	}
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/health", nil))
	if w.Code != http.StatusOK {
		t.Errorf("overloaded health status = %d, want 200", w.Code)
	}
	close(id.release)
	<-finished
}

func closeBody(t *testing.T, body io.Closer) {
	t.Helper()
	if err := body.Close(); err != nil {
		t.Errorf("close response body: %v", err)
	}
}
