package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClientSendsFileAndPrintsResults(t *testing.T) {
	inputBody := `[{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1"}]`
	path := writeInput(t, inputBody)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/fingerprint" || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected request %s %s %s", r.Method, r.URL.Path, r.Header.Get("Content-Type"))
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != inputBody {
			t.Errorf("request body = %q, want %q (error %v)", body, inputBody, err)
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := io.WriteString(w, `[{"ip":"1.2.3.4","port":22,"protocol":"SSH","product":"OpenSSH","version":"8.9p1","os_hint":"","confidence":0.95}]`); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	var output bytes.Buffer
	if err := run([]string{"-input", path, "-server", server.URL + "/"}, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"protocol": "SSH"`) || !strings.Contains(output.String(), `"confidence": 0.95`) {
		t.Fatalf("unexpected client output: %s", output.String())
	}
}

func TestClientReportsServerError(t *testing.T) {
	path := writeInput(t, "[]")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		if _, err := io.WriteString(w, `{"error":"invalid batch"}`); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	if err := run([]string{"-input", path, "-server", server.URL}, io.Discard); err == nil || !strings.Contains(err.Error(), "HTTP 400") {
		t.Fatalf("error = %v, want useful HTTP 400 error", err)
	}
}

func TestClientRequestTimeout(t *testing.T) {
	path := writeInput(t, "[]")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			return
		}
		// A client disconnect is not always visible to net/http before a body
		// read. Bound this fixture independently so server.Close cannot hang.
		timer := time.NewTimer(200 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-r.Context().Done():
		case <-timer.C:
		}
	}))
	t.Cleanup(server.Close)
	if err := run([]string{"-input", path, "-server", server.URL, "-timeout", "20ms"}, io.Discard); err == nil || !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("timeout error = %v, want context deadline exceeded", err)
	}
}

func TestClientRejectsInvalidInputAndURL(t *testing.T) {
	for _, body := range []string{"null", "{}", "[] []", `[{"port":"22"}]`} {
		path := writeInput(t, body)
		if err := run([]string{"-input", path}, io.Discard); err == nil {
			t.Errorf("input %q unexpectedly succeeded", body)
		}
	}
	if err := run([]string{"-server", "file:///tmp/server"}, io.Discard); err == nil {
		t.Error("non-HTTP server unexpectedly succeeded")
	}
	if err := run([]string{"-timeout", "0s"}, io.Discard); err == nil {
		t.Error("zero timeout unexpectedly succeeded")
	}
}

func TestClientRejectsMalformedResults(t *testing.T) {
	path := writeInput(t, "[]")
	for _, body := range []string{"null", "{}", "[] []", `[{"protocol":"SSH"}]`} {
		t.Run(body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if _, err := io.WriteString(w, body); err != nil {
					t.Errorf("write response: %v", err)
				}
			}))
			defer server.Close()
			if err := run([]string{"-input", path, "-server", server.URL}, io.Discard); err == nil {
				t.Errorf("malformed response %q unexpectedly succeeded", body)
			}
		})
	}
}

func writeInput(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
