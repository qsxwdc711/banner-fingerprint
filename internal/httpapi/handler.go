// Package httpapi provides the bounded HTTP transport for banner recognition.
package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"time"

	"bannerfingerprint/internal/fingerprint"
)

// Identifier is the recognition dependency consumed by the HTTP handler.
type Identifier interface {
	Identify(fingerprint.Input) fingerprint.Result
}

// Limits bound memory and work for requests to the public endpoint.
type Limits struct {
	MaxBodyBytes   int64
	MaxBatchSize   int
	MaxBannerBytes int
	MaxConcurrent  int
}

// DefaultLimits returns conservative limits for the standalone service.
func DefaultLimits() Limits {
	return Limits{
		MaxBodyBytes:   8 << 20,
		MaxBatchSize:   10000,
		MaxBannerBytes: 64 << 10,
		MaxConcurrent:  4,
	}
}

type handler struct {
	identifier Identifier
	limits     Limits
	logger     *slog.Logger
	inflight   chan struct{}
}

// New returns a handler only after the caller has loaded a valid rule engine.
// Health probes bypass the request admission limit so overload does not hide
// readiness. The engine must be immutable and safe for concurrent calls.
func New(identifier Identifier, limits Limits, logger *slog.Logger) http.Handler {
	defaults := DefaultLimits()
	if limits.MaxBodyBytes <= 0 {
		limits.MaxBodyBytes = defaults.MaxBodyBytes
	}
	if limits.MaxBatchSize <= 0 {
		limits.MaxBatchSize = defaults.MaxBatchSize
	}
	if limits.MaxBannerBytes <= 0 {
		limits.MaxBannerBytes = defaults.MaxBannerBytes
	}
	if limits.MaxConcurrent <= 0 {
		limits.MaxConcurrent = defaults.MaxConcurrent
	}
	if logger == nil {
		logger = slog.Default()
	}
	h := &handler{identifier: identifier, limits: limits, logger: logger, inflight: make(chan struct{}, limits.MaxConcurrent)}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", h.health)
	mux.HandleFunc("/fingerprint", h.fingerprint)
	return mux
}

func (h *handler) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		h.writeError(w, http.StatusMethodNotAllowed, "method must be GET")
		return
	}
	h.writeJSON(w, http.StatusOK, struct {
		Status string `json:"status"`
	}{Status: "ok"})
}

func (h *handler) fingerprint(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		h.writeError(w, http.StatusMethodNotAllowed, "method must be POST")
		return
	}
	if contentType := r.Header.Get("Content-Type"); contentType != "" {
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err != nil || mediaType != "application/json" {
			h.writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
			return
		}
	}
	select {
	case h.inflight <- struct{}{}:
		defer func() { <-h.inflight }()
	default:
		w.Header().Set("Retry-After", "1")
		h.writeError(w, http.StatusServiceUnavailable, "too many concurrent batches; retry later")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, h.limits.MaxBodyBytes)
	defer func() {
		if err := r.Body.Close(); err != nil {
			h.logger.Debug("request body close failed", "error", err)
		}
	}()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	opening, err := decoder.Token()
	if err != nil {
		h.decodeError(w, err)
		return
	}
	if opening != json.Delim('[') {
		h.writeError(w, http.StatusBadRequest, "request must be a JSON array; null is not accepted")
		return
	}
	inputs := make([]fingerprint.Input, 0)
	for decoder.More() {
		// Stop at the batch limit while decoding instead of first allocating an
		// arbitrarily large slice of empty or malformed input records.
		if len(inputs) >= h.limits.MaxBatchSize {
			h.writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("batch exceeds %d items", h.limits.MaxBatchSize))
			return
		}
		var input fingerprint.Input
		if err := decoder.Decode(&input); err != nil {
			h.decodeError(w, err)
			return
		}
		inputs = append(inputs, input)
	}
	if _, err := decoder.Token(); err != nil {
		h.decodeError(w, err)
		return
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			h.writeError(w, http.StatusBadRequest, "only one JSON array is allowed")
		} else {
			h.decodeError(w, err)
		}
		return
	}
	// Validate the entire batch before recognition: callers never receive a
	// successful partial result after an invalid record.
	for i := range inputs {
		if err := validateInput(&inputs[i], h.limits.MaxBannerBytes); err != nil {
			h.writeError(w, http.StatusBadRequest, fmt.Sprintf("item %d: %v", i, err))
			return
		}
	}
	results := make([]fingerprint.Result, len(inputs))
	for i, input := range inputs {
		if err := r.Context().Err(); err != nil {
			h.logger.Debug("batch request canceled", "items", len(inputs), "error", err)
			return
		}
		results[i] = h.identifier.Identify(input)
	}
	h.writeJSON(w, http.StatusOK, results)
	h.logger.Info("batch recognized", "items", len(inputs), "elapsed_ms", time.Since(started).Milliseconds())
}

func validateInput(input *fingerprint.Input, maxBannerBytes int) error {
	if net.ParseIP(input.IP) == nil {
		return errors.New("ip must be a valid IPv4 or IPv6 address")
	}
	if input.Port < 1 || input.Port > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	if input.BannerBase64 != "" {
		if input.Banner != "" {
			return errors.New("provide banner or banner_base64, not both")
		}
		if base64.StdEncoding.DecodedLen(len(input.BannerBase64)) > maxBannerBytes+2 {
			return fmt.Errorf("decoded banner exceeds %d bytes", maxBannerBytes)
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(input.BannerBase64)
		if err != nil {
			return errors.New("banner_base64 must contain valid standard base64")
		}
		input.Banner = string(decoded)
		input.BannerBase64 = ""
	}
	if len(input.Banner) > maxBannerBytes {
		return fmt.Errorf("banner exceeds %d bytes", maxBannerBytes)
	}
	return nil
}

func (h *handler) decodeError(w http.ResponseWriter, err error) {
	var oversized *http.MaxBytesError
	if errors.As(err, &oversized) {
		h.writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("request body exceeds %d bytes", h.limits.MaxBodyBytes))
		return
	}
	// Decoder errors contain field names and byte offsets, but never echo raw
	// banners, which may contain credentials or arbitrary terminal sequences.
	h.writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON request: %v", err))
}

func (h *handler) writeError(w http.ResponseWriter, status int, message string) {
	h.writeJSON(w, status, struct {
		Error string `json:"error"`
	}{Error: message})
}

func (h *handler) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		h.logger.Debug("response write failed", "error", err)
	}
}
