// Command server exposes the batch fingerprint HTTP service and its health probe.
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
	"syscall"
	"time"

	"bannerfingerprint/internal/fingerprint"
	"bannerfingerprint/internal/httpapi"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(logger); err != nil {
		logger.Error("server failed", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	listen := flag.String("listen", ":8080", "HTTP listen address")
	rules := flag.String("rules", "rules/fingerprints.json", "fingerprint rule JSON path")
	healthcheck := flag.String("healthcheck", "", "probe this health URL and exit")
	flag.Parse()
	if *healthcheck != "" {
		return probeHealth(*healthcheck)
	}
	engine, err := fingerprint.Load(*rules)
	if err != nil {
		return fmt.Errorf("load fingerprint rules: %w", err)
	}
	server := &http.Server{
		Addr:              *listen,
		Handler:           httpapi.New(engine, httpapi.DefaultLimits(), logger),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	serveErrors := make(chan error, 1)
	go func() {
		serveErrors <- server.ListenAndServe()
	}()
	logger.Info("HTTP server starting", "listen", *listen, "rules", *rules)
	select {
	case err := <-serveErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve HTTP: %w", err)
	case <-ctx.Done():
		logger.Info("HTTP server shutting down")
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		if closeErr := server.Close(); closeErr != nil {
			logger.Error("force close failed", "error", closeErr)
		}
		return fmt.Errorf("shutdown HTTP: %w", err)
	}
	if err := <-serveErrors; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve HTTP: %w", err)
	}
	return nil
}

func probeHealth(url string) error {
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("health probe: %w", err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			slog.Debug("health response close failed", "error", err)
		}
	}()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("health probe returned HTTP %d", response.StatusCode)
	}
	if _, err := io.Copy(io.Discard, io.LimitReader(response.Body, 4096)); err != nil {
		return fmt.Errorf("read health response: %w", err)
	}
	return nil
}
