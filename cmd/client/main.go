// Command client sends a local JSON batch to the fingerprint service.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"bannerfingerprint/internal/fingerprint"
)

const maxInputBytes = 8 << 20

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "client: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("client", flag.ContinueOnError)
	input := flags.String("input", "samples/banners.json", "input JSON array file")
	server := flags.String("server", "http://localhost:8080", "server base URL")
	timeout := flags.Duration("timeout", 30*time.Second, "request timeout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments; use -input and -server")
	}
	if *timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	endpoint, err := url.Parse(*server)
	if err != nil || endpoint.Host == "" || (endpoint.Scheme != "http" && endpoint.Scheme != "https") {
		return fmt.Errorf("server must be an absolute http or https URL")
	}
	if endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.User != nil {
		return fmt.Errorf("server URL must not contain credentials, a query, or a fragment")
	}
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/fingerprint"
	file, err := os.Open(*input)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(file, maxInputBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return fmt.Errorf("read input: %w", readErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close input: %w", closeErr)
	}
	if len(body) > maxInputBytes {
		return fmt.Errorf("input file exceeds %d bytes", maxInputBytes)
	}
	var batch []fingerprint.Input
	if err := json.Unmarshal(body, &batch); err != nil {
		return fmt.Errorf("input must be a JSON array: %w", err)
	}
	if batch == nil {
		return fmt.Errorf("input must be a JSON array; null is not accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: *timeout}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("request fingerprint service: %w", err)
	}
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, maxInputBytes+1))
	closeErr = response.Body.Close()
	if readErr != nil {
		return fmt.Errorf("read server response: %w", readErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close server response: %w", closeErr)
	}
	if len(responseBody) > maxInputBytes {
		return fmt.Errorf("server response exceeds %d bytes", maxInputBytes)
	}
	if response.StatusCode != http.StatusOK {
		// JSON error payloads are printed as quoted text to keep terminal escape
		// sequences from arbitrary upstream responses from executing.
		return fmt.Errorf("server returned HTTP %d: %q", response.StatusCode, strings.TrimSpace(string(responseBody)))
	}
	var results []fingerprint.Result
	if err := json.Unmarshal(responseBody, &results); err != nil {
		return fmt.Errorf("decode server results: %w", err)
	}
	if results == nil || len(results) != len(batch) {
		return fmt.Errorf("server returned an invalid result count: got %d, expected %d", len(results), len(batch))
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		return fmt.Errorf("display results: %w", err)
	}
	return nil
}
