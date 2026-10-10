# Banner fingerprint implementation plan

**Goal:** Deliver and publish a self-contained Go client/server fingerprint system within the requested 30-minute window.

**Architecture:** Stateless HTTP transport calls an immutable fingerprint engine loaded from external JSON rules. Independent server/client binaries share a module and run in separate hardened Compose services.

**Tech Stack:** Go 1.23 standard library, Docker multi-stage builds, Docker Compose and GitHub CLI.

- [x] Implement internal/fingerprint types, external rule loading, framing, identification and table/fuzz tests. Contract: Load(path) returns an engine; Identify(Input) returns Result without an identification error.
- [x] Implement internal/httpapi and cmd/server with batch validation, healthcheck mode, HTTP timeouts and graceful shutdown. Test with httptest using real requests.
- [x] Implement cmd/client with JSON file input, request deadline, HTTP error handling and formatted output.
- [x] Add rules/fingerprints.json, samples/banners.json, Dockerfile, compose.yaml, ignore files, Chinese README and CI verification.
- [x] Run `go test ./...`, `go vet ./...`, `gofmt -l .`, Linux static builds and `docker compose config --quiet`. Run the supplied sample through the actual server/client and compare all result fields.
- [x] Review protocol boundaries, error paths and rendered container configuration; correct proven issues and repeat affected checks.
- [ ] Inspect staged files, commit, create a public GitHub repository, push and compare local HEAD with remote main. Record actual validation and any environment limitation in README before final submission.

Parallel ownership: engine agent owns internal/fingerprint and rules; API agent owns cmd and internal/httpapi; deployment agent owns container assets, sample data, README and workflow. Root owns integration, release validation and GitHub publication.
