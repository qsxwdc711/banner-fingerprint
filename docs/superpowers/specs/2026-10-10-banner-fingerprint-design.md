# Banner fingerprint design

The delivery is a passive recognizer: it consumes supplied scan results and never contacts the scanned hosts. A standard-library Go HTTP server exposes POST /fingerprint and GET /health; a separate Go client reads a JSON array and prints the returned array. Identification preserves the input order and endpoint identity.

The engine loads and validates JSON rules before the listener starts. Protocol framing guards select useful banner regions; external rules provide product patterns, named version captures, and heuristic confidence. SSH, HTTP, MySQL, Redis and FTP are required. Unrecognized content produces unknown with empty product/version/os_hint and zero confidence, including when it occurs on a familiar port. Binary input supports JSON control escapes and optional base64.

Transport validation distinguishes an invalid request from an unidentified banner. Invalid JSON, invalid endpoints and configured size limits produce structured HTTP errors. No matching rule is a successful result. Bounded requests, timeouts and graceful shutdown protect service resources.

Docker builds two static binaries in a builder stage and uses separate scratch runtime targets. Both run without root, a writable root filesystem or Linux capabilities. Compose uses an internal network and service DNS; the client waits for the server's actual HTTP healthcheck. Only the server's loopback-bound port is published. The sample client exits after one batch while the server continues serving.

Tests cover the supplied sample, additional versions/products, malformed/truncated binary banners, misleading HTTP bodies, API limits, unknown results, and client errors. Final verification includes go test, go vet, Linux compilation and Compose configuration; live container verification depends on the available Docker daemon. Publication uses an authenticated GitHub account and a public repository, with local and remote commit IDs compared.
