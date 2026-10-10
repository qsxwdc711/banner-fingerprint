# Fingerprint rules

`fingerprints.json` is the editable rule set. The server loads and validates it
once at startup; a missing file, unsupported schema, unknown field, invalid
regular expression, invalid capture group, duplicate rule name, or confidence
outside `(0, 1]` prevents startup. Restart the server after changing the file.
No product names or product versions are compiled into the Go recognition code.

Rules are tried in file order, and the first matching rule for the observed
protocol wins. Put specific product rules before generic protocol rules. The
engine compiles Go/RE2 regular expressions once, avoiding per-request compilation
and backtracking regular-expression behavior. Rule loading accepts at most 1 MiB.

Example rule:

```json
{
  "name": "http-nginx",
  "protocol": "HTTP",
  "target": "http_server",
  "pattern": "(?im)(?:^|[ \\t;(])nginx(?:/([0-9][A-Za-z0-9._+-]*))?(?:$|[ \\t;(])",
  "product": "nginx",
  "version_group": 1,
  "confidence": 0.9
}
```

`version_group` selects a regular-expression capture group; `0` means no version
extraction. An unmatched optional capture produces an empty version. `product`
is a canonical output name, so case variations in input do not change output.
`confidence` is an explicit evidence-strength heuristic, not a calibrated
probability of correctness. Banners are self-reported information and can be
spoofed. Generic replies such as Redis `+PONG` consequently have lower confidence
than a version-bearing software banner.

Protocol framing lives in `internal/fingerprint/engine.go`, with rule targets:

| Protocol | Target | Text available to the rule |
| --- | --- | --- |
| SSH | `ssh_software` | Software/comment portion of a valid SSH 2.0 or 1.99 identification line |
| SSH | `banner` | The complete valid SSH identification line |
| HTTP | `http_server` | Only values from `Server` headers before the first empty line |
| HTTP | `banner` | Status line and headers, with the response body excluded |
| MySQL | `mysql_version` | The NUL-terminated server version in a protocol-10 greeting |
| Redis | `banner` | RESP reply or INFO output; a Redis-specific rule must additionally match |
| FTP | `banner` | A banner starting with a 220 greeting; an FTP-specific rule must additionally match |

HTTP header names are case-insensitive, and both CRLF and LF captures are
supported. Bare `Server:` header observations are accepted only when `Server:`
is the first line. Product names inside HTTP bodies are deliberately excluded.
SSH pre-identification notice lines are allowed. FTP multiline greetings can
match a later `220` product line. A generic `220` line is insufficient because
SMTP uses the same greeting code. Redis `+OK` and arbitrary `-ERR` lines likewise
remain unknown because they are ambiguous.

MySQL greeting captures can be truncated after a complete version field, as in
the task's supplied example. The packet header, sequence number, protocol byte,
printable version, and terminating NUL are still checked. A payload-only
protocol-10 greeting is also supported. The parser never assumes that a declared
packet length is actually available. MariaDB's `5.5.5-` compatibility prefix is
removed by its product rule. Ports are preserved as metadata and never used to
guess a protocol.

`os_hints` is a separate ordered list of `{ "pattern": "...", "hint": "..." }`.
It searches only the matched SSH software/comment, HTTP Server header value,
MySQL version field, or Redis/FTP banner. A distribution or OS must appear in
this evidence; the engine does not infer an OS solely from a product name.

Use `banner_base64` for binary scanner output. JSON's Unicode escapes represent
Unicode characters, not arbitrary non-UTF-8 bytes. In particular `\xNN` is not
legal JSON. Standard JSON escapes such as `\u0000` work for the ASCII sample's
NUL bytes, while base64 preserves every byte of a real binary handshake.

Add regression cases to `internal/fingerprint/engine_test.go` when changing
rules. The package includes all 20 supplied observations, unrelated-port cases,
unseen software versions, framing checks, adversarial HTTP-body examples,
configuration rejection tests, concurrent use, and a fuzz target.
