// Package fingerprint identifies passive service banners using protocol framing
// and externally configured product rules. It does not connect to scanned hosts.
package fingerprint

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// Input is one observation from a network scanner. BannerBase64, when present,
// is the authoritative representation of binary bytes; Banner is otherwise used.
type Input struct {
	IP           string `json:"ip"`
	Port         int    `json:"port"`
	Banner       string `json:"banner"`
	BannerBase64 string `json:"banner_base64,omitempty"`
}

// Result describes evidence found in a banner. Unknown observations retain their
// input address and have empty product, version, and OSHint and zero confidence.
type Result struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	OSHint     string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`
}

type ruleConfig struct {
	Name         string  `json:"name"`
	Protocol     string  `json:"protocol"`
	Target       string  `json:"target"`
	Pattern      string  `json:"pattern"`
	Product      string  `json:"product"`
	VersionGroup int     `json:"version_group"`
	Confidence   float64 `json:"confidence"`
}

type osConfig struct {
	Pattern string `json:"pattern"`
	Hint    string `json:"hint"`
}

type configuration struct {
	SchemaVersion int          `json:"schema_version"`
	Rules         []ruleConfig `json:"rules"`
	OSHints       []osConfig   `json:"os_hints"`
}

type rule struct {
	ruleConfig
	pattern *regexp.Regexp
}

type osRule struct {
	pattern *regexp.Regexp
	hint    string
}

// Engine is immutable after Load and may be shared between concurrent requests.
// Rule order is significant: the first matching rule for a framed protocol wins.
type Engine struct {
	rules   []rule
	osHints []osRule
}

// Load validates and compiles a rules file once. Invalid configuration fails
// startup instead of silently disabling recognition or failing individual items.
func Load(path string) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read fingerprint rules: %w", err)
	}
	if len(data) > 1024*1024 {
		return nil, errors.New("fingerprint rules exceed 1 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var config configuration
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("decode fingerprint rules: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("fingerprint rules must contain exactly one JSON object")
	}
	if config.SchemaVersion != 1 {
		return nil, fmt.Errorf("unsupported fingerprint rules schema: %d", config.SchemaVersion)
	}
	if len(config.Rules) == 0 {
		return nil, errors.New("fingerprint rules must not be empty")
	}
	engine := &Engine{}
	names := make(map[string]bool)
	for i, configRule := range config.Rules {
		if configRule.Name == "" || names[configRule.Name] {
			return nil, fmt.Errorf("rule %d has an empty or duplicate name", i)
		}
		names[configRule.Name] = true
		if !validTarget(configRule.Protocol, configRule.Target) {
			return nil, fmt.Errorf("rule %q has an invalid protocol or target", configRule.Name)
		}
		if configRule.Pattern == "" || configRule.Confidence <= 0 || configRule.Confidence > 1 {
			return nil, fmt.Errorf("rule %q requires a pattern and confidence in (0,1]", configRule.Name)
		}
		pattern, err := regexp.Compile(configRule.Pattern)
		if err != nil {
			return nil, fmt.Errorf("compile rule %q: %w", configRule.Name, err)
		}
		if configRule.VersionGroup < 0 || configRule.VersionGroup > pattern.NumSubexp() {
			return nil, fmt.Errorf("rule %q refers to an invalid version capture group", configRule.Name)
		}
		engine.rules = append(engine.rules, rule{ruleConfig: configRule, pattern: pattern})
	}
	for i, hint := range config.OSHints {
		if hint.Hint == "" || hint.Pattern == "" {
			return nil, fmt.Errorf("OS hint %d requires a pattern and hint", i)
		}
		pattern, err := regexp.Compile(hint.Pattern)
		if err != nil {
			return nil, fmt.Errorf("compile OS hint %d: %w", i, err)
		}
		engine.osHints = append(engine.osHints, osRule{pattern: pattern, hint: hint.Hint})
	}
	return engine, nil
}

// Identify returns one result without changing the input or engine. Ports are
// metadata, never recognition evidence. Invalid base64 and unsupported data are
// unknown; the transport layer may separately reject invalid input encoding.
func (e *Engine) Identify(input Input) Result {
	result := Result{IP: input.IP, Port: input.Port, Protocol: "unknown"}
	if e == nil {
		return result
	}
	banner := input.Banner
	if input.BannerBase64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(input.BannerBase64)
		if err != nil {
			return result
		}
		banner = string(decoded)
	}
	protocol, targets, osEvidence := frame(banner)
	if protocol == "" {
		return result
	}
	for _, candidate := range e.rules {
		if candidate.Protocol != protocol {
			continue
		}
		target, exists := targets[candidate.Target]
		if !exists {
			continue
		}
		match := candidate.pattern.FindStringSubmatch(target)
		if match == nil {
			continue
		}
		result.Protocol = protocol
		result.Product = candidate.Product
		result.Confidence = candidate.Confidence
		if candidate.VersionGroup > 0 {
			result.Version = match[candidate.VersionGroup]
		}
		for _, hint := range e.osHints {
			if hint.pattern.MatchString(osEvidence) {
				result.OSHint = hint.hint
				break
			}
		}
		return result
	}
	return result
}

func validTarget(protocol, target string) bool {
	switch protocol {
	case "SSH":
		return target == "banner" || target == "ssh_software"
	case "HTTP":
		return target == "banner" || target == "http_server"
	case "MySQL":
		return target == "mysql_version"
	case "Redis", "FTP":
		return target == "banner"
	default:
		return false
	}
}

// The expressions below describe wire protocol syntax, not product fingerprints.
var (
	sshIdentification = regexp.MustCompile(`^SSH-(?:1\.99|2\.0)-([^\r\n]+)$`)
	httpStatus        = regexp.MustCompile(`^HTTP/(?:1\.[01]|2(?:\.0)?|3(?:\.0)?) [0-9]{3}(?:[ \t].*)?$`)
)

func frame(banner string) (string, map[string]string, string) {
	// HTTP is checked before line-oriented greetings, so an SSH/FTP string in an
	// HTTP response body cannot override the enclosing protocol.
	if header, server, ok := httpHeader(banner); ok {
		return "HTTP", map[string]string{"banner": header, "http_server": server}, server
	}
	for _, line := range strings.Split(banner, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if match := sshIdentification.FindStringSubmatch(line); match != nil {
			return "SSH", map[string]string{"banner": line, "ssh_software": match[1]}, match[1]
		}
	}
	if version, ok := mysqlVersion([]byte(banner)); ok {
		return "MySQL", map[string]string{"mysql_version": version}, version
	}
	trimmed := strings.TrimSpace(banner)
	if trimmed == "" {
		return "", nil, ""
	}
	// RESP framing alone is not sufficient evidence: external Redis rules must
	// also match a characteristic reply or redis_version field.
	if strings.Contains(trimmed, "redis_version:") || strings.ContainsRune("+-$*:%,_~#=!", rune(trimmed[0])) {
		return "Redis", map[string]string{"banner": trimmed}, trimmed
	}
	// A 220 greeting is shared with SMTP. FTP product or FTP wording rules must
	// match before it is classified, avoiding guesses based on port 21 alone.
	if strings.HasPrefix(trimmed, "220 ") || strings.HasPrefix(trimmed, "220-") {
		return "FTP", map[string]string{"banner": trimmed}, trimmed
	}
	return "", nil, ""
}

func httpHeader(banner string) (string, string, bool) {
	text := strings.TrimLeft(banner, "\r\n")
	lines := strings.Split(text, "\n")
	if len(lines) == 0 {
		return "", "", false
	}
	first := strings.TrimSuffix(lines[0], "\r")
	status := httpStatus.MatchString(first)
	// Header-only observations are common scanner output. Require Server to be
	// the first line to avoid interpreting an arbitrary body's later text.
	serverOnly := strings.HasPrefix(strings.ToLower(first), "server:")
	if !status && !serverOnly {
		return "", "", false
	}
	var headers []string
	var servers []string
	for _, line := range lines {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			break
		}
		headers = append(headers, line)
		key, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(key), "Server") {
			servers = append(servers, strings.TrimSpace(value))
		}
	}
	return strings.Join(headers, "\n"), strings.Join(servers, "\n"), true
}

func mysqlVersion(banner []byte) (string, bool) {
	var payload []byte
	if len(banner) >= 5 && banner[3] == 0 && banner[4] == 10 {
		declared := int(banner[0]) | int(banner[1])<<8 | int(banner[2])<<16
		// A capture may stop after the version (as in the supplied sample), so
		// do not require the complete declared packet. Reject impossible lengths.
		if declared < 4 {
			return "", false
		}
		payload = banner[5:]
		if declared-1 < len(payload) {
			payload = payload[:declared-1]
		}
	} else if len(banner) > 1 && banner[0] == 10 {
		// Some scanners retain only the handshake payload, without packet header.
		payload = banner[1:]
	} else {
		return "", false
	}
	end := bytes.IndexByte(payload, 0)
	if end < 3 || end > 128 {
		return "", false
	}
	version := payload[:end]
	if version[0] < '0' || version[0] > '9' || !bytes.ContainsRune(version, '.') {
		return "", false
	}
	for _, value := range version {
		if value < 32 || value > 126 {
			return "", false
		}
	}
	return string(version), true
}
