package fingerprint

import (
	"encoding/base64"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func testEngine(t testing.TB) *Engine {
	t.Helper()
	engine, err := Load(filepath.Join("..", "..", "rules", "fingerprints.json"))
	if err != nil {
		t.Fatalf("Load rules: %v", err)
	}
	return engine
}

func TestIdentifySuppliedSamples(t *testing.T) {
	engine := testEngine(t)
	cases := []struct {
		port       int
		banner     string
		protocol   string
		product    string
		version    string
		osHint     string
		confidence float64
	}{
		{22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3", "SSH", "OpenSSH", "8.9p1", "Ubuntu", .95},
		{80, "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html", "HTTP", "nginx", "1.24.0", "", .9},
		{443, "HTTP/1.1 200 OK\r\nServer: Apache/2.4.57", "HTTP", "Apache", "2.4.57", "", .9},
		{3306, "J\x00\x00\x00\n8.0.32\x00", "MySQL", "MySQL", "8.0.32", "", .9},
		{6379, "-ERR wrong number of arguments for 'get' command", "Redis", "Redis", "", "", .7},
		{21, "220 ProFTPD 1.3.7 Server (ProFTPD)", "FTP", "ProFTPD", "1.3.7", "", .9},
		{8080, "HTTP/1.1 404 Not Found\r\nServer: Jetty/9.4.51", "HTTP", "Jetty", "9.4.51", "", .85},
		{22, "SSH-2.0-OpenSSH_9.3 Debian-1", "SSH", "OpenSSH", "9.3", "Debian", .95},
		{80, "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)", "HTTP", "nginx", "1.18.0", "Ubuntu", .9},
		{443, "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)", "HTTP", "Apache", "2.4.41", "Ubuntu", .9},
		{3306, "J\x00\x00\x00\n5.7.42\x00", "MySQL", "MySQL", "5.7.42", "", .9},
		{6379, "+PONG", "Redis", "Redis", "", "", .7},
		{21, "220 (vsFTPd 3.0.5)", "FTP", "vsFTPd", "3.0.5", "", .9},
		{8443, "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3", "HTTP", "nginx", "1.25.3", "", .9},
		{22, "SSH-1.99-OpenSSH_4.3", "SSH", "OpenSSH", "4.3", "", .95},
		{9999, "\x16\x03\x01\x00\xa5\x01\x00\x00\xa1", "unknown", "", "", "", 0},
		{8888, "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0", "HTTP", "Microsoft-IIS", "10.0", "", .9},
		{6379, "-NOAUTH Authentication required.", "Redis", "Redis", "", "", .7},
		{21, "220 Welcome to Pure-FTPd", "FTP", "Pure-FTPd", "", "", .9},
		{12345, "QUIT\r\n", "unknown", "", "", "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.banner, func(t *testing.T) {
			input := Input{IP: "1.2.3.4", Port: tc.port, Banner: tc.banner}
			got := engine.Identify(input)
			want := Result{IP: input.IP, Port: tc.port, Protocol: tc.protocol, Product: tc.product, Version: tc.version, OSHint: tc.osHint, Confidence: tc.confidence}
			if got != want {
				t.Errorf("Identify(%q) = %+v, want %+v", tc.banner, got, want)
			}
		})
	}
}

func TestIdentifyUnseenAndAdversarial(t *testing.T) {
	engine := testEngine(t)
	cases := []struct {
		name     string
		banner   string
		protocol string
		product  string
		version  string
		osHint   string
	}{
		{"empty", "", "unknown", "", "", ""},
		{"wrong_port_does_not_override_banner", "SSH-2.0-OpenSSH_9.9p2\r\n", "SSH", "OpenSSH", "9.9p2", ""},
		{"ssh_pre_identification", "Maintenance notice\r\nSSH-2.0-dropbear_2022.83\r\n", "SSH", "Dropbear", "2022.83", ""},
		{"unknown_ssh_software", "SSH-2.0-CustomSSH_1.2", "SSH", "", "", ""},
		{"unsupported_ssh_protocol", "SSH-0.5-OpenSSH_9.3", "unknown", "", "", ""},
		{"ssh_mere_product_name", "OpenSSH_9.3", "unknown", "", "", ""},
		{"lowercase_header", "HTTP/1.1 200 OK\r\nsErVeR: NGINX/1.26.2 (Alpine)\r\n\r\n", "HTTP", "nginx", "1.26.2", "Alpine"},
		{"header_only", "Server: nginx/1.25.4", "HTTP", "nginx", "1.25.4", ""},
		{"http2", "HTTP/2 200\nServer: Apache/2.4.62 (Win64)\n\n", "HTTP", "Apache", "2.4.62", "Windows"},
		{"product_without_version", "HTTP/1.1 200 OK\r\nServer: nginx", "HTTP", "nginx", "", ""},
		{"duplicate_server_header", "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nServer: proxy", "HTTP", "nginx", "1.24.0", ""},
		{"known_product_in_later_server_header", "HTTP/1.1 200 OK\r\nServer: proxy\r\nServer: nginx/1.24.0", "HTTP", "nginx", "1.24.0", ""},
		{"jetty_parentheses", "HTTP/1.0 200 OK\r\nServer: Jetty(9.4.51.v20230217)", "HTTP", "Jetty", "9.4.51.v20230217", ""},
		{"http_unknown_product", "HTTP/1.1 403 Forbidden\r\nServer: ExampleServer/1.0", "HTTP", "", "", ""},
		{"http_no_server", "HTTP/1.1 204 No Content\r\nDate: today", "HTTP", "", "", ""},
		{"body_product_is_not_header", "HTTP/1.1 200 OK\r\n\r\nServer: nginx/1.2\nSSH-2.0-OpenSSH_9.4", "HTTP", "", "", ""},
		{"body_os_hint_is_not_header", "HTTP/1.1 200 OK\r\nServer: nginx/1.2\r\n\r\nUbuntu", "HTTP", "nginx", "1.2", ""},
		{"body_product_words", "<html>nginx/1.24.0 Apache/2.4.57</html>", "unknown", "", "", ""},
		{"product_prefix_is_not_product", "HTTP/1.1 200 OK\r\nServer: faken ginx/1.2 mynginx/1.2", "HTTP", "", "", ""},
		{"mariadb_handshake", "Z\x00\x00\x00\x0a5.5.5-10.11.2-MariaDB-1:10.11.2\x00", "MySQL", "MariaDB", "10.11.2", ""},
		{"mysql_payload_only", "\x0a8.4.0\x00", "MySQL", "MySQL", "8.4.0", ""},
		{"mysql_distro_suffix", "Z\x00\x00\x00\x0a8.0.32-0ubuntu0.22.04.2\x00", "MySQL", "MySQL", "8.0.32", ""},
		{"mysql_truncated_version", "J\x00\x00\x00\x0a8.0", "unknown", "", "", ""},
		{"mysql_impossible_packet_length", "\x01\x00\x00\x00\x0a8.0.32\x00", "unknown", "", "", ""},
		{"mysql_wrong_sequence", "J\x00\x00\x01\x0a8.0.32\x00", "unknown", "", "", ""},
		{"mysql_plain_version_is_not_handshake", "8.0.32", "unknown", "", "", ""},
		{"redis_info", "$67\r\n# Server\r\nredis_version:7.2.4\r\nredis_mode:standalone\r\n", "Redis", "Redis", "7.2.4", ""},
		{"redis_info_without_bulk_header", "# Server\r\nredis_version:6.2.14\r\n", "Redis", "Redis", "6.2.14", ""},
		{"redis_unknown_command", "-ERR unknown command 'HELLO', with args beginning with: '3'", "Redis", "Redis", "", ""},
		{"redis_generic_error_ambiguous", "-ERR arbitrary error", "unknown", "", "", ""},
		{"redis_generic_simple_string_ambiguous", "+OK\r\n", "unknown", "", "", ""},
		{"redis_wrongpass", "-WRONGPASS invalid username-password pair or user is disabled.\r\n", "Redis", "Redis", "", ""},
		{"redis_protected_mode", "-DENIED Redis is running in protected mode because protected mode is enabled", "Redis", "Redis", "", ""},
		{"ftp_pure_version", "220 Pure-FTPd 1.0.51 Server", "FTP", "Pure-FTPd", "1.0.51", ""},
		{"ftp_filezilla", "220 FileZilla Server 0.9.60 beta", "FTP", "FileZilla Server", "0.9.60", ""},
		{"ftp_multiline", "220-Welcome to this service\r\n220 ProFTPD 1.3.8 Server (ProFTPD)", "FTP", "ProFTPD", "1.3.8", ""},
		{"ftp_product_line_ends_crlf", "220-ProFTPD 1.3.8\r\n220 Ready\r\n", "FTP", "ProFTPD", "1.3.8", ""},
		{"ftp_generic", "220 Welcome to the FTP server", "FTP", "", "", ""},
		{"smtp_220_is_not_ftp", "220 mail.example.com ESMTP Postfix (Ubuntu)", "unknown", "", "", ""},
		{"ambiguous_220", "220 Welcome", "unknown", "", "", ""},
		{"binary_noise", "\x00\xff\xfe\x80\x00", "unknown", "", "", ""},
		{"empty_ports_no_guess", strings.Repeat("x", 65536), "unknown", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := engine.Identify(Input{IP: "2001:db8::1", Port: 12345, Banner: tc.banner})
			if got.IP != "2001:db8::1" || got.Port != 12345 || got.Protocol != tc.protocol || got.Product != tc.product || got.Version != tc.version || got.OSHint != tc.osHint {
				t.Errorf("Identify(%q) = %+v; want protocol=%q product=%q version=%q os_hint=%q", tc.banner, got, tc.protocol, tc.product, tc.version, tc.osHint)
			}
			if got.Confidence < 0 || got.Confidence > 1 || math.IsNaN(got.Confidence) {
				t.Errorf("confidence = %v, want finite value in [0,1]", got.Confidence)
			}
		})
	}
}

func TestBase64AndConcurrentUse(t *testing.T) {
	engine := testEngine(t)
	input := Input{IP: "1.2.3.4", Port: 443, Banner: "conflicting text", BannerBase64: base64.StdEncoding.EncodeToString([]byte("J\x00\x00\x00\x0a8.0.32\x00"))}
	want := Result{IP: input.IP, Port: input.Port, Protocol: "MySQL", Product: "MySQL", Version: "8.0.32", Confidence: .9}
	var workers sync.WaitGroup
	for i := 0; i < 50; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 20; j++ {
				if got := engine.Identify(input); got != want {
					t.Errorf("concurrent Identify = %+v, want %+v", got, want)
				}
			}
		}()
	}
	workers.Wait()
	if got := engine.Identify(Input{BannerBase64: "!!!"}); got.Protocol != "unknown" {
		t.Errorf("invalid base64 result = %+v, want unknown", got)
	}
	var nilEngine *Engine
	if got := nilEngine.Identify(Input{Banner: "SSH-2.0-OpenSSH_9.3"}); got.Protocol != "unknown" {
		t.Errorf("nil engine result = %+v, want unknown", got)
	}
}

func TestLoadRejectsInvalidRules(t *testing.T) {
	valid := `{"schema_version":1,"rules":[{"name":"test","protocol":"SSH","target":"banner","pattern":"^SSH-(.*)","product":"test","version_group":1,"confidence":0.9}]}`
	cases := map[string]string{
		"bad_json":             "{",
		"unknown_field":        strings.Replace(valid, `"schema_version":1`, `"schema_version":1,"mystery":true`, 1),
		"unsupported_schema":   strings.Replace(valid, `"schema_version":1`, `"schema_version":2`, 1),
		"bad_regex":            strings.Replace(valid, `^SSH-(.*)`, `[`, 1),
		"capture_out_of_range": strings.Replace(valid, `"version_group":1`, `"version_group":2`, 1),
		"negative_capture":     strings.Replace(valid, `"version_group":1`, `"version_group":-1`, 1),
		"invalid_target":       strings.Replace(valid, `"target":"banner"`, `"target":"http_server"`, 1),
		"confidence_too_high":  strings.Replace(valid, `"confidence":0.9`, `"confidence":1.1`, 1),
		"zero_confidence":      strings.Replace(valid, `"confidence":0.9`, `"confidence":0`, 1),
		"no_rules":             `{"schema_version":1,"rules":[]}`,
		"multiple_objects":     valid + valid,
		"empty_os_hint":        strings.Replace(valid, `}]}`, `}],"os_hints":[{"pattern":"Ubuntu","hint":""}]}`, 1),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "rules.json")
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Error("Load invalid configuration succeeded, want error")
			}
		})
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("Load missing file succeeded, want error")
	}
}

// FuzzIdentify verifies that arbitrary scanner bytes cannot panic or produce
// invalid confidence, and that address metadata survives every parsing path.
func FuzzIdentify(f *testing.F) {
	engine := testEngine(f)
	for _, banner := range []string{"", "SSH-2.0-OpenSSH_9.3", "HTTP/1.1 200 OK\r\nServer: nginx/1.2", "J\x00\x00\x00\x0a8.0.32\x00", "+PONG", "220 (vsFTPd 3.0.5)", "\xff\x00\x01"} {
		f.Add([]byte(banner))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		got := engine.Identify(Input{IP: "192.0.2.1", Port: 12345, Banner: string(data)})
		if got.IP != "192.0.2.1" || got.Port != 12345 || got.Confidence < 0 || got.Confidence > 1 || math.IsNaN(got.Confidence) {
			t.Fatalf("Identify(%x) produced invalid result %+v", data, got)
		}
	})
}
