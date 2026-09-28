package redact

import (
	"strings"
	"testing"
)

// --- SECURITY TEST 5: sensitive headers and values are redacted ------------

func TestSensitiveHeadersRedacted(t *testing.T) {
	in := map[string][]string{
		"Authorization":       {"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.abcdefghijk"},
		"Cookie":              {"session=abc123; csrftoken=xyz"},
		"Set-Cookie":          {"session=abc123; HttpOnly; Secure"},
		"X-Api-Key":           {"AKIAIOSFODNN7EXAMPLE"},
		"X-Auth-Token":        {"s3cr3t"},
		"Proxy-Authorization": {"Basic dXNlcjpwYXNz"},
		"User-Agent":          {"bugbounty-toolkit/1.0"},
		"Content-Type":        {"text/html; charset=utf-8"},
	}
	out := Headers(in)
	for _, h := range []string{"authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token", "proxy-authorization"} {
		vals := out[h]
		if len(vals) != 1 || vals[0] != Placeholder {
			t.Errorf("SECURITY: header %q not fully redacted: %v", h, vals)
		}
	}
	// Non-sensitive headers survive untouched.
	if got := out["user-agent"]; len(got) != 1 || got[0] != "bugbounty-toolkit/1.0" {
		t.Errorf("user-agent was altered: %v", got)
	}
	// The original map must not be mutated.
	if in["Authorization"][0] == Placeholder {
		t.Error("SECURITY: Headers() mutated its input")
	}
}

func TestHeaderByName(t *testing.T) {
	if got := Header("Authorization", "Bearer abcdefghijklmnop"); got != Placeholder {
		t.Errorf("SECURITY: Authorization header leaked: %q", got)
	}
	if got := Header("X-API-Key", "whatever"); got != Placeholder {
		t.Errorf("SECURITY: x-api-key leaked: %q", got)
	}
	if got := Header("Content-Type", "application/json"); got != "application/json" {
		t.Errorf("non-sensitive header altered: %q", got)
	}
}

func TestIsSensitiveKeyVariants(t *testing.T) {
	sensitive := []string{
		"Authorization", "authorization", "AUTHORIZATION",
		"X-Api-Key", "x_api_key", "XAPIKEY", "ApiKey",
		"Cookie", "Set-Cookie", "Proxy-Authorization",
		"X-CSRF-Token", "X-Refresh-Token", "X-Goog-Api-Key",
		"access_token", "refresh_token", "client_secret",
		"password", "PASSWORD", "api_key", "apikey", "private_key",
		"Authorization-Token", "X-Amz-Security-Token",
	}
	for _, k := range sensitive {
		if !IsSensitiveKey(k) {
			t.Errorf("SECURITY: %q not recognized as sensitive", k)
		}
	}
	benign := []string{"Content-Type", "Server", "X-Request-Id", "Accept", "Cache-Control", "X-Frame-Options", "Keylen", "keyword"}
	for _, k := range benign {
		if IsSensitiveKey(k) {
			t.Errorf("false positive: %q treated as sensitive", k)
		}
	}
}

// --- credential pattern detection ------------------------------------------

func TestCredentialPatterns(t *testing.T) {
	secrets := map[string]string{
		"aws access key": "AKIAIOSFODNN7EXAMPLE",
		"gcp key":        "AIzaSyD-1234567890abcdefghijklmnopqrstu",
		"github token":   "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
		"slack token":    "xoxb-1234567890-abcdefghijkl",
		"jwt":            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKKF2QT4f",
		"bearer":         "Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
		"kv password":    `password=hunter2secret`,
		"kv api key":     `api_key: "sk-live-1234567890"`,
		"url userinfo":   "https://admin:hunter2@internal.example.com/x",
		"basic auth":     "Basic YWRtaW46aHVudGVyMg==",
	}
	for name, s := range secrets {
		got := Text(s)
		if strings.Contains(got, "hunter2") || strings.Contains(got, "sk-live-1234567890") ||
			strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") || strings.Contains(got, "AIzaSyD-") ||
			strings.Contains(got, "ghp_1234") || strings.Contains(got, "xoxb-") ||
			strings.Contains(got, "eyJhbGciOiJIUzI1NiJ9") || strings.Contains(got, "abcdefghijklmnopqrstuvwxyz") ||
			strings.Contains(got, "YWRtaW46") {
			t.Errorf("SECURITY: %s leaked after redaction: %q -> %q", name, s, got)
		}
	}
}

func TestTextLeavesBenignContentAlone(t *testing.T) {
	for _, s := range []string{
		"https://example.com/path?page=2",
		"Content-Type: text/html",
		"server_version=1.2.3",
		"a normal sentence about API keys in general",
	} {
		if got := Text(s); got != s {
			t.Errorf("benign text was altered: %q -> %q", s, got)
		}
	}
}

func TestURLRedactsQuerySecrets(t *testing.T) {
	in := "https://example.com/callback?code=abc123XYZ&state=xyz&access_token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig&page=2"
	got := URL(in)
	for _, leak := range []string{"abc123XYZ", "eyJhbGciOiJIUzI1NiJ9", "sig"} {
		if strings.Contains(got, leak) {
			t.Errorf("SECURITY: %q leaked in redacted URL: %s", leak, got)
		}
	}
	if !strings.Contains(got, "page=2") {
		t.Errorf("benign parameter was lost: %s", got)
	}
}

func TestURLRedactsUserInfo(t *testing.T) {
	got := URL("https://admin:hunter2@example.com/x")
	if strings.Contains(got, "hunter2") {
		t.Errorf("SECURITY: password leaked in URL: %s", got)
	}
	if !strings.Contains(got, "admin") {
		t.Errorf("username should be preserved: %s", got)
	}
}

func TestURLUnparseableIsSanitizedNotCrashed(t *testing.T) {
	for _, s := range []string{"::::not a url", "http://[::1", "\x00\x01\x02", "%%%"} {
		_ = URL(s) // must not panic
	}
}

// --- log injection ----------------------------------------------------------

func TestControlCharactersStripped(t *testing.T) {
	// A hostile server returning CRLF-delimited content must not be able to
	// forge additional log records.
	in := "GET / HTTP/1.1\r\nHost: evil\r\n{\"level\":\"error\"}\x00\x1b[31mred"
	got := Sanitize(in)
	if strings.ContainsAny(got, "\r\n\x00\x1b") {
		t.Errorf("SECURITY: control characters survived sanitization: %q", got)
	}
}

func TestNewlinesNeutralizedInEvidence(t *testing.T) {
	in := "line one\nline two\r\nline three"
	got := SanitizeMultiline(in)
	if strings.ContainsAny(got, "\n\r") {
		t.Errorf("SECURITY: newline survived: %q", got)
	}
	if !strings.Contains(got, `\n`) {
		t.Errorf("expected a literal escape, got %q", got)
	}
}

func TestTextAlsoStripsControlCharacters(t *testing.T) {
	got := Text("token=abcdef\r\nINFO forged event=login")
	if strings.ContainsAny(got, "\r\n") {
		t.Errorf("SECURITY: Text() left a newline: %q", got)
	}
	if strings.Contains(got, "abcdef") {
		t.Errorf("SECURITY: secret survived: %q", got)
	}
}

// --- map helpers ------------------------------------------------------------

func TestMapRedaction(t *testing.T) {
	in := map[string]string{
		"url":      "https://example.com/?api_key=supersecretvalue",
		"password": "hunter2",
		"status":   "200",
	}
	out, scrubbed := Scrub(in)
	if !scrubbed {
		t.Error("Scrub should report that redaction occurred")
	}
	if out["password"] != Placeholder {
		t.Errorf("SECURITY: password survived: %q", out["password"])
	}
	if strings.Contains(out["url"], "supersecretvalue") {
		t.Errorf("SECURITY: api_key survived: %q", out["url"])
	}
	if out["status"] != "200" {
		t.Errorf("benign value altered: %q", out["status"])
	}
}

func TestScrubReportsNoChange(t *testing.T) {
	in := map[string]string{"status": "200", "title": "Home"}
	_, scrubbed := Scrub(in)
	if scrubbed {
		t.Error("Scrub reported a change for benign data")
	}
}

func TestStringSlice(t *testing.T) {
	got := StringSlice([]string{"https://a.example.com/x?token=abcdefgh", "normal"})
	if strings.Contains(got[0], "abcdefgh") {
		t.Errorf("SECURITY: token leaked in slice: %q", got[0])
	}
	if got[1] != "normal" {
		t.Errorf("benign element altered: %q", got[1])
	}
}

func TestLengthIsBounded(t *testing.T) {
	huge := strings.Repeat("A", 100000)
	if got := Sanitize(huge); len(got) > 4200 {
		t.Errorf("Sanitize did not bound its output: %d bytes", len(got))
	}
}

func TestEmptyInputs(t *testing.T) {
	if Text("") != "" || Sanitize("") != "" || URL("") != "" || SanitizeMultiline("") != "" {
		t.Error("empty input handling")
	}
	if Headers(nil) != nil || Map(nil) != nil || StringSlice(nil) != nil || URLValues(nil) != nil {
		t.Error("nil map/slice handling")
	}
}

func TestSensitiveKeyListSorted(t *testing.T) {
	l := SensitiveKeyList()
	if len(l) == 0 {
		t.Fatal("expected a non-empty list")
	}
	for i := 1; i < len(l); i++ {
		if l[i-1] > l[i] {
			t.Fatalf("list is not sorted: %q before %q", l[i-1], l[i])
		}
	}
}
