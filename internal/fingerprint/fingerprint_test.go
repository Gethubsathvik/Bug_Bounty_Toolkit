package fingerprint

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// --- signature database -----------------------------------------------------

func TestEmbeddedSignaturesLoad(t *testing.T) {
	set, err := Load()
	if err != nil {
		t.Fatalf("the embedded signature database must parse: %v", err)
	}
	names := set.All()
	if len(names) == 0 {
		t.Fatal("the embedded database is empty")
	}
	seen := map[string]bool{}
	for _, n := range names {
		if seen[n] {
			t.Errorf("duplicate signature %q", n)
		}
		seen[n] = true
	}
}

func TestMatchKnownTechnologies(t *testing.T) {
	set, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		in   Input
		want []string
	}{
		{
			name: "nginx from the server header",
			in:   Input{URL: "https://a.example/", Header: map[string][]string{"Server": {"nginx/1.24.0"}}},
			want: []string{"nginx"},
		},
		{
			name: "apache from the server header",
			in:   Input{URL: "https://a.example/", Header: map[string][]string{"Server": {"Apache/2.4.57"}}},
			want: []string{"Apache"},
		},
		{
			name: "wordpress from a generator meta tag",
			in: Input{URL: "https://a.example/", Body: []byte(
				`<meta name="generator" content="WordPress 6.4.1">`)},
			want: []string{"WordPress"},
		},
		{
			name: "cloudflare from response headers",
			in: Input{URL: "https://a.example/", Header: map[string][]string{
				"Server": {"cloudflare"}, "Cf-Ray": {"7a1b2c3d4e5f6789-AMS"},
			}},
			want: []string{"Cloudflare"},
		},
		{
			name: "jquery from an asset path",
			in:   Input{URL: "https://a.example/", Body: []byte(`<script src="/static/jquery-3.7.1.min.js"></script>`)},
			want: []string{"jQuery"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hits := set.Match(tc.in)
			names := Names(hits)
			for _, w := range tc.want {
				// Names appends the detected version, so a hit reads
				// "nginx 1.24.0" rather than "nginx".
				if !hasNamePrefix(names, w) {
					t.Errorf("expected %q among %v", w, names)
				}
			}
			for _, h := range hits {
				if h.Confidence == "" || h.Confidence.ConfidenceRank() == 0 {
					t.Errorf("%s was reported with no confidence: %q", h.Name, h.Confidence)
				}
				if h.Evidence == "" {
					t.Errorf("%s was reported with no evidence", h.Name)
				}
			}
		})
	}
}

func TestVersionExtraction(t *testing.T) {
	set, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	hits := set.Match(Input{
		URL:    "https://a.example/",
		Header: map[string][]string{"Server": {"nginx/1.24.0"}},
	})
	var version string
	for _, h := range hits {
		if h.Name == "nginx" {
			version = h.Version
		}
	}
	if version != "1.24.0" {
		t.Errorf("version = %q, want 1.24.0", version)
	}
}

func TestMatchIsDeterministic(t *testing.T) {
	set, _ := Load()
	in := Input{
		URL:    "https://a.example/",
		Header: map[string][]string{"Server": {"nginx/1.24.0", "cloudflare"}, "X-Powered-By": {"PHP/8.2.1"}},
		Body:   []byte(`<meta name="generator" content="WordPress 6.4.1"><script src="/jquery.js"></script>`),
	}
	first := Names(set.Match(in))
	for i := 0; i < 20; i++ {
		got := Names(set.Match(in))
		if strings.Join(got, ",") != strings.Join(first, ",") {
			t.Fatalf("match order is not stable:\n%v\n%v", first, got)
		}
	}
}

// --- signature validation ---------------------------------------------------

func TestParseRejectsMalformedSignatures(t *testing.T) {
	cases := map[string]string{
		"not yaml at all":        "\t\tthis: is: not: yaml:\n\t\t\t- [",
		"unclosed regex":         "signatures:\n  - name: x\n    header:\n      - regex: \"([unclosed\"\n",
		"oversized regex":        "signatures:\n  - name: x\n    header:\n      - regex: \"" + strings.Repeat("a", MaxPatternLen+10) + "\"\n",
		"signature without name": "signatures:\n  - category: web\n    header:\n      - regex: \"nginx\"\n",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(doc)); err == nil {
				t.Error("a malformed signature document was accepted")
			}
		})
	}
}

func TestParseRejectsOversizedDocuments(t *testing.T) {
	var b strings.Builder
	b.WriteString("signatures:\n")
	for i := 0; i < MaxSignatures+10; i++ {
		b.WriteString("  - name: tech\n    category: web\n    header:\n      - regex: \"x\"\n")
	}
	if _, err := Parse([]byte(b.String())); err == nil {
		t.Error("an oversized signature document was accepted")
	}
}

func TestHostileSignatureBodyDoesNotHang(t *testing.T) {
	// A signature pattern with nested quantifiers would hang a backtracking
	// engine. RE2 does not backtrack, so this must simply return.
	doc := "signatures:\n  - name: evil\n    category: web\n    body:\n      - regex: \"(a+)+b\"\n"
	set, err := Parse([]byte(doc))
	if err != nil {
		t.Skipf("the parser rejected the pattern outright, which is also acceptable: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		set.Match(Input{
			URL:  "https://a.example/",
			Body: []byte(strings.Repeat("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaac", 5000)),
		})
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("a pathological signature pattern did not terminate")
	}
}

func TestHostileResponseDoesNotBreakMatcher(t *testing.T) {
	set, _ := Load()
	payloads := []Input{
		{Body: []byte(strings.Repeat("<", 200000))},
		{Body: []byte(strings.Repeat("A", 4<<20))},
		{Body: []byte("\x00\x01\xff\xfe garbage")},
		{Body: []byte(strings.Repeat(`<script src="`, 20000))},
		{Header: map[string][]string{"Server": {strings.Repeat("x", 100000)}}},
		{Title: strings.Repeat("<", 50000)},
	}
	for i, in := range payloads {
		in.URL = "https://a.example/"
		done := make(chan struct{})
		go func(i int, in Input) {
			defer close(done)
			set.Match(in)
		}(i, in)
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Fatalf("payload %d did not terminate", i)
		}
	}
}

func TestMatchResultIsBounded(t *testing.T) {
	set, _ := Load()
	// A response claiming every technology should still be bounded.
	in := Input{
		URL:    "https://a.example/",
		Body:   []byte(strings.Repeat(`<meta name="generator" content="WordPress 6.4.1">`, 1000)),
		Header: map[string][]string{"Server": {"nginx", "Apache", "cloudflare", "IIS"}},
	}
	if got := len(set.Match(in)); got > MaxMatches {
		t.Errorf("%d hits exceeds the cap of %d", got, MaxMatches)
	}
}

func TestEmptyAndNilInputs(t *testing.T) {
	set, _ := Load()
	if hits := set.Match(Input{}); len(hits) != 0 {
		t.Errorf("an empty input produced %d hits", len(hits))
	}
	var nilSet *Set
	if hits := nilSet.Match(Input{Body: []byte("nginx")}); hits != nil {
		t.Error("a nil set must produce no hits rather than panicking")
	}
}

func TestMatchIsConcurrencySafe(t *testing.T) {
	set, _ := Load()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			set.Match(Input{
				URL:    "https://a.example/",
				Header: map[string][]string{"Server": {"nginx/1.24.0"}},
				Body:   []byte(`<meta name="generator" content="WordPress 6.4.1">`),
			})
		}()
	}
	wg.Wait()
}

// --- security header analysis ----------------------------------------------

func TestAnalyzeSecurityHeadersMissing(t *testing.T) {
	r := AnalyzeSecurityHeaders(nil, false)
	if len(r.Present) != 0 {
		t.Errorf("an empty response reported headers: %v", r.Present)
	}
	if len(r.Missing) == 0 {
		t.Error("everything should be missing")
	}
	if len(r.Missing) != len(HeaderCatalogue()) {
		t.Errorf("missing %d headers, catalogue has %d", len(r.Missing), len(HeaderCatalogue()))
	}
}

func TestAnalyzeSecurityHeadersComplete(t *testing.T) {
	r := AnalyzeSecurityHeaders(map[string][]string{
		"Strict-Transport-Security": {"max-age=31536000; includeSubDomains; preload"},
		"Content-Security-Policy": {"default-src 'self'; object-src 'none'; base-uri 'self'; " +
			"frame-ancestors 'none'"},
		"X-Content-Type-Options":     {"nosniff"},
		"X-Frame-Options":            {"DENY"},
		"Referrer-Policy":            {"strict-origin-when-cross-origin"},
		"Cross-Origin-Opener-Policy": {"same-origin"},
		"Permissions-Policy":         {"geolocation=()"},
	}, true)
	if len(r.Missing) != 0 {
		t.Errorf("missing: %v", r.Missing)
	}
	if len(r.Weak) != 0 {
		t.Errorf("weak: %v", r.Weak)
	}
	if len(r.Present) == 0 {
		t.Error("no headers were recorded as present")
	}
}

func TestAnalyzeSecurityHeadersFindsIssues(t *testing.T) {
	r := AnalyzeSecurityHeaders(map[string][]string{
		"Strict-Transport-Security":   {"max-age=10"},
		"Content-Security-Policy":     {"default-src * 'unsafe-inline' 'unsafe-eval'; script-src * data:"},
		"X-Content-Type-Options":      {"sniff"},
		"X-Frame-Options":             {"ALLOW-FROM https://evil.example"},
		"Referrer-Policy":             {"unsafe-url"},
		"Set-Cookie":                  {"session=abc"},
		"Access-Control-Allow-Origin": {"*"},
	}, true)
	if len(r.Weak) == 0 {
		t.Error("a CSP missing object-src, base-uri and frame-ancestors was not flagged")
	}
	notes := strings.Join(r.Notes, "; ")
	for _, want := range []string{"max-age", "Secure", "HttpOnly", "SameSite", "Access-Control-Allow-Origin"} {
		if !strings.Contains(notes, want) {
			t.Errorf("expected a note mentioning %q; got: %s", want, notes)
		}
	}
	// The cookie value must never be reproduced in a report field.
	if strings.Contains(notes, "abc") {
		t.Errorf("SECURITY: a cookie value leaked into the report: %s", notes)
	}
	for k, v := range r.Present {
		if strings.Contains(v, "abc") {
			t.Errorf("SECURITY: a cookie value leaked into present[%s]: %s", k, v)
		}
	}
}

func TestHSTSAnalysis(t *testing.T) {
	if present, _ := HSTSAnalysis(""); present {
		t.Error("an absent header must not be reported as present")
	}
	present, notes := HSTSAnalysis("max-age=31536000; includeSubDomains; preload")
	if !present {
		t.Fatal("HSTS was not detected")
	}
	if len(notes) == 0 {
		t.Error("a strong HSTS policy should still explain itself")
	}
	_, notes = HSTSAnalysis("max-age=0")
	if !strings.Contains(strings.Join(notes, " "), "disabled") &&
		!strings.Contains(strings.Join(notes, " "), "0") {
		t.Errorf("max-age=0 disables HSTS and should say so; got %v", notes)
	}
}

func TestParseCSPStrictness(t *testing.T) {
	weak := ParseCSP("default-src * 'unsafe-inline' 'unsafe-eval' data:")
	if !weak.Present {
		t.Error("a CSP was not detected")
	}
	if _, ok := weak.Directives["default-src"]; !ok {
		t.Error("default-src was not seen")
	}
	if !strings.Contains(strings.Join(weak.Notes, " "), "unsafe") {
		t.Errorf("unsafe directives were not reported: %v", weak.Notes)
	}
	if len(weak.Missing) == 0 {
		t.Error("object-src, base-uri and frame-ancestors are all missing")
	}
	strong := ParseCSP("default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
	if len(strong.Missing) != 0 {
		t.Errorf("a strict policy reported missing directives: %v", strong.Missing)
	}
	if strings.Contains(strings.Join(strong.Notes, " "), "unsafe") {
		t.Errorf("a strict policy was reported as unsafe: %v", strong.Notes)
	}
}

func TestParseSetCookieFlags(t *testing.T) {
	c := ParseSetCookie("session=abc123")
	if c.Secure || c.HTTPOnly || c.SameSite != "" {
		t.Errorf("a bare cookie was reported as hardened: %+v", c)
	}
	c = ParseSetCookie("session=abc; Secure; HttpOnly; SameSite=Strict")
	if !c.Secure || !c.HTTPOnly || c.SameSite != "Strict" {
		t.Errorf("flags were not parsed: %+v", c)
	}
	c = ParseSetCookie("id=x; secure; httponly; samesite=lax")
	if !c.Secure || !c.HTTPOnly {
		t.Errorf("attribute matching is not case-insensitive: %+v", c)
	}
}

func TestCookieParsingHostileInput(t *testing.T) {
	// A cookie header with no '=' and a pathological attribute list must not
	// panic or loop.
	for _, v := range []string{"", "=", ";;;;", "a" + strings.Repeat(";b", 5000),
		"x=y; Secure; Secure; Secure; Secure; Secure; Secure; Secure; Secure; Secure"} {
		c := ParseSetCookie(v)
		_ = c.Name
	}
}

func TestHeaderMetaCoversCatalogue(t *testing.T) {
	cat := HeaderCatalogue()
	if len(cat) == 0 {
		t.Fatal("the header catalogue is empty")
	}
	for _, h := range cat {
		why, rem, ok := HeaderMeta(h)
		if !ok {
			t.Errorf("%q is in the catalogue but has no metadata", h)
		}
		if why == "" || rem == "" {
			t.Errorf("%q is missing an explanation or a remediation", h)
		}
	}
	if _, _, ok := HeaderMeta("X-Not-A-Real-Header"); ok {
		t.Error("an unknown header reported metadata")
	}
}

func TestAnalyzeHandlesNilMapAndHostileHeaders(t *testing.T) {
	inputs := []map[string][]string{
		nil,
		{},
		{"Set-Cookie": {strings.Repeat("a=b; ", 20000)}},
		{"Content-Security-Policy": {strings.Repeat("default-src ", 20000)}},
		{"Strict-Transport-Security": {strings.Repeat("max-age=", 20000) + "999999999999999999999"}},
	}
	for i, in := range inputs {
		done := make(chan struct{})
		go func(in map[string][]string) {
			defer close(done)
			AnalyzeSecurityHeaders(in, true)
		}(in)
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Fatalf("header input %d did not terminate", i)
		}
	}
}

func hasNamePrefix(list []string, want string) bool {
	for _, s := range list {
		if s == want || strings.HasPrefix(s, want+" ") {
			return true
		}
	}
	return false
}
