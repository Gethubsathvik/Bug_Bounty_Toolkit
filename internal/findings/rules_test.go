package findings

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/bbtoolkit/bugbounty/internal/fingerprint"
	"github.com/bbtoolkit/bugbounty/pkg/models"
)

var testNow = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// --- engine construction -----------------------------------------------------

func TestNewEngineRejectsBadRules(t *testing.T) {
	ok := Rule{ID: "ok", Severity: models.SeverityLow, Confidence: models.ConfidenceHigh, Check: func(context.Context, Input) []Result { return nil }}

	cases := map[string]struct {
		rule Rule
		want error
	}{
		"no check function": {
			rule: Rule{ID: "x", Severity: models.SeverityLow, Confidence: models.ConfidenceHigh},
			want: ErrEmptyRule,
		},
		"no id": {
			rule: Rule{Severity: models.SeverityLow, Confidence: models.ConfidenceHigh, Check: ok.Check},
			want: ErrEmptyRule,
		},
		"invalid severity": {
			rule: Rule{ID: "x", Severity: models.Severity("catastrophic"), Confidence: models.ConfidenceHigh, Check: ok.Check},
		},
		"invalid confidence": {
			rule: Rule{ID: "x", Severity: models.SeverityLow, Confidence: models.Confidence("certain"), Check: ok.Check},
		},
		"manual verification with no steps": {
			rule: Rule{ID: "x", Severity: models.SeverityLow, Confidence: models.ConfidenceHigh, Check: ok.Check, ManualVerificationRequired: true},
			want: nil, // a distinct error, checked by message below
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := NewEngine(tc.rule)
			if err == nil {
				t.Fatalf("SECURITY/robustness: %s was accepted", name)
			}
			if tc.want != nil && !strings.Contains(err.Error(), tc.want.Error()) {
				t.Errorf("error = %v, want it to mention %v", err, tc.want)
			}
		})
	}
}

func TestNewEngineRejectsDuplicateIDs(t *testing.T) {
	r := Rule{ID: "dup", Severity: models.SeverityLow, Confidence: models.ConfidenceHigh, Check: func(context.Context, Input) []Result { return nil }}
	if _, err := NewEngine(r, r); err == nil {
		t.Fatal("a duplicate rule ID was accepted; the suppress list would be ambiguous")
	}
}

func TestDefaultEngineIsValid(t *testing.T) {
	e := DefaultEngine()
	ids := e.RuleIDs()
	if len(ids) < 10 {
		t.Fatalf("the default rule set only has %d rules", len(ids))
	}
	seen := map[string]struct{}{}
	for _, id := range ids {
		if _, dup := seen[id]; dup {
			t.Errorf("duplicate default rule ID %q", id)
		}
		seen[id] = struct{}{}
	}
	for _, r := range e.Rules() {
		if !r.Severity.Valid() {
			t.Errorf("rule %q has invalid severity %q", r.ID, r.Severity)
		}
		if !r.Confidence.Valid() {
			t.Errorf("rule %q has invalid confidence %q", r.ID, r.Confidence)
		}
		if r.Description == "" {
			t.Errorf("rule %q has no description; a report would show a title and nothing else", r.ID)
		}
		if r.Impact == "" {
			t.Errorf("rule %q has no impact statement", r.ID)
		}
	}
}

func TestFilterSelectsRules(t *testing.T) {
	e := DefaultEngine()
	one := e.Filter([]string{RuleMissingHSTS})
	ids := one.RuleIDs()
	if len(ids) != 1 || ids[0] != RuleMissingHSTS {
		t.Errorf("Filter returned %v", ids)
	}
	if got := e.Filter(nil).RuleIDs(); len(got) != len(e.RuleIDs()) {
		t.Error("an empty filter should keep every rule")
	}
	if got := e.Filter([]string{"no-such-rule"}).RuleIDs(); len(got) != 0 {
		t.Errorf("selecting an unknown rule produced %v", got)
	}
}

// --- evaluation --------------------------------------------------------------

func runRules(t *testing.T, rules []Rule, in Input) []models.Finding {
	t.Helper()
	e, err := NewEngine(rules...)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if in.Now.IsZero() {
		in.Now = testNow
	}
	out, errs := e.Evaluate(context.Background(), in)
	for _, err := range errs {
		t.Errorf("unexpected evaluation error: %v", err)
	}
	return out
}

func hasFindingType(in []models.Finding, id string) bool {
	for _, f := range in {
		if f.Type == id {
			return true
		}
	}
	return false
}

func findByType(in []models.Finding, id string) *models.Finding {
	for i := range in {
		if in[i].Type == id {
			return &in[i]
		}
	}
	return nil
}

func TestEvaluateProducesRedactedEvidence(t *testing.T) {
	// Everything in a Result comes from the target, so a target that reflects a
	// credential back at us must not end up with that credential in the report.
	rule := Rule{
		ID:          "reflects-secrets",
		Title:       "Response reflects a value",
		Severity:    models.SeverityMedium,
		Confidence:  models.ConfidenceHigh,
		Description: "d", Impact: "i",
		Check: func(context.Context, Input) []Result {
			return []Result{{
				Summary: "server said: api_key=AKIAIOSFODNN7EXAMPLE and token: ghp_0123456789abcdefghijklmnopqrstuvwx",
				Data: map[string]string{
					"password": "hunter2",
					"harmless": "value",
				},
			}}
		},
	}
	out := runRules(t, []Rule{rule}, Input{Asset: "example.com"})
	if len(out) != 1 {
		t.Fatalf("got %d findings, want 1", len(out))
	}
	f := out[0]
	if f.ID == "" {
		t.Error("the finding has no ID")
	}
	if f.FirstSeen != testNow || f.LastSeen != testNow {
		t.Errorf("timestamps = %v/%v, want the injected clock", f.FirstSeen, f.LastSeen)
	}
	ev := f.Evidence[0]
	for _, secret := range []string{"AKIAIOSFODNN7EXAMPLE", "ghp_0123456789abcdefghijklmnopqrstuvwx"} {
		if strings.Contains(ev.Summary, secret) {
			t.Errorf("SECURITY: evidence summary leaked %q: %s", secret, ev.Summary)
		}
	}
	if !strings.Contains(ev.Summary, "server said:") {
		t.Errorf("redaction destroyed the non-secret text: %q", ev.Summary)
	}
	if !ev.Redacted {
		t.Error("the evidence was modified but not marked as redacted")
	}
	if got := ev.Data["password"]; got == "hunter2" {
		t.Errorf("SECURITY: a value under a sensitive key survived redaction: %q", got)
	}
	if got := ev.Data["harmless"]; got != "value" {
		t.Errorf("a harmless value was altered: %q", got)
	}
	if ev.Data["redaction_applied"] != "true" {
		t.Error("the evidence does not record that redaction was applied")
	}
}

func TestEvaluateRedactsSecretsInTheEndpoint(t *testing.T) {
	rule := Rule{
		ID: "endpoint-rule", Title: "t", Severity: models.SeverityLow, Confidence: models.ConfidenceLow,
		Description: "d", Impact: "i",
		Check: func(context.Context, Input) []Result {
			return []Result{{Endpoint: "https://example.com/x?token=supersecretvalue&page=2"}}
		},
	}
	out := runRules(t, []Rule{rule}, Input{Asset: "example.com"})
	if strings.Contains(out[0].Endpoint, "supersecretvalue") {
		t.Errorf("SECURITY: the endpoint leaked its token: %s", out[0].Endpoint)
	}
	if !strings.Contains(out[0].Endpoint, "page=2") {
		t.Errorf("redaction removed an ordinary parameter: %s", out[0].Endpoint)
	}
}

func TestEvaluateIsolatesAPanickingRule(t *testing.T) {
	good := Rule{
		ID: "good", Title: "t", Severity: models.SeverityLow, Confidence: models.ConfidenceLow,
		Description: "d", Impact: "i",
		Check: func(context.Context, Input) []Result {
			return []Result{{Summary: "fine"}}
		},
	}
	bad := Rule{
		ID: "bad", Title: "t", Severity: models.SeverityLow, Confidence: models.ConfidenceLow,
		Description: "d", Impact: "i",
		Check: func(context.Context, Input) []Result {
			panic("index out of range")
		},
	}
	e, err := NewEngine(good, bad)
	if err != nil {
		t.Fatal(err)
	}
	out, errs := e.Evaluate(context.Background(), Input{Asset: "example.com", Now: testNow})

	// A panicking rule must not take the run down, and must not be reported as
	// a clean result either: the operator has to learn the check never ran.
	if len(out) != 1 || out[0].Type != "good" {
		t.Fatalf("the healthy rule's output was lost: %+v", out)
	}
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "panicked") {
		t.Errorf("errs = %v, want one report of the panic", errs)
	}
}

func TestEvaluateStopsOnContextCancellation(t *testing.T) {
	rule := Rule{
		ID: "r", Title: "t", Severity: models.SeverityLow, Confidence: models.ConfidenceLow,
		Description: "d", Impact: "i",
		Check: func(context.Context, Input) []Result { return []Result{{Summary: "x"}} },
	}
	e, _ := NewEngine(rule)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, errs := e.Evaluate(ctx, Input{Asset: "example.com", Now: testNow})
	if len(errs) == 0 {
		t.Fatal("a cancelled context produced no error")
	}
}

func TestEvaluatePicksAnAssetWhenNoneWasGiven(t *testing.T) {
	rule := Rule{
		ID: "r", Title: "t", Severity: models.SeverityLow, Confidence: models.ConfidenceLow,
		Description: "d", Impact: "i",
		Check: func(context.Context, Input) []Result { return []Result{{Summary: "x"}} },
	}
	e, _ := NewEngine(rule)
	out, errs := e.Evaluate(context.Background(), Input{
		Now:  testNow,
		HTTP: []models.HTTPSvc{{URL: "https://primary.example/", StatusCode: 200}},
	})
	if len(errs) != 0 {
		t.Fatalf("errs = %v", errs)
	}
	if out[0].Asset != "https://primary.example/" {
		t.Errorf("Asset = %q, want the first probed URL", out[0].Asset)
	}
}

func TestEvaluateResultOverridesWinOverRuleDefaults(t *testing.T) {
	rule := Rule{
		ID: "r", Title: "t", Severity: models.SeverityLow, Confidence: models.ConfidenceLow,
		Description: "d", Impact: "i",
		Check: func(context.Context, Input) []Result {
			sev := models.SeverityHigh
			return []Result{{Summary: "x", Severity: &sev}}
		},
	}
	out := runRules(t, []Rule{rule}, Input{Asset: "example.com"})
	if out[0].Severity != models.SeverityHigh {
		t.Errorf("Severity = %q, want the override to win", out[0].Severity)
	}
}

func TestEvaluateIgnoresAnInvalidOverride(t *testing.T) {
	rule := Rule{
		ID: "r", Title: "t", Severity: models.SeverityLow, Confidence: models.ConfidenceMedium,
		Description: "d", Impact: "i",
		Check: func(context.Context, Input) []Result {
			bad := models.Severity("nonsense")
			badConf := models.Confidence("also nonsense")
			return []Result{{Summary: "x", Severity: &bad, Confidence: &badConf}}
		},
	}
	out := runRules(t, []Rule{rule}, Input{Asset: "example.com"})
	// An unparseable override must not silently blank out the rule's rating.
	if out[0].Severity != models.SeverityLow || out[0].Confidence != models.ConfidenceMedium {
		t.Errorf("got %q/%q, want the rule defaults to be kept", out[0].Severity, out[0].Confidence)
	}
}

// --- header rules ------------------------------------------------------------

func svc(url string, status int, present map[string]string, notes ...string) models.HTTPSvc {
	return models.HTTPSvc{
		URL:        url,
		StatusCode: status,
		Security:   models.SecurityHeaderReport{Present: present, Notes: notes},
	}
}

func TestMissingHSTSOnlyForHTTPSHosts(t *testing.T) {
	out := runRules(t, DefaultRules(), Input{
		Asset: "example.com",
		HTTP: []models.HTTPSvc{
			svc("https://example.com/", 200, map[string]string{}),
			svc("http://example.com/", 200, map[string]string{}),
		},
		Now: testNow,
	})
	f := findByType(out, RuleMissingHSTS)
	if f == nil {
		t.Fatal("no HSTS finding for the HTTPS host")
	}
	if f.Endpoint != "https://example.com/" {
		t.Errorf("Endpoint = %q, want only the HTTPS URL", f.Endpoint)
	}
}

func TestMissingHSTSIsSuppressedWhenTheHostDoesNotServeHTTPS(t *testing.T) {
	// The no-HTTPS rule is the finding that matters here. Reporting the
	// absence of HSTS as well is noise that buries it.
	out := runRules(t, DefaultRules(), Input{
		Asset: "example.com",
		HTTP:  []models.HTTPSvc{svc("http://example.com/", 200, map[string]string{})},
		Now:   testNow,
	})
	if hasFindingType(out, RuleMissingHSTS) {
		t.Error("HSTS was reported for a host that does not serve HTTPS")
	}
	if !hasFindingType(out, RuleHTTPSPresent) {
		t.Error("the absence of HTTPS itself was not reported")
	}
}

func TestMissingHSTSSeverityRisesWithOtherWeakHeaders(t *testing.T) {
	base := map[string]string{"x-frame-options": "DENY"}
	withWeak := map[string]string{"x-frame-options": "SAMEORIGIN"}

	out := runRules(t, DefaultRules(), Input{
		Asset: "example.com",
		HTTP: []models.HTTPSvc{
			{URL: "https://a.example/", StatusCode: 200, Security: models.SecurityHeaderReport{Present: base}},
			{URL: "https://b.example/", StatusCode: 200, Security: models.SecurityHeaderReport{Present: withWeak, Weak: []string{"x-frame-options"}}},
		},
		Now: testNow,
	})
	var low, higher models.Severity
	for _, f := range out {
		if f.Type != RuleMissingHSTS {
			continue
		}
		if f.Endpoint == "https://a.example/" {
			low = f.Severity
		} else {
			higher = f.Severity
		}
	}
	if low == "" || higher == "" {
		t.Fatalf("expected two HSTS findings, got %+v", out)
	}
	if higher.SeverityRank() <= low.SeverityRank() {
		t.Errorf("severities = %q vs %q; the host with other weak headers should rank higher", low, higher)
	}
}

func TestMissingCSPIsNotReportedForNonHTML(t *testing.T) {
	out := runRules(t, DefaultRules(), Input{
		Asset: "example.com",
		HTTP: []models.HTTPSvc{
			{URL: "https://example.com/api", StatusCode: 200, ContentType: "application/json",
				Security: models.SecurityHeaderReport{Present: map[string]string{}}},
		},
		Now: testNow,
	})
	if hasFindingType(out, RuleMissingCSP) {
		t.Error("a missing CSP was reported for a JSON endpoint, where it has no effect")
	}
}

func TestXFrameOptionsIsSuppressedByCSPFrameAncestors(t *testing.T) {
	out := runRules(t, DefaultRules(), Input{
		Asset: "example.com",
		HTTP: []models.HTTPSvc{{
			URL:         "https://example.com/",
			StatusCode:  200,
			ContentType: "text/html",
			Security: models.SecurityHeaderReport{
				Present: map[string]string{
					"content-security-policy": "frame-ancestors 'none'",
				},
			},
		}},
		Now: testNow,
	})
	if hasFindingType(out, RuleMissingXFrameOptions) {
		t.Error("X-Frame-Options was reported even though frame-ancestors covers it")
	}
}

func TestServerVersionDisclosureNeedsAVersion(t *testing.T) {
	out := runRules(t, DefaultRules(), Input{
		Asset: "example.com",
		HTTP: []models.HTTPSvc{
			{URL: "https://plain.example/", StatusCode: 200, Security: models.SecurityHeaderReport{Present: map[string]string{"server": "nginx"}}},
			{URL: "https://leaky.example/", StatusCode: 200, Security: models.SecurityHeaderReport{Present: map[string]string{"server": "nginx/1.18.0"}}},
		},
		Now: testNow,
	})
	var endpoints []string
	for _, f := range out {
		if f.Type == RuleServerVersionLeak {
			endpoints = append(endpoints, f.Endpoint)
			if f.Status != models.StatusNeedsManual {
				t.Errorf("a version disclosure should require manual verification, status is %q", f.Status)
			}
		}
	}
	if len(endpoints) != 1 || !strings.Contains(endpoints[0], "leaky") {
		t.Errorf("reported = %v, want only the host that names a version", endpoints)
	}
}

func TestDisclosesVersion(t *testing.T) {
	cases := map[string]bool{
		"nginx":                 false,
		"nginx/1.18.0":          true,
		"Apache/2.4.51":         true,
		"cloudflare":            false,
		"-":                     false,
		"":                      false,
		"PHP/8.1.2":             true,
		"gunicorn (no version)": false,
	}
	for in, want := range cases {
		if got := disclosesVersion(in); got != want {
			t.Errorf("disclosesVersion(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestCookieRules(t *testing.T) {
	out := runRules(t, DefaultRules(), Input{
		Asset: "example.com",
		HTTP: []models.HTTPSvc{{
			URL:        "https://example.com/",
			StatusCode: 200,
			Security: models.SecurityHeaderReport{
				Notes: []string{"Set-Cookie session is missing Secure; missing HttpOnly"},
			},
		}},
		Now: testNow,
	})
	if !hasFindingType(out, RuleCookieNoSecure) {
		t.Error("a cookie missing Secure was not reported")
	}
	if !hasFindingType(out, RuleCookieNoHTTPOnly) {
		t.Error("a cookie missing HttpOnly was not reported")
	}
}

func TestCookieRulesIgnoreUnrelatedNotes(t *testing.T) {
	out := runRules(t, DefaultRules(), Input{
		Asset: "example.com",
		HTTP: []models.HTTPSvc{{
			URL:        "https://example.com/",
			StatusCode: 200,
			Security:   models.SecurityHeaderReport{Notes: []string{"no cookies were set"}},
		}},
		Now: testNow,
	})
	if hasFindingType(out, RuleCookieNoSecure) || hasFindingType(out, RuleCookieNoHTTPOnly) {
		t.Error("a cookie finding was produced from an unrelated note")
	}
}

// --- TLS rules ---------------------------------------------------------------

func TestExpiredCertificateSeverityDependsOnThePath(t *testing.T) {
	out := runRules(t, DefaultRules(), Input{
		Asset: "example.com",
		HTTP: []models.HTTPSvc{
			{URL: "https://example.com/about", StatusCode: 200, TLS: &models.TLSInfo{Expired: true, NotAfter: testNow.AddDate(0, -1, 0)}},
			{URL: "https://example.com/login", StatusCode: 200, TLS: &models.TLSInfo{Expired: true, NotAfter: testNow.AddDate(0, -1, 0)}},
		},
		Now: testNow,
	})
	var byPath = map[string]models.Severity{}
	for _, f := range out {
		if f.Type == RuleTLSCertificateExpired {
			byPath[f.Endpoint] = f.Severity
		}
	}
	if byPath["https://example.com/about"] != models.SeverityHigh {
		t.Errorf("an expired certificate on a public page should be high, got %q", byPath["https://example.com/about"])
	}
	if byPath["https://example.com/login"] != models.SeverityCritical {
		t.Errorf("an expired certificate on a login page should be critical, got %q", byPath["https://example.com/login"])
	}
}

func TestUnexpiredCertificateIsNotReported(t *testing.T) {
	out := runRules(t, DefaultRules(), Input{
		Asset: "example.com",
		HTTP: []models.HTTPSvc{
			{URL: "https://example.com/", StatusCode: 200, TLS: &models.TLSInfo{NotAfter: testNow.AddDate(1, 0, 0)}},
		},
		Now: testNow,
	})
	if hasFindingType(out, RuleTLSCertificateExpired) {
		t.Error("a valid certificate was reported as expired")
	}
}

func TestWeakTLSVersionAndCipher(t *testing.T) {
	out := runRules(t, DefaultRules(), Input{
		Asset: "example.com",
		HTTP: []models.HTTPSvc{
			{URL: "https://old.example/", StatusCode: 200, TLS: &models.TLSInfo{Version: "TLS 1.0"}},
			{URL: "https://exp.example/", StatusCode: 200, TLS: &models.TLSInfo{Version: "TLS 1.2", CipherSuite: "TLS_RSA_WITH_RC4_128_SHA"}},
			{URL: "https://ok.example/", StatusCode: 200, TLS: &models.TLSInfo{Version: "TLS 1.3", CipherSuite: "TLS_AES_128_GCM_SHA256"}},
		},
		Now: testNow,
	})
	var versions, ciphers int
	for _, f := range out {
		switch f.Type {
		case RuleTLSWeakVersion:
			versions++
		case RuleTLSWeakCipher:
			ciphers++
		}
	}
	if versions != 1 {
		t.Errorf("weak version findings = %d, want 1", versions)
	}
	if ciphers != 1 {
		t.Errorf("weak cipher findings = %d, want 1", ciphers)
	}
}

func TestWeakCipherIgnoresAnEmptySuiteName(t *testing.T) {
	// An empty suite name means the handshake did not complete. Claiming the
	// cipher is weak would be reporting a guess.
	if weakCipher("") {
		t.Error("an empty cipher name was treated as weak")
	}
}

func TestSANOutOfScopeNames(t *testing.T) {
	out := runRules(t, DefaultRules(), Input{
		Asset: "example.com",
		HTTP: []models.HTTPSvc{{
			URL:        "https://example.com/",
			StatusCode: 200,
			TLS: &models.TLSInfo{SANs: []string{
				"example.com", "www.example.com", "other-tenant.net", "203.0.113.10",
			}},
		}},
		Now: testNow,
	})
	var named []string
	for _, f := range out {
		if f.Type == RuleTLSSANOutOfScope {
			named = append(named, f.Evidence[0].Data["san"])
			if !f.ManualVerificationRequired {
				t.Error("a SAN belonging to another organisation must require manual verification")
			}
		}
	}
	if len(named) != 1 || named[0] != "other-tenant.net" {
		t.Errorf("named = %v, want only the third-party host", named)
	}
}

// --- DNS rules ---------------------------------------------------------------

func dnsRec(t models.RecordType, value string) models.DNSRecord {
	return models.DNSRecord{Name: "example.com", Type: t, Value: value}
}

func TestSPFAndDMARCAreNotReportedWithoutMX(t *testing.T) {
	out := runRules(t, DefaultRules(), Input{
		Asset:   "example.com",
		Posture: []models.SecurityPosture{{HasSPF: false, HasDMARC: false, HasCAA: false, HasMX: false}},
		Now:     testNow,
	})
	if hasFindingType(out, RuleDNSMissingSPF) {
		t.Error("a missing SPF record was reported for a zone that receives no mail")
	}
	if hasFindingType(out, RuleDNSMissingDMARC) {
		t.Error("a missing DMARC record was reported for a zone that receives no mail")
	}
	if !hasFindingType(out, RuleDNSMissingCAA) {
		t.Error("a missing CAA record should still be reported")
	}
}

func TestPermissiveSPF(t *testing.T) {
	cases := map[string]bool{
		"v=spf1 include:_spf.google.com all":   true,
		"v=spf1 ip4:192.0.2.1 +all":            true,
		"v=spf1 include:_spf.example.com ~all": false,
		"v=spf1 include:_spf.example.com -all": false,
		"v=spf1 mx -all":                       false,
		"google-site-verification=abc":         false,
		"":                                     false,
		"v=spf1 redirect=_spf.example.com":     false,
	}
	for in, want := range cases {
		if got := permissiveSPF(in); got != want {
			t.Errorf("permissiveSPF(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestPermissiveSPFIsReported(t *testing.T) {
	out := runRules(t, DefaultRules(), Input{
		Asset: "example.com",
		DNS: []models.DNSResult{{
			Name:    "example.com",
			Records: []models.DNSRecord{dnsRec(models.RecordTXT, "v=spf1 include:_spf.google.com all")},
		}},
		Now: testNow,
	})
	f := findByType(out, RuleDNSPermissiveSPF)
	if f == nil {
		t.Fatal("a permissive SPF record was not reported")
	}
	if f.Severity != models.SeverityMedium {
		t.Errorf("Severity = %q, want medium", f.Severity)
	}
}

func TestDanglingRecordRanksAboveAPlainPrivateAnswer(t *testing.T) {
	out := runRules(t, DefaultRules(), Input{
		Asset: "example.com",
		DNS: []models.DNSResult{
			{Name: "a.example.com", Unconnectable: []string{"10.0.0.1"}},
			{Name: "b.example.com", Unconnectable: []string{"169.254.169.254"}, Dangling: true},
		},
		Now: testNow,
	})
	byAsset := map[string]models.Severity{}
	for _, f := range out {
		if f.Type == RuleDNSUnconnectableTarget {
			byAsset[f.Asset] = f.Severity
		}
	}
	if byAsset["b.example.com"] != models.SeverityHigh {
		t.Errorf("a dangling record should be high, got %q", byAsset["b.example.com"])
	}
	if byAsset["a.example.com"] != models.SeverityMedium {
		t.Errorf("a private answer should be medium, got %q", byAsset["a.example.com"])
	}
}

func TestSubdomainInventoryIsInformational(t *testing.T) {
	out := runRules(t, DefaultRules(), Input{
		Asset: "example.com",
		DNS: []models.DNSResult{{
			Name:     "www.example.com",
			Resolved: true,
			Records:  []models.DNSRecord{dnsRec(models.RecordA, "192.0.2.1")},
		}},
		Now: testNow,
	})
	f := findByType(out, RuleDNSSubdomain)
	if f == nil {
		t.Fatal("a discovered subdomain was not reported")
	}
	if f.Severity != models.SeverityInformational {
		t.Errorf("Severity = %q, want informational; an asset inventory is not a defect", f.Severity)
	}
	if f.Asset != "www.example.com" {
		t.Errorf("Asset = %q, want the discovered name rather than the zone", f.Asset)
	}
}

// --- surface rules -----------------------------------------------------------

func TestAdminSurfaceMatchesWholeSegments(t *testing.T) {
	out := runRules(t, DefaultRules(), Input{
		Asset: "example.com",
		Endpoints: []models.Endpoint{
			{URL: "https://example.com/admin", Kind: models.EndpointLink, StatusCode: 200},
			{URL: "https://example.com/administration-guide", Kind: models.EndpointLink, StatusCode: 200},
			{URL: "https://example.com/about", Kind: models.EndpointLink, StatusCode: 200},
			{URL: "https://example.com/admin", Kind: models.EndpointLink, StatusCode: 200},
		},
		Now: testNow,
	})
	var paths []string
	for _, f := range out {
		if f.Type == RuleAdminSurface {
			paths = append(paths, f.Evidence[0].Data["url"])
			if !f.ManualVerificationRequired {
				t.Error("an administrative surface candidate must require manual verification")
			}
		}
	}
	if len(paths) != 1 || !strings.HasSuffix(paths[0], "/admin") {
		t.Errorf("paths = %v; only the exact segment should match, and duplicates should collapse", paths)
	}
}

func TestRedirectParameterCandidates(t *testing.T) {
	out := runRules(t, DefaultRules(), Input{
		Asset: "example.com",
		Endpoints: []models.Endpoint{{
			URL:  "https://example.com/go",
			Kind: models.EndpointLink,
			Parameters: []models.Parameter{
				{Name: "next", Kind: models.ParamQuery},
				{Name: "page", Kind: models.ParamQuery},
			},
		}},
		Now: testNow,
	})
	if !hasFindingType(out, RuleOpenRedirectCandidate) {
		t.Fatal("the redirect parameter was not reported")
	}
	for _, f := range out {
		if f.Type != RuleOpenRedirectCandidate {
			continue
		}
		if p := f.Evidence[0].Data["parameter"]; p != "next" {
			t.Errorf("parameter = %q, want only the redirect-shaped one", p)
		}
	}
}

func TestSurfaceRulesRedactHostileParameterNames(t *testing.T) {
	out := runRules(t, DefaultRules(), Input{
		Asset: "example.com",
		Endpoints: []models.Endpoint{{
			URL:  "https://example.com/go?next=x",
			Kind: models.EndpointLink,
			Parameters: []models.Parameter{
				{Name: "next\x00password=hunter2", Kind: models.ParamQuery},
			},
		}},
		Now: testNow,
	})
	for _, f := range out {
		if f.Type != RuleOpenRedirectCandidate {
			continue
		}
		if strings.Contains(f.Evidence[0].Data["parameter"], "\x00") {
			t.Errorf("SECURITY: a NUL byte from a parameter name reached evidence: %q", f.Evidence[0].Data["parameter"])
		}
	}
}

// --- technology baseline -----------------------------------------------------

func TestOutdatedTechnologyRequiresTheOperatorBaseline(t *testing.T) {
	in := Input{Asset: "example.com", Now: testNow, Tech: []fingerprint.Hit{
		{Name: "nginx", Version: "1.14.0", Evidence: "Server: nginx/1.14.0"},
	}}
	if hasFindingType(runRules(t, DefaultRules(), in), RuleTechOutdated) {
		t.Error("a technology was declared outdated with no baseline configured")
	}

	in.Baseline = NewBaseline(map[string]TechState{
		"nginx": {Latest: "1.24", Outdated: true, Reason: "1.24 is the current stable release"},
	})
	f := findByType(runRules(t, DefaultRules(), in), RuleTechOutdated)
	if f == nil {
		t.Fatal("the outdated technology was not reported once a baseline existed")
	}
	if !f.ManualVerificationRequired {
		t.Error("a fingerprinted version must be confirmed by a human before it is filed")
	}
}

func TestEndOfLifeTechnologyOutranksSimplyOutdated(t *testing.T) {
	in := Input{Asset: "example.com", Now: testNow, Tech: []fingerprint.Hit{
		{Name: "oldapp", Version: "1.0"},
		{Name: "stableapp", Version: "1.0"},
	}, Baseline: NewBaseline(map[string]TechState{
		"oldapp":    {Latest: "n/a", Outdated: true, EndOfLife: true, Reason: "the product line is no longer maintained"},
		"stableapp": {Latest: "2.0", Outdated: true, Reason: "2.0 is the current stable release"},
	})}
	byTech := map[string]models.Severity{}
	for _, f := range runRules(t, DefaultRules(), in) {
		if f.Type == RuleTechOutdated {
			byTech[f.Evidence[0].Data["technology"]] = f.Severity
		}
	}
	if byTech["oldapp"] != models.SeverityMedium {
		t.Errorf("an end-of-life product ranked %q, want medium", byTech["oldapp"])
	}
	if byTech["stableapp"] != models.SeverityLow {
		t.Errorf("an outdated but supported product ranked %q, want low", byTech["stableapp"])
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0},
		{"1.2", "1.2.0", 0},
		{"1.2.3", "1.10.0", -1},
		{"1.10.0", "1.9.9", 1},
		{"1.18.0-alpine", "1.18.0", 0},
		{"1.18.0", "1.18", 0},
		{"", "1.0", 0},
		{"unknown", "1.0", 0},
		{"abc", "def", 0},
		{"1.2.3.4", "1.2.3", 1},
	}
	for _, tc := range cases {
		if got := CompareVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestBaselineLookupIsCaseInsensitive(t *testing.T) {
	b := NewBaseline(map[string]TechState{"Nginx": {Latest: "1.24"}})
	if _, ok := b.Lookup("nginx"); !ok {
		t.Error("baseline lookup is case sensitive")
	}
	if len(b.Products()) != 1 {
		t.Errorf("Products = %v", b.Products())
	}
}
