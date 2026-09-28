package scope

import (
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

func mustEngine(t *testing.T, allowed, excluded []string) *Engine {
	t.Helper()
	e, err := New(allowed, excluded, DefaultPolicy())
	if err != nil {
		t.Fatalf("New(%v, %v): %v", allowed, excluded, err)
	}
	return e
}

func TestCanonicalizeDomain(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"example.com", "example.com"},
		{"EXAMPLE.COM", "example.com"},
		{"example.com.", "example.com"},
		{"  example.com  ", "example.com"},
		{"sub.Example.Com", "sub.example.com"},
		{"https://api.example.com/v1", "api.example.com"},
		{"https://api.example.com:8443/v1", "api.example.com"},
		{"1.2.3.4", "1.2.3.4"},
		{"::ffff:1.2.3.4", "1.2.3.4"}, // IPv4-mapped must normalize to IPv4
		{"[2001:db8::1]", "2001:db8::1"},
		{"2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"},
		{"bücher.example", "xn--bcher-kva.example"},
		{"xn--bcher-kva.example", "xn--bcher-kva.example"},
		// IDNA must be injective: sharp s must NOT fold to "ss".
		{"faß.de", "xn--fa-hia.de"},
		{"fass.de", "fass.de"},
	}
	for _, tc := range cases {
		got, err := CanonicalizeDomain(tc.in)
		if err != nil {
			t.Errorf("CanonicalizeDomain(%q): unexpected error %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("CanonicalizeDomain(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCanonicalizeDomainRejects(t *testing.T) {
	bad := []string{
		"", " ", ".", "..", "example", "exa mple.com", "exam\tple.com",
		"exa_mple.com",         // underscore is not a legal LDH label
		"example.com\x00.evil", // NUL byte
		"example.com/../evil",  // path traversal in a host
		"-example.com",         // leading hyphen
		"example-.com",         // trailing hyphen
		"a..b.com",             // empty label
		"example.com:99999",    // port out of range
		"fe80::1%eth0",         // zone identifiers are not accepted here
		"exa[mple.com",         // illegal byte
		"пример.рф",            // valid IDN TLD; accepted below, not here
	}
	for _, in := range bad {
		// A couple of the above are actually expected to be valid; assert only
		// the ones that are genuinely invalid.
		switch in {
		case "пример.рф":
			continue
		}
		if got, err := CanonicalizeDomain(in); err == nil {
			t.Errorf("CanonicalizeDomain(%q) unexpectedly succeeded as %q", in, got)
		}
	}
}

func TestCanonicalizeDomainAcceptsIDN(t *testing.T) {
	got, err := CanonicalizeDomain("пример.рф")
	if err != nil {
		t.Fatalf("expected IDN to be accepted: %v", err)
	}
	if got != "xn--e1afmkfd.xn--p1ai" {
		t.Errorf("got %q, want xn--e1afmkfd.xn--p1ai", got)
	}
}

func TestIDNIsInjective(t *testing.T) {
	// The two names below differ by one character. If canonicalization folded
	// characters, one of them would match an in-scope rule for the other.
	a, err1 := CanonicalizeDomain("xn--fa-hia.de")
	b, err2 := CanonicalizeDomain("fass.de")
	if err1 != nil || err2 != nil {
		t.Fatalf("canonicalize: %v %v", err1, err2)
	}
	if a == b {
		t.Fatalf("IDN folding is not injective: %q and %q collapsed to the same name", a, b)
	}
}

// --- SECURITY TEST 1: out-of-scope domains cannot be scanned -----------------

func TestOutOfScopeDomainDenied(t *testing.T) {
	e := mustEngine(t, []string{"example.com", "*.example.com"}, nil)

	inScope := []string{
		"example.com", "api.example.com", "a.b.c.example.com",
	}
	for _, h := range inScope {
		if d := e.CheckHost(h); !d.Allowed {
			t.Errorf("CheckHost(%q) denied: %s", h, d.Reason)
		}
	}

	outOfScope := []string{
		"evil.com", "example.com.evil.com", "notexample.com", "example.org",
		"example.co", "example.comm", "xexample.com",
		// A trailing root label is the same name, so it is (correctly) in
		// scope; a doubled label is not the same name and must be denied.
		"example.com..",
	}
	for _, h := range outOfScope {
		if d := e.CheckHost(h); d.Allowed {
			t.Errorf("SECURITY: CheckHost(%q) was ALLOWED by rule %q - scope bypass", h, d.Rule)
		}
	}
}

func TestEmptyScopeDeniesEverything(t *testing.T) {
	e, err := New(nil, nil, DefaultPolicy())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, h := range []string{"example.com", "localhost", "127.0.0.1", "8.8.8.8"} {
		if e.CheckHost(h).Allowed {
			t.Errorf("SECURITY: empty scope allowed %q", h)
		}
	}
	if err := e.RequireActive(); err == nil {
		t.Error("SECURITY: RequireActive() succeeded with an empty scope")
	}
}

func TestDenyAllEngine(t *testing.T) {
	e := NewDenyAll()
	if e.CheckHost("example.com").Allowed {
		t.Error("SECURITY: deny-all engine allowed a host")
	}
	if err := e.RequireActive(); err == nil {
		t.Error("SECURITY: deny-all engine permitted active work")
	}
}

// --- SECURITY TEST 3: excluded subdomains are never admitted ----------------

func TestExclusionsWin(t *testing.T) {
	e := mustEngine(t,
		[]string{"*.example.com"},
		[]string{"admin.example.com", "*.internal.example.com", "test.example.com"},
	)

	denied := []string{
		"admin.example.com",
		"www.internal.example.com",
		"deep.nested.internal.example.com",
		"test.example.com",
		// Exclusion must also defeat a broad allow of the exact host.
		"admin.example.com:443",
	}
	for _, h := range denied {
		if d := e.CheckHost(h); d.Allowed {
			t.Errorf("SECURITY: excluded host %q was ALLOWED by %q", h, d.Rule)
		}
	}

	allowed := []string{"api.example.com", "cdn.example.com"}
	for _, h := range allowed {
		if d := e.CheckHost(h); !d.Allowed {
			t.Errorf("host %q should be allowed: %s", h, d.Reason)
		}
	}
}

func TestExclusionOfParentRemovesSubdomains(t *testing.T) {
	e := mustEngine(t, []string{"*.example.com"}, []string{"internal.example.com"})
	if d := e.CheckHost("api.internal.example.com"); d.Allowed {
		t.Errorf("SECURITY: %q allowed despite parent exclusion (%s)", "api.internal.example.com", d.Rule)
	}
}

// --- wildcard rules ---------------------------------------------------------

func TestWildcardDoesNotMatchApex(t *testing.T) {
	e := mustEngine(t, []string{"*.example.com"}, nil)
	if e.CheckHost("example.com").Allowed {
		t.Error("SECURITY: wildcard matched its own apex domain")
	}
	if !e.CheckHost("a.example.com").Allowed {
		t.Error("wildcard should match a subdomain")
	}
}

func TestWildcardRejectsPublicSuffix(t *testing.T) {
	for _, bad := range []string{"*.com", "*.co.uk", "*.localhost", "*.internal", "*", "*.", "com"} {
		if _, err := ParseRule(bad); err == nil {
			t.Errorf("SECURITY: rule %q was accepted but must be rejected", bad)
		}
	}
}

func TestWildcardRejectsPartialLabel(t *testing.T) {
	for _, bad := range []string{"*example.com", "example*.com", "e*ple.com", "*.*.example.com", "**.example.com"} {
		if _, err := ParseRule(bad); err == nil {
			t.Errorf("SECURITY: malformed wildcard %q was accepted", bad)
		}
	}
}

func TestWildcardSuffixConfusion(t *testing.T) {
	e := mustEngine(t, []string{"*.example.com"}, nil)
	// Suffix-lookalike hosts must not match.
	for _, h := range []string{"notexample.com", "example.com.evil.net", "xexample.com", "evil-example.com"} {
		if d := e.CheckHost(h); d.Allowed {
			t.Errorf("SECURITY: %q matched wildcard *.example.com", h)
		}
	}
}

func TestWildcardRejectsNonASCIIParent(t *testing.T) {
	// Punycode must be used so that the operator sees exactly what is scoped.
	if _, err := ParseRule("*.bücher.example"); err == nil {
		t.Error("SECURITY: non-ASCII wildcard parent accepted; use the punycode form")
	}
	// The punycode form is accepted and matches only that name.
	e := mustEngine(t, []string{"*.xn--bcher-kva.example"}, nil)
	if !e.CheckHost("www.xn--bcher-kva.example").Allowed {
		t.Error("punycode wildcard should match its subdomain")
	}
	if e.CheckHost("www.bücher.example.example.com").Allowed {
		t.Error("SECURITY: unicode host matched a punycode wildcard rule")
	}
}

// --- URL exclusions ----------------------------------------------------------

func TestURLExclusionWithdrawsOnlyThePathItNames(t *testing.T) {
	// A path-scoped exclusion is a statement about a subtree, not about the
	// host. Treating it as a host withdrawal silently removed an authorised
	// target from scope: the example scope file shipped with this repository
	// excludes "https://example.com/admin-internal" and allows example.com, and
	// the combination made example.com itself unscannable, so the documented
	// quickstart could not run.
	e := mustEngine(t, []string{"example.com"}, []string{"https://example.com/admin-internal"})
	u := func(s string) *url.URL { p, _ := url.Parse(s); return p }

	if !e.CheckHost("example.com").Allowed {
		t.Error("SECURITY/UX: a path exclusion took the whole host out of scope")
	}
	for _, s := range []string{
		"https://example.com/",
		"https://example.com/api",
		"https://example.com/admin",
		"https://example.com/admin-internalary",
	} {
		if !e.CheckURL(u(s)).Allowed {
			t.Errorf("%q was denied, but the exclusion does not cover it", s)
		}
	}
	for _, s := range []string{
		"https://example.com/admin-internal",
		"https://example.com/admin-internal/",
		"https://example.com/admin-internal/panel/users",
		// A path that cannot be shown to stay outside the excluded subtree is
		// refused rather than read as "the exclusion does not apply".
		"https://example.com/admin-internal/%2e%2e/%2e%2e/secret",
		"https://example.com/x/../admin-internal",
	} {
		if e.CheckURL(u(s)).Allowed {
			t.Errorf("SECURITY: %q escaped the excluded path", s)
		}
	}
}

func TestDomainExclusionStillWithdrawsTheWholeSubtree(t *testing.T) {
	// The narrower URL-exclusion behaviour must not weaken the plain domain
	// form, which is how an operator removes a host entirely.
	e := mustEngine(t, []string{"*.example.com"}, []string{"internal.example.com"})
	u := func(s string) *url.URL { p, _ := url.Parse(s); return p }
	for _, s := range []string{
		"https://internal.example.com/",
		"https://internal.example.com/admin",
		"https://deep.internal.example.com/",
	} {
		if e.CheckURL(u(s)).Allowed {
			t.Errorf("SECURITY: %q was allowed despite the domain exclusion", s)
		}
	}
	if !e.CheckURL(u("https://public.example.com/")).Allowed {
		t.Error("an unrelated host was denied by the exclusion")
	}
}

// --- URL rules --------------------------------------------------------------

func TestURLRuleRestrictsPath(t *testing.T) {
	e := mustEngine(t, []string{"https://example.com/api"}, nil)
	u := func(s string) *url.URL { p, _ := url.Parse(s); return p }

	if !e.CheckURL(u("https://example.com/api")).Allowed {
		t.Error("exact path should match")
	}
	if !e.CheckURL(u("https://example.com/api/v1/users")).Allowed {
		t.Error("subpath should match")
	}
	if e.CheckURL(u("https://example.com/apiary")).Allowed {
		t.Error("SECURITY: /apiary matched the /api prefix")
	}
	if e.CheckURL(u("https://example.com/")).Allowed {
		t.Error("SECURITY: / matched the /api prefix")
	}
	if e.CheckURL(u("http://example.com/api")).Allowed {
		t.Error("SECURITY: http matched an https-only rule")
	}
}

func TestURLRuleResistsEncodingTricks(t *testing.T) {
	e := mustEngine(t, []string{"https://example.com/api"}, nil)
	u := func(s string) *url.URL { p, _ := url.Parse(s); return p }
	for _, s := range []string{
		"https://example.com/%2e%2e/admin",
		"https://example.com/api/%2e%2e/admin",
		"https://example.com/api/..%2fadmin",
		"https://example.com/api/%2e%2e/%2e%2e/admin",
	} {
		if e.CheckURL(u(s)).Allowed {
			t.Errorf("SECURITY: encoded traversal %q escaped the /api scope", s)
		}
	}
}

func TestURLRuleSchemeAndPort(t *testing.T) {
	e := mustEngine(t, []string{"https://example.com:8443/admin"}, nil)
	u := func(s string) *url.URL { p, _ := url.Parse(s); return p }
	if !e.CheckURL(u("https://example.com:8443/admin")).Allowed {
		t.Error("expected match")
	}
	if e.CheckURL(u("https://example.com/admin")).Allowed {
		t.Error("SECURITY: default port matched a rule naming :8443")
	}
	if e.CheckURL(u("https://example.com:8443/")).Allowed {
		t.Error("SECURITY: wrong path matched")
	}
}

func TestNonHTTPSchemesRejected(t *testing.T) {
	e := mustEngine(t, []string{"example.com"}, nil)
	for _, s := range []string{"file:///etc/passwd", "gopher://example.com/", "ftp://example.com/", "javascript:alert(1)", "data:text/html,x"} {
		u, err := url.Parse(s)
		if err != nil {
			continue
		}
		if e.CheckURL(u).Allowed {
			t.Errorf("SECURITY: scheme %q was accepted", s)
		}
	}
}

func TestURLWithUserInfoRejected(t *testing.T) {
	e := mustEngine(t, []string{"example.com"}, nil)
	u, err := url.Parse("https://user:pass@example.com/")
	if err != nil {
		t.Fatal(err)
	}
	if e.CheckURL(u).Allowed {
		t.Error("SECURITY: URL with embedded credentials was accepted")
	}
}

// --- IP and CIDR rules ------------------------------------------------------

func TestIPRules(t *testing.T) {
	e := mustEngine(t, []string{"93.184.216.34", "10.10.0.0/16", "2001:db8::/32"}, nil)
	allowed := []string{"93.184.216.34", "10.10.4.5", "2001:db8::5"}
	for _, s := range allowed {
		a, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatal(err)
		}
		if d := e.CheckAddr(a); !d.Allowed {
			t.Errorf("SECURITY: address %s denied: %s", s, d.Reason)
		}
	}
	denied := []string{"93.184.216.35", "10.11.4.5", "2001:db9::5", "2001:dba::5"}
	for _, s := range denied {
		a, _ := netip.ParseAddr(s)
		if d := e.CheckAddr(a); d.Allowed {
			t.Errorf("SECURITY: address %s was ALLOWED by %q", s, d.Rule)
		}
	}
}

func TestCIDRNormalization(t *testing.T) {
	// 10.10.4.5/16 must be masked to 10.10.0.0/16, not treated as /32.
	r, err := ParseRule("10.10.4.5/16")
	if err != nil {
		t.Fatal(err)
	}
	if r.Prefix.String() != "10.10.0.0/16" {
		t.Errorf("prefix not masked: %s", r.Prefix)
	}
	if r.Prefix.Bits() != 16 {
		t.Errorf("bits wrong: %d", r.Prefix.Bits())
	}
}

func TestIPv4MappedIPv6CannotEvadeCIDR(t *testing.T) {
	e := mustEngine(t, []string{"10.0.0.0/8"}, nil)
	// ::ffff:10.1.2.3 is IPv4 10.1.2.3 and must be judged by the IPv4 rule.
	a, err := netip.ParseAddr("::ffff:10.1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if !e.CheckAddr(a).Allowed {
		t.Error("IPv4-mapped form of an allowed address should be allowed")
	}
	b, _ := netip.ParseAddr("::ffff:192.168.1.1")
	if e.CheckAddr(b).Allowed {
		t.Error("SECURITY: IPv4-mapped form bypassed the IPv4 CIDR rule")
	}
}

func TestIPv6ZoneRejected(t *testing.T) {
	if _, err := ParseAddrStrict("fe80::1%eth0"); err == nil {
		t.Error("SECURITY: zoned address was accepted by ParseAddrStrict")
	}
	if _, err := CanonicalizeDomain("fe80::1%eth0"); err == nil {
		t.Error("SECURITY: zoned address was accepted as a host")
	}
}

// --- SSRF protections -------------------------------------------------------

func TestSpecialPurposeAddressesRequireExplicitRule(t *testing.T) {
	// Naming a host must not authorize reaching a private address behind it.
	e := mustEngine(t, []string{"internal.corp.example.com", "router.example.com"}, nil)
	for _, s := range []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1", "169.254.1.1", "::1", "fe80::1", "fc00::1"} {
		a, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		if d := e.CheckAddr(a); d.Allowed {
			t.Errorf("SECURITY: special-purpose address %s was ALLOWED by %q", s, d.Rule)
		}
	}
}

func TestNeverScopableAddressesRejectedAsRules(t *testing.T) {
	for _, s := range []string{"0.0.0.0", "0.0.0.0/0", "::", "::/0", "224.0.0.1", "224.0.0.0/4", "255.255.255.255", "ff02::1"} {
		if r, err := ParseRule(s); err == nil {
			t.Errorf("SECURITY: rule %q was accepted as kind %s", s, r.Kind)
		}
	}
}

func TestLoopbackAllowedWhenExplicitlyScoped(t *testing.T) {
	// An internal engagement may legitimately scope loopback; the toolkit only
	// refuses to *infer* it from a name.
	e := mustEngine(t, []string{"127.0.0.1/32"}, nil)
	a, _ := netip.ParseAddr("127.0.0.1")
	if d := e.CheckAddr(a); !d.Allowed {
		t.Errorf("explicit loopback rule should be honored: %s", d.Reason)
	}
}

func TestPrivateRangesAllowedWhenExplicitlyScoped(t *testing.T) {
	e := mustEngine(t, []string{"10.0.0.0/8"}, nil)
	a, _ := netip.ParseAddr("10.5.5.5")
	if d := e.CheckAddr(a); !d.Allowed {
		t.Errorf("explicit 10/8 scope should permit 10.5.5.5: %s", d.Reason)
	}
}

func TestCloudMetadataAlwaysBlockedByDefault(t *testing.T) {
	e := mustEngine(t, []string{"169.254.169.254/32"}, nil)
	a, _ := netip.ParseAddr("169.254.169.254")
	if d := e.CheckAddr(a); d.Allowed {
		t.Error("SECURITY: cloud metadata address allowed without an explicit opt-in")
	}

	p := DefaultPolicy()
	p.AllowCloudMetadata = true
	e2, err := New([]string{"169.254.0.0/16"}, nil, p)
	if err != nil {
		t.Fatal(err)
	}
	if d := e2.CheckAddr(a); !d.Allowed {
		t.Errorf("with allow_cloud_metadata the address should be reachable: %s", d.Reason)
	}
}

// TestScopeFileCannotEnableCloudMetadata is the invariant that matters in
// practice. The policy is settable in Go, so a caller can opt in deliberately.
// A scope FILE is different: it is written under time pressure, often copied
// from a previous engagement, and it is the artefact a less careful operator
// edits. It must not be able to re-open the metadata endpoint.
func TestScopeFileCannotEnableCloudMetadata(t *testing.T) {
	const doc = `version: 1
scope:
  allowed:
    - 169.254.169.254/32
policy:
  allow_cloud_metadata: true
`
	eng, _, err := Load(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("the scope file was rejected outright: %v", err)
	}
	if eng.Policy().AllowCloudMetadata {
		t.Error("SECURITY: a scope file enabled cloud metadata access")
	}
	a := netip.MustParseAddr("169.254.169.254")
	if d := eng.CheckAddr(a); d.Allowed {
		t.Errorf("SECURITY: the metadata address is reachable from a scope file: %s", d.Reason)
	}
	// The key is honoured as a no-op, not as a silent success: an operator who
	// set it must be told it did nothing.
	var warned bool
	for _, w := range eng.Warnings() {
		if strings.Contains(w, "allow_cloud_metadata") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("the ignored key was not surfaced in the warnings: %v", eng.Warnings())
	}
}

func TestPortAllowlist(t *testing.T) {
	e := mustEngine(t, []string{"example.com"}, nil)
	u := func(s string) *url.URL { p, _ := url.Parse(s); return p }
	if !e.CheckURL(u("https://example.com:443/x")).Allowed {
		t.Error("443 should be allowed by default")
	}
	if e.CheckURL(u("https://example.com:9443/x")).Allowed {
		t.Error("SECURITY: non-standard port allowed by default")
	}
	if e.CheckURL(u("https://example.com:22/x")).Allowed {
		t.Error("SECURITY: SSH port allowed over HTTPS")
	}
}

// --- passive-only -----------------------------------------------------------

func TestPassiveOnlyBlocksActive(t *testing.T) {
	p := DefaultPolicy()
	p.PassiveOnly = true
	e, err := New([]string{"example.com"}, nil, p)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.RequireActive(); err == nil {
		t.Error("SECURITY: passive-only engine permitted active work")
	}
	if !e.PassiveOnly() {
		t.Error("PassiveOnly() should report true")
	}
}

func TestPolicyDefaultsAreConservative(t *testing.T) {
	p := DefaultPolicy()
	if p.MaxRPS > 5 {
		t.Errorf("default max_rps %v is too aggressive", p.MaxRPS)
	}
	if p.MaxConcurrency > 10 {
		t.Errorf("default max_concurrency %d is too aggressive", p.MaxConcurrency)
	}
	if !p.RobotsEnabled() {
		t.Error("robots must be respected by default")
	}
	if p.AllowCloudMetadata {
		t.Error("cloud metadata must be blocked by default")
	}
}

func TestPolicyClampsUnsafeValues(t *testing.T) {
	p := Policy{MaxRPS: 100000, MaxConcurrency: 100000, MaxResponseBytes: 1 << 40, MaxRedirects: 1000}
	merged := mergePolicy(p)
	if merged.MaxRPS > 100 {
		t.Errorf("max_rps not clamped: %v", merged.MaxRPS)
	}
	if merged.MaxConcurrency > 200 {
		t.Errorf("max_concurrency not clamped: %d", merged.MaxConcurrency)
	}
	if merged.MaxResponseBytes > 64<<20 {
		t.Errorf("max_response_bytes not clamped: %d", merged.MaxResponseBytes)
	}
	if merged.MaxRedirects > 20 {
		t.Errorf("max_redirects not clamped: %d", merged.MaxRedirects)
	}
}

// --- path handling ----------------------------------------------------------

func TestPathPrefixSegmentAware(t *testing.T) {
	if !prefixMatch("/api/v1", "/api") {
		t.Error("/api/v1 should match /api")
	}
	if prefixMatch("/apixyz", "/api") {
		t.Error("/apixyz must not match /api")
	}
	if !prefixMatch("/api/", "/api/") {
		t.Error("trailing slash prefix should match itself")
	}
}

func TestNormalizePathRejectsEscape(t *testing.T) {
	if _, err := normalizePathPrefix("/../etc"); err == nil {
		t.Error("SECURITY: /../etc was normalized instead of rejected")
	}
	if _, err := normalizePathPrefix("/a/../../etc"); err == nil {
		t.Error("SECURITY: /a/../../etc was normalized instead of rejected")
	}
	got, err := normalizePathPrefix("/a/./b/../c")
	if err != nil || got != "/a/c" {
		t.Errorf("normalizePathPrefix = %q, %v; want /a/c", got, err)
	}
}

func TestRelativePathRejected(t *testing.T) {
	if _, err := normalizePathPrefix("api/v1"); err == nil {
		t.Error("relative path accepted as a scope prefix")
	}
}

// --- rule parsing edge cases ------------------------------------------------

func TestParseRuleRejectsBadSchemes(t *testing.T) {
	for _, s := range []string{"file://example.com/x", "ftp://example.com/", "gopher://example.com"} {
		if _, err := ParseRule(s); err == nil {
			t.Errorf("SECURITY: rule %q accepted", s)
		}
	}
}
func TestParseRuleRejectsCredentials(t *testing.T) {
	if _, err := ParseRule("https://user:pass@example.com/"); err == nil {
		t.Error("SECURITY: rule with embedded credentials accepted")
	}
}

func TestParseRuleRejectsGarbage(t *testing.T) {
	for _, s := range []string{"", "   ", "not a host", "10.0.0.0/99", "1.2.3.4/", "999.999.999.999", "http://", "://example.com"} {
		if _, err := ParseRule(s); err == nil {
			t.Errorf("rule %q was accepted but is invalid", s)
		}
	}
}

func TestWarningsFlagShadowedRule(t *testing.T) {
	e := mustEngine(t, []string{"admin.example.com"}, []string{"admin.example.com"})
	found := false
	for _, w := range e.Warnings() {
		if w != "" && contains(w, "never match") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a shadowed-rule warning, got %v", e.Warnings())
	}
}

func TestWarningsFlagEmptyScope(t *testing.T) {
	e, _ := New(nil, nil, DefaultPolicy())
	found := false
	for _, w := range e.Warnings() {
		if contains(w, "empty") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an empty-scope warning, got %v", e.Warnings())
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle || indexOf(haystack, needle) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// --- concurrency ------------------------------------------------------------

func TestEngineConcurrentReads(t *testing.T) {
	e := mustEngine(t, []string{"*.example.com"}, []string{"admin.example.com"})
	done := make(chan struct{})
	for i := 0; i < 32; i++ {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			host := "a.example.com"
			if i%2 == 0 {
				host = "admin.example.com"
			}
			_ = e.CheckHost(host)
			_ = e.Policy()
			_, _ = e.Rules()
			_ = e.Warnings()
		}(i)
	}
	for i := 0; i < 32; i++ {
		<-done
	}
}
