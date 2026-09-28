package robots

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	httpclient "github.com/bbtoolkit/bugbounty/internal/http"
	"github.com/bbtoolkit/bugbounty/internal/ratelimit"
	"github.com/bbtoolkit/bugbounty/internal/scope"
)

// --- path matching -----------------------------------------------------------

// TestNonAnchoredRulesMatchByPrefix is the semantics the whole package rests
// on. A rule without a trailing '$' matches any path it is a prefix of, so
// "Disallow: /admin" covers "/admin/page" and "Disallow: /" covers everything.
//
// Getting this wrong is a robots bypass in the direction that matters: the
// crawler requests paths the site owner forbade.
func TestNonAnchoredRulesMatchByPrefix(t *testing.T) {
	cases := []struct {
		name, rule, path string
		want             bool
	}{
		{"catch-all covers a normal path", "/", "/admin", false},
		{"catch-all covers the root", "/", "/", false},
		{"rule covers a child path", "/admin", "/admin/page", false},
		{"rule covers itself", "/admin", "/admin", false},
		{"rule covers a longer name that starts with it", "/admin", "/administration", false},
		{"rule does not cover a sibling", "/admin", "/public", true},
		{"wildcard spans a segment", "/*.php", "/index.php", false},
		{"wildcard spans a segment then a suffix", "/a/*/b", "/a/x/b/c", false},
		{"anchored rule does not cover a child", "/admin$", "/admin/page", true},
		{"anchored rule covers exactly itself", "/admin$", "/admin", false},
		{"empty path is treated as root", "/", "", false},
		{"a longer allow rule beats a shorter deny", "/", "/allowed/page", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rule := "Disallow: " + c.rule
			if c.name == "a longer allow rule beats a shorter deny" {
				// A catch-all deny with a narrower allow, which is how a site
				// publishes a public section inside a private one.
				rule = "Disallow: /\nAllow: /allowed"
			}
			p := Parse("https://x", "User-agent: *\n"+rule+"\n", "tester")
			got, _ := p.Allows(c.path, "tester")
			if got != c.want {
				t.Errorf("rule %q against %q: allowed = %v, want %v", c.rule, c.path, got, c.want)
			}
		})
	}
}

// TestAllowBeatsTheCatchAll checks the precedence a site relies on to publish
// a public section inside an otherwise private site.
func TestAllowBeatsTheCatchAll(t *testing.T) {
	p := Parse("https://x", "User-agent: *\nDisallow: /\nAllow: /public\n", "tester")
	if ok, _ := p.Allows("/public", "tester"); !ok {
		t.Error("an Allow rule did not override the catch-all Disallow")
	}
	if ok, _ := p.Allows("/private", "tester"); ok {
		t.Error("SECURITY: the catch-all Disallow did not take effect")
	}
}

// TestAnchoredRuleDoesNotLeak guards the fail-open direction of the anchor: an
// anchored Allow must not extend to a path that merely starts with it.
func TestAnchoredRuleDoesNotLeak(t *testing.T) {
	p := Parse("https://x", "User-agent: *\nDisallow: /\nAllow: /public$\n", "tester")
	if ok, _ := p.Allows("/public", "tester"); !ok {
		t.Error("the anchored Allow did not match the path it names")
	}
	if ok, _ := p.Allows("/publicsecret", "tester"); ok {
		t.Error("SECURITY: an anchored Allow extended past the end of the path")
	}
}

// TestMostSpecificRuleWins checks that a longer rule is chosen over a shorter
// one that also matches, which is how a site carves an exception out of a
// broad rule.
func TestMostSpecificRuleWins(t *testing.T) {
	p := Parse("https://x", "User-agent: *\nDisallow: /a\nAllow: /a/b\n", "tester")
	if ok, _ := p.Allows("/a/b", "tester"); !ok {
		t.Error("the longer Allow did not win over the shorter Disallow")
	}
	if ok, _ := p.Allows("/a/c", "tester"); ok {
		t.Error("SECURITY: the shorter Disallow did not apply")
	}
}

// TestUserAgentGrouping checks the group semantics, including that an empty
// Disallow is dropped rather than becoming a rule that would cancel a later one.
func TestUserAgentGrouping(t *testing.T) {
	body := "User-agent: *\nDisallow: /shared\n\n" +
		"User-agent: goodbot\nDisallow:\n\n" +
		"User-agent: goodbot\nDisallow: /private\n"
	p := Parse("https://x", body, "goodbot")

	if ok, _ := p.Allows("/shared", "goodbot"); ok {
		t.Error("the * group rule was not applied to goodbot")
	}
	if ok, _ := p.Allows("/private", "goodbot"); ok {
		t.Error("the goodbot-specific rule was not applied")
	}
	// Another agent gets only the * group, so the goodbot-only rule must not
	// apply to it.
	if ok, _ := p.Allows("/private", "otherbot"); !ok {
		t.Error("a rule written for one agent was applied to a different agent")
	}
	// A group whose only rule is an empty Disallow must not forbid anything.
	if ok, _ := p.Allows("/anything", "goodbot"); !ok {
		t.Error("an empty Disallow was treated as a rule")
	}
}

// TestPathlessDisallowIsNotAFullDeny checks the case that would silently hand
// the whole site to the crawler.
func TestPathlessDisallowIsNotAFullDeny(t *testing.T) {
	p := Parse("https://x", "User-agent: *\nDisallow:\n", "tester")
	if ok, _ := p.Allows("/anything", "tester"); !ok {
		t.Error("an empty Disallow denied the whole site")
	}
}

// --- parsing -----------------------------------------------------------------

// TestHostileRobotsIsBounded checks that a file designed to exhaust the parser
// is bounded rather than obeyed.
func TestHostileRobotsIsBounded(t *testing.T) {
	// A rule-expansion bomb: many groups, each with many rules.
	var b strings.Builder
	for i := 0; i < 5000; i++ {
		b.WriteString("User-agent: *\n")
		for j := 0; j < 50; j++ {
			b.WriteString("Disallow: /x\n")
		}
	}
	p := Parse("https://x", b.String(), "tester")
	if p.ParseError == "" {
		t.Error("a rule-expansion bomb produced no note")
	}
	if n := countRules(p); n > MaxGroupExpansion {
		t.Errorf("%d rules were retained, want at most %d", n, MaxGroupExpansion)
	}

	// A single enormous line.
	long := "Disallow: /" + strings.Repeat("a", 100_000)
	p2 := Parse("https://x", long, "tester")
	if n := countRules(p2); n != 0 {
		t.Errorf("an over-long line produced %d rules, want 0", n)
	}
}

func countRules(p *Policy) int {
	n := 0
	for _, g := range p.Groups {
		n += len(g.rules)
	}
	return n
}

// TestMalformedLinesAreSkipped checks that a broken file degrades to the rules
// that could be understood, rather than to no restrictions at all.
func TestMalformedLinesAreSkipped(t *testing.T) {
	body := "User-agent: *\n" +
		"this line has no colon\n" +
		": leading colon with no field\n" +
		"Disallow: /keep\n" +
		"# Disallow: /commented\n" +
		"Disallow: /also-kept\n"
	p := Parse("https://x", body, "tester")
	if ok, _ := p.Allows("/keep", "tester"); ok {
		t.Error("a rule after a malformed line was lost")
	}
	if ok, _ := p.Allows("/also-kept", "tester"); ok {
		t.Error("a later rule was lost")
	}
	if ok, _ := p.Allows("/commented", "tester"); !ok {
		t.Error("a comment was treated as a rule")
	}
}

// TestCrawlDelayAndSitemaps covers the two fields other stages read.
func TestCrawlDelayAndSitemaps(t *testing.T) {
	body := "User-agent: *\nCrawl-delay: 2.5\n" +
		"Sitemap: https://x/sitemap.xml\n" +
		"Sitemap: /relative.xml\n" +
		"Sitemap: ftp://x/nope.xml\n" +
		"Sitemap: javascript:alert(1)\n"
	p := Parse("https://x", body, "tester")

	if p.CrawlDelay != 2500*time.Millisecond {
		t.Errorf("crawl delay = %v, want 2.5s", p.CrawlDelay)
	}
	if len(p.Sitemaps) != 1 {
		t.Fatalf("kept %d sitemaps (%v), want only the absolute http one", len(p.Sitemaps), p.Sitemaps)
	}
	if p.Sitemaps[0] != "https://x/sitemap.xml" {
		t.Errorf("sitemap = %q", p.Sitemaps[0])
	}

	// An absurd delay is ignored rather than stalling the run for an hour.
	bad := Parse("https://x", "User-agent: *\nCrawl-delay: 999999\n", "tester")
	if bad.CrawlDelay != 0 {
		t.Errorf("an out-of-range crawl delay was accepted: %v", bad.CrawlDelay)
	}
}

// TestNilPolicyAllows guards the zero-value path, which a caller can reach by
// asking for a policy that was never fetched.
func TestNilPolicyAllows(t *testing.T) {
	var p *Policy
	if ok, reason := p.Allows("/x", "tester"); !ok || reason == "" {
		t.Error("a nil policy should allow with a stated reason")
	}
	empty := &Policy{}
	if ok, _ := empty.Allows("/x", "tester"); !ok {
		t.Error("a policy that was never fetched should allow")
	}
}

func TestDenyAllOverridesEverything(t *testing.T) {
	p := &Policy{Available: true, DenyAll: true, ParseError: "the server returned 429"}
	p.Groups = append(p.Groups, group{agents: []string{"*"}, rules: []Rule{{Path: "/", Allow: true, Priority: 1}}})
	if ok, reason := p.Allows("/anything", "tester"); ok {
		t.Errorf("SECURITY: DenyAll was overridden by a rule: %s", reason)
	}
}

// --- fetching ----------------------------------------------------------------

// scopeForHost builds a scope engine that allows the given host, so the tests
// exercise the robots logic rather than the scope engine's refusals.
//
// The port has to be allowed explicitly: the default policy permits only the
// standard web ports, and a test server listens on a random one. That the port
// can be opened here at all is deliberate, since these tests need loopback.
func scopeForHost(t *testing.T, host string) *scope.Engine {
	t.Helper()
	name := host
	pol := scope.DefaultPolicy()
	if h, p, err := net.SplitHostPort(host); err == nil {
		name = h
		port, err := strconv.Atoi(p)
		if err != nil {
			t.Fatalf("port %q: %v", p, err)
		}
		pol.AllowedPorts = append(pol.AllowedPorts, port)
	}
	eng, err := scope.New([]string{name}, nil, pol)
	if err != nil {
		t.Fatalf("scope for %q: %v", host, err)
	}
	return eng
}

// testClient builds a permissive client. A nil resolver means the client
// resolves normally, which is what a loopback test server needs.
func testClient(t *testing.T, sc *scope.Engine) *httpclient.Client {
	t.Helper()
	cfg := httpclient.DefaultConfig()
	cfg.MaxResponseBytes = 1 << 20
	c, err := httpclient.New(cfg, sc, ratelimit.New(0, 2, 0), nil)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	return c
}

// newStore wires a store against a test server, with scope allowing the host.
// It returns the store and a base URL on that server, so a test can ask about
// the root path and let the store derive the origin itself.
func newStore(t *testing.T, h http.HandlerFunc, enabled bool) (*Store, *url.URL) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	base, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	sc := scopeForHost(t, base.Host)
	return NewStore(testClient(t, sc), sc, "tester", enabled), base
}

func TestStoreFetchesOncePerOrigin(t *testing.T) {
	var hits int
	store, base := newStore(t, func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path == "/robots.txt" {
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /admin\n"))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}, true)

	// The served rule forbids /admin, so that is the path to ask about.
	admin, err := url.Parse(base.String() + "/admin")
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		if ok, _ := store.Allowed(admin); ok {
			t.Fatal("the disallowed path was allowed")
		}
	}
	if hits != 1 {
		t.Errorf("robots.txt was fetched %d times, want 1", hits)
	}
}

func TestStoreHonoursARateLimitResponse(t *testing.T) {
	store, base := newStore(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}, true)

	if ok, reason := store.Allowed(base); ok {
		t.Errorf("SECURITY: a host returning 429 was still crawled: %s", reason)
	}
}

func TestStoreAssumesDisallowOnAServerError(t *testing.T) {
	store, base := newStore(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}, true)

	if ok, _ := store.Allowed(base); ok {
		t.Error("SECURITY: a 5xx was treated as no restrictions published")
	}
}

func TestStoreAllowsWhenNothingIsPublished(t *testing.T) {
	store, base := newStore(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		// A body that would be catastrophic if parsed as rules.
		_, _ = w.Write([]byte("Disallow: /\n"))
	}, true)

	if ok, _ := store.Allowed(base); !ok {
		t.Error("a 404 should mean no restrictions are published")
	}
}

func TestStoreDoesNotParseAnErrorPage(t *testing.T) {
	// A 403 whose body says "Disallow: /" must not become a rule, or a server
	// could dictate the crawl through an error page.
	store, base := newStore(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Disallow: /\n"))
	}, true)

	pol, err := store.Policy(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	if countRules(pol) != 0 {
		t.Errorf("an error page was parsed as %d rules", countRules(pol))
	}
	if pol.DenyAll {
		t.Error("a 403 was treated as a stop signal")
	}
}

func TestStoreIgnoresMarkupServedAsRules(t *testing.T) {
	// A hostile or misconfigured host can serve HTML with a 200. Nothing in a
	// robots.txt body may widen what the crawler fetches, and this body names
	// no rule, so nothing is forbidden.
	store, base := newStore(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>Disallow: /</html>"))
	}, true)

	if ok, _ := store.Allowed(base); !ok {
		t.Error("markup was interpreted as a rule that forbids the site")
	}
}

func TestStoreReadsRealRules(t *testing.T) {
	// The positive control for the test above: a genuine rule in a 200 body
	// is honoured, so the previous test is not passing by accident.
	store, base := newStore(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("User-agent: *\nDisallow: /\n"))
	}, true)

	if ok, _ := store.Allowed(base); ok {
		t.Error("SECURITY: a genuine catch-all Disallow was ignored")
	}
}

func TestDisabledStoreFetchesNothing(t *testing.T) {
	var hits int
	store, base := newStore(t, func(w http.ResponseWriter, r *http.Request) { hits++ }, false)

	for range 3 {
		if ok, _ := store.Allowed(base); !ok {
			t.Error("a disabled store refused a path")
		}
	}
	if hits != 0 {
		t.Errorf("a disabled store made %d requests", hits)
	}
	if store.Enabled() {
		t.Error("a disabled store reported itself as enabled")
	}
}

func TestStoreRefusesToFetchOutOfScope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("robots.txt was fetched for an out-of-scope host")
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	// A scope that authorises a different host entirely.
	sc := scopeForHost(t, "example.invalid")
	store := NewStore(testClient(t, sc), sc, "tester", true)

	if _, err := store.Policy(context.Background(), u); err == nil {
		t.Error("SECURITY: an out-of-scope robots.txt fetch was attempted")
	}
}
