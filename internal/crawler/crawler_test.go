package crawler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bbtoolkit/bugbounty/internal/http"
	"github.com/bbtoolkit/bugbounty/internal/ratelimit"
	"github.com/bbtoolkit/bugbounty/internal/robots"
	"github.com/bbtoolkit/bugbounty/internal/scope"
	"github.com/bbtoolkit/bugbounty/pkg/models"
)

func newCrawler(t *testing.T, cfg Config, sc *scope.Engine) *Crawler {
	t.Helper()
	cfg = mergeConfig(cfg)
	client, err := httpclient.New(httpclient.DefaultConfig(), sc, ratelimit.New(0, 4, 0), nil)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	c, err := New(cfg, client, sc, nil)
	if err != nil {
		t.Fatalf("crawler: %v", err)
	}
	return c
}

func mergeConfig(cfg Config) Config {
	d := DefaultConfig()
	if cfg.MaxDepth == 0 {
		cfg.MaxDepth = d.MaxDepth
	}
	if cfg.MaxPages == 0 {
		cfg.MaxPages = d.MaxPages
	}
	if cfg.MaxConcurrency == 0 {
		cfg.MaxConcurrency = d.MaxConcurrency
	}
	if cfg.MaxResponseSize == 0 {
		cfg.MaxResponseSize = d.MaxResponseSize
	}
	if cfg.MaxParameters == 0 {
		cfg.MaxParameters = d.MaxParameters
	}
	if cfg.MaxEndpoints == 0 {
		cfg.MaxEndpoints = d.MaxEndpoints
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = d.Timeout
	}
	return cfg
}

func scopeFor(t *testing.T, srvURL string, extraAllowed, excluded []string) *scope.Engine {
	t.Helper()
	host, port := splitHostPort(t, srvURL)
	allowed := append([]string{hostPort(host, port)}, extraAllowed...)
	e, err := scope.New(allowed, excluded, scope.DefaultPolicy())
	if err != nil {
		t.Fatalf("scope: %v", err)
	}
	return e
}

func splitHostPort(t *testing.T, rawURL string) (string, string) {
	t.Helper()
	u := strings.TrimPrefix(strings.TrimPrefix(rawURL, "http://"), "https://")
	if i := strings.Index(u, "/"); i >= 0 {
		u = u[:i]
	}
	j := strings.LastIndex(u, ":")
	if j < 0 {
		return u, "80"
	}
	return u[:j], u[j+1:]
}

func hostPort(host, port string) string { return host + ":" + port }

// --- SECURITY TEST 7: crawling cannot escape the configured scope -----------

func TestCrawlerCannotEscapeScope(t *testing.T) {
	// A page that links to an out-of-scope host, an excluded subdomain and a
	// non-HTTP scheme.
	var outHits atomic.Int64
	outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		outHits.Add(1)
		fmt.Fprint(w, "you should never see this")
	}))
	defer outside.Close()

	excludedHits := atomic.Int64{}
	excluded := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		excludedHits.Add(1)
	}))
	defer excluded.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<html><body>
			<a href="%s/secret">external</a>
			<a href="http://admin.example.com/admin">excluded</a>
			<a href="javascript:alert(1)">js</a>
			<a href="file:///etc/passwd">file</a>
			<a href="/internal">internal</a>
		</body></html>`, outside.URL)
	})
	mux.HandleFunc("/internal", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html>internal page</html>")
	})
	origin := httptest.NewServer(mux)
	defer origin.Close()

	sc := scopeFor(t, origin.URL, nil, []string{"admin.example.com"})
	c := newCrawler(t, Config{MaxDepth: 3, MaxPages: 50}, sc)

	res, err := c.Crawl(context.Background(), origin.URL)
	if err != nil {
		t.Fatalf("crawl: %v", err)
	}
	if outHits.Load() != 0 {
		t.Errorf("SECURITY: the out-of-scope host was crawled %d times", outHits.Load())
	}
	if excludedHits.Load() != 0 {
		t.Errorf("SECURITY: the excluded host was crawled %d times", excludedHits.Load())
	}
	if res.OutOfScope == 0 {
		t.Error("expected the crawler to record at least one out-of-scope skip")
	}
	// The in-scope link must still have been followed.
	found := false
	for _, p := range res.Pages {
		if strings.HasSuffix(p.URL, "/internal") {
			found = true
		}
	}
	if !found {
		t.Error("the in-scope link was not followed; the crawler is too restrictive to be useful")
	}
}

func TestCrawlerRefusesOutOfScopeSeed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	// A scope that does not cover the server's own address.
	narrow, err := scope.New([]string{"example.com"}, nil, scope.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	c := newCrawler(t, Config{}, narrow)
	if _, err := c.Crawl(context.Background(), srv.URL); err == nil {
		t.Error("SECURITY: the crawler accepted an out-of-scope seed")
	}
}

func TestCrawlerDoesNotFollowOutOfScopeRedirect(t *testing.T) {
	var victimHits atomic.Int64
	victim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		victimHits.Add(1)
		fmt.Fprint(w, "secret internal data")
	}))
	defer victim.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, victim.URL+"/admin", http.StatusFound)
	}))
	defer origin.Close()

	sc := scopeFor(t, origin.URL, nil, nil)
	c := newCrawler(t, Config{MaxDepth: 2, MaxPages: 10}, sc)
	res, err := c.Crawl(context.Background(), origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	if victimHits.Load() != 0 {
		t.Fatalf("SECURITY: a redirect escaped scope and reached the victim %d times", victimHits.Load())
	}
	for _, p := range res.Pages {
		if strings.Contains(p.URL, "victim") {
			t.Errorf("SECURITY: an out-of-scope host appears in results: %s", p.URL)
		}
	}
}

func TestCrawlerRespectsPassiveOnly(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()

	p := scope.DefaultPolicy()
	p.PassiveOnly = true
	sc, err := scope.New([]string{hostPort(splitHostPort(t, srv.URL))}, nil, p)
	if err != nil {
		t.Fatal(err)
	}
	c := newCrawler(t, Config{}, sc)
	if _, err := c.Crawl(context.Background(), srv.URL); err == nil {
		t.Error("SECURITY: passive-only mode allowed a crawl")
	}
	if hits.Load() != 0 {
		t.Errorf("SECURITY: passive-only mode issued %d requests", hits.Load())
	}
}

// --- loop and budget bounds -------------------------------------------------

func TestCrawlerPreventsInfiniteLoops(t *testing.T) {
	// A page that links to itself and to a rotating set of names would run
	// forever without a page budget and deduplication.
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		// Self reference plus equivalent spellings of the same URL.
		fmt.Fprintf(w, `<html><body>
			<a href="/">self</a>
			<a href="/./">dot</a>
			<a href="//%s/">scheme relative</a>
			<a href="/?a=1&b=2">query</a>
			<a href="/?b=2&a=1">reordered query</a>
			<a href="/#frag">fragment</a>
		</body></html>`, r.Host)
	}))
	defer srv.Close()

	sc := scopeFor(t, srv.URL, nil, nil)
	c := newCrawler(t, Config{MaxDepth: 5, MaxPages: 20, MaxConcurrency: 4}, sc)

	res, err := c.Crawl(context.Background(), srv.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	if hits.Load() > 20 {
		t.Errorf("SECURITY: %d requests were made with a page budget of 20", hits.Load())
	}
	if !res.Truncated {
		t.Log("crawl finished before the budget; still within limits")
	}
}

func TestCrawlerBoundsDepth(t *testing.T) {
	// A chain of links, each one level deeper. With MaxDepth 3 the crawl must
	// stop at /level3 and never request /level4.
	var requested sync.Map
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested.Store(r.URL.Path, true)
		var n int
		fmt.Sscanf(strings.TrimPrefix(r.URL.Path, "/level"), "%d", &n)
		if n < 10 {
			fmt.Fprintf(w, `<a href="/level%d">next</a>`, n+1)
		}
	}))
	defer srv.Close()

	sc := scopeFor(t, srv.URL, nil, nil)
	c := newCrawler(t, Config{MaxDepth: 3, MaxPages: 100}, sc)
	if _, err := c.Crawl(context.Background(), srv.URL+"/level0"); err != nil {
		t.Fatal(err)
	}
	for _, deeper := range []string{"/level4", "/level5", "/level6"} {
		if _, hit := requested.Load(deeper); hit {
			t.Errorf("SECURITY: %s was requested although MaxDepth is 3", deeper)
		}
	}
	if _, hit := requested.Load("/level3"); !hit {
		t.Error("/level3 is at the limit and should have been fetched")
	}
}

func TestCrawlerBoundsResponseSize(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("A", 2<<20)))
	}))
	defer srv.Close()

	sc := scopeFor(t, srv.URL, nil, nil)
	c := newCrawler(t, Config{MaxDepth: 1, MaxPages: 5, MaxResponseSize: 16 << 10}, sc)
	res, err := c.Crawl(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Pages) == 0 {
		t.Fatal("no page recorded")
	}
}

func TestCrawlerNeverSubmitsForms(t *testing.T) {
	var posts atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			posts.Add(1)
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body>
			<form action="/login" method="POST">
				<input name="username" value="x">
				<input type="password" name="password">
				<select name="role"><option>a</option></select>
			</form>
		</body></html>`)
	}))
	defer page.Close()

	// Scope covers only the form host.
	sc := scopeFor(t, page.URL, nil, nil)
	c := newCrawler(t, Config{MaxDepth: 2, MaxPages: 20, ParseForms: true}, sc)
	res, err := c.Crawl(context.Background(), page.URL)
	if err != nil {
		t.Fatal(err)
	}
	if posts.Load() != 0 {
		t.Errorf("SECURITY: the crawler issued %d non-GET requests", posts.Load())
	}
	// The form fields should still be recorded as attack surface.
	names := map[string]bool{}
	for _, p := range res.Parameters {
		names[p.Name] = true
	}
	for _, want := range []string{"username", "password", "role"} {
		if !names[want] {
			t.Errorf("form field %q was not recorded", want)
		}
	}
}

func TestCrawlerRecordsMethodOnFormEndpoint(t *testing.T) {
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body><form action="/api/login" method="POST"><input name="u"></form></body></html>`)
	}))
	defer page.Close()
	sc := scopeFor(t, page.URL, nil, nil)
	c := newCrawler(t, Config{MaxDepth: 1, MaxPages: 10}, sc)
	res, err := c.Crawl(context.Background(), page.URL)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range res.Endpoints {
		if e.Kind == models.EndpointForm {
			found = true
		}
	}
	if !found {
		t.Error("the form action was not recorded as an endpoint")
	}
}

// --- robots -----------------------------------------------------------------

func TestCrawlerHonoursRobots(t *testing.T) {
	var adminHits atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "User-agent: *\nDisallow: /admin\nDisallow: /private\n")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<a href="/admin">a</a><a href="/public">p</a>`)
	})
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		adminHits.Add(1)
	})
	mux.HandleFunc("/public", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "public ok")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	sc := scopeFor(t, srv.URL, nil, nil)
	client, _ := httpclient.New(httpclient.DefaultConfig(), sc, ratelimit.New(0, 4, 0), nil)
	store := robots.NewStore(client, sc, "bugbounty-toolkit", true)
	c, err := New(mergeConfig(Config{MaxDepth: 2, MaxPages: 20}), client, sc, store)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Crawl(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if adminHits.Load() != 0 {
		t.Errorf("SECURITY: a robots-disallowed path was crawled %d times", adminHits.Load())
	}
	if res.BlockedByRobots == 0 {
		t.Error("expected robots blocks to be recorded")
	}
}

func TestRobotsDisabledAllowsEverything(t *testing.T) {
	var adminHits atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "User-agent: *\nDisallow: /\n")
	})
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		adminHits.Add(1)
		fmt.Fprint(w, "ok")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<a href="/admin">a</a>`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	sc := scopeFor(t, srv.URL, nil, nil)
	client, _ := httpclient.New(httpclient.DefaultConfig(), sc, ratelimit.New(0, 4, 0), nil)
	store := robots.NewStore(client, sc, "bugbounty-toolkit", false)
	c, _ := New(mergeConfig(Config{MaxDepth: 2, MaxPages: 20}), client, sc, store)
	if _, err := c.Crawl(context.Background(), srv.URL); err != nil {
		t.Fatal(err)
	}
	if adminHits.Load() == 0 {
		t.Error("with robots disabled the path should have been crawled")
	}
}

func TestRobotsParse(t *testing.T) {
	p := robots.Parse("https://example.com", `
User-agent: *
Disallow: /private
Allow: /private/public
Disallow: /*.json$
Crawl-delay: 5
Sitemap: https://example.com/sitemap.xml
# comment
`, "bugbounty-toolkit")
	cases := []struct {
		path string
		want bool
	}{
		{"/", true},
		{"/private", false},
		{"/private/public", true},
		{"/data.json", false},
		{"/data.xml", true},
	}
	for _, tc := range cases {
		got, _ := p.Allows(tc.path, "bugbounty-toolkit")
		if got != tc.want {
			t.Errorf("Allows(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
	if p.CrawlDelay != 5*time.Second {
		t.Errorf("crawl delay = %v", p.CrawlDelay)
	}
	if len(p.Sitemaps) != 1 {
		t.Errorf("sitemaps = %v", p.Sitemaps)
	}
}

func TestRobotsHostileInput(t *testing.T) {
	// A billion-laughs style expansion and a malformed file must not hang or
	// panic.
	body := "User-agent: *\n"
	for i := 0; i < 20000; i++ {
		body += "Disallow: /" + strings.Repeat("a", 200) + "\n"
	}
	p := robots.Parse("https://example.com", body, "x")
	if p == nil {
		t.Fatal("parse returned nil")
	}
	if allowed, _ := p.Allows("/", "x"); !allowed {
		t.Error("expected the file to remain usable")
	}

	garbage := robots.Parse("https://example.com", "\x00\x01 nonsense\n:::\nDisallow\n= = =\n", "x")
	if allowed, _ := garbage.Allows("/x", "x"); !allowed {
		t.Error("malformed input changed behaviour unexpectedly")
	}
}

func TestRobotsEmptyDisallowAllowsAll(t *testing.T) {
	p := robots.Parse("https://example.com", "User-agent: *\nDisallow:\n", "x")
	if allowed, _ := p.Allows("/anything", "x"); !allowed {
		t.Error("an empty Disallow must allow everything")
	}
}

// --- extraction -------------------------------------------------------------

func TestNormalizeURLDeduplication(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://example.com/a//b", "https://example.com/a/b"},
		{"https://example.com/a/./b", "https://example.com/a/b"},
		{"https://example.com/a/x/../b", "https://example.com/a/b"},
		{"https://example.com/?b=2&a=1", "https://example.com/?a=1&b=2"},
		{"https://example.com/p#frag", "https://example.com/p"},
		{"https://EXAMPLE.com:443/x", "https://example.com/x"},
		{"http://example.com:80/x", "http://example.com/x"},
		{"https://example.com", "https://example.com/"},
	}
	for _, tc := range cases {
		u, err := NormalizeURL(tc.in, http.MethodGet)
		if err != nil {
			t.Errorf("NormalizeURL(%q): %v", tc.in, err)
			continue
		}
		if got := u.String(); got != tc.want {
			t.Errorf("NormalizeURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeURLRejectsBadInput(t *testing.T) {
	for _, in := range []string{"", "not a url", "javascript:alert(1)", "file:///etc/passwd",
		"https://user:pass@example.com/", "ftp://example.com/"} {
		if _, err := NormalizeURL(in, http.MethodGet); err == nil {
			t.Errorf("SECURITY: NormalizeURL accepted %q", in)
		}
	}
}

func TestResolveRejectsDangerousSchemes(t *testing.T) {
	base, _ := NormalizeURL("https://example.com/a/b", http.MethodGet)
	for _, ref := range []string{"javascript:alert(1)", "data:text/html,<script>", "vbscript:x",
		"file:///etc/passwd", "blob:https://example.com/x", "about:blank"} {
		if _, err := Resolve(base, ref); err == nil {
			t.Errorf("SECURITY: Resolve accepted %q", ref)
		}
	}
	u, err := Resolve(base, "/c")
	if err != nil || u.String() != "https://example.com/c" {
		t.Errorf("Resolve(/c) = %v, %v", u, err)
	}
}

func TestExtractLinksFormsAndParameters(t *testing.T) {
	base, _ := NormalizeURL("https://example.com/dir/page.html", http.MethodGet)
	html := `<html><body>
		<a href="/one">1</a>
		<a href="two.html">2</a>
		<a href="https://other.example/x">3</a>
		<a href="javascript:void(0)">js</a>
		<script src="/static/app.js"></script>
		<form action="/submit" method="post">
			<input name="email" type="email">
			<input name="csrf_token" type="hidden">
		</form>
		<img src="/img/a.png">
	</body></html>`
	e := Extract(base, []byte(html), "text/html", ExtractOptions{JavaScript: true, Forms: true, Parameters: true})
	if len(e.Links) < 4 {
		t.Errorf("expected several links, got %d: %+v", len(e.Links), e.Links)
	}
	names := map[string]models.ParamKind{}
	for _, p := range e.Parameters {
		names[p.Name] = p.Kind
	}
	if names["email"] != models.ParamForm {
		t.Error("form field email not recorded")
	}
	if names["csrf_token"] != models.ParamForm {
		t.Error("csrf_token not recorded")
	}
}

func TestExtractFromJavaScript(t *testing.T) {
	base, _ := NormalizeURL("https://example.com/app", http.MethodGet)
	js := `fetch("/api/v1/users?id=1");
		  axios.post("/api/v1/login", {});
		  var u = "https://api.example.com/v2/data";`
	e := Extract(base, []byte(js), "application/javascript", ExtractOptions{JavaScript: true, Parameters: true})
	joined := ""
	for _, l := range e.Links {
		joined += l.URL + "\n"
	}
	for _, want := range []string{"/api/v1/users?id=1", "/api/v1/login", "https://api.example.com/v2/data"} {
		if !strings.Contains(joined, want) {
			t.Errorf("JavaScript endpoint %q was not extracted; got:\n%s", want, joined)
		}
	}
}

func TestExtractHostileInputIsBounded(t *testing.T) {
	base, _ := NormalizeURL("https://example.com/", http.MethodGet)
	inputs := []string{
		strings.Repeat("<a href='/x'>", 50000),
		strings.Repeat("<!--", 50000),
		"{\"a\":" + strings.Repeat("[", 5000) + strings.Repeat("]", 5000) + "}",
		strings.Repeat("fetch('/x');", 10000),
	}
	for i, in := range inputs {
		done := make(chan struct{})
		go func(in string) {
			defer close(done)
			Extract(base, []byte(in), "text/html", ExtractOptions{JavaScript: true, Parameters: true, MaxParams: 50})
		}(in)
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Fatalf("payload %d did not terminate", i)
		}
	}
}

func TestInterestingParameterNames(t *testing.T) {
	for _, n := range []string{"id", "redirect", "token", "file", "debug", "sql"} {
		if ok, reason := IsInterestingName(n); !ok || reason == "" {
			t.Errorf("%q should be interesting with a reason", n)
		}
	}
	if ok, _ := IsInterestingName("theme"); ok {
		t.Error("theme should not be flagged as interesting")
	}
}
