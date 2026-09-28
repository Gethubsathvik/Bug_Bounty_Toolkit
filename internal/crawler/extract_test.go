package crawler

import (
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/bbtoolkit/bugbounty/pkg/models"
)

func mustBase(t *testing.T) *url.URL {
	t.Helper()
	u, err := url.Parse("https://example.com/dir/page")
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func allOpts() ExtractOptions {
	return ExtractOptions{JavaScript: true, Forms: true, Parameters: true}
}

// linksOf flattens the extracted links for easy assertions.
func linksOf(e Extracted) []string {
	out := make([]string, 0, len(e.Links))
	for _, l := range e.Links {
		out = append(out, l.URL)
	}
	return out
}

func has(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// --- JSON --------------------------------------------------------------------

// TestJSONEndpointsAreFound covers the path a real API response takes: the
// discoverable endpoints are inside JSON, under keys that name what they hold.
func TestJSONEndpointsAreFound(t *testing.T) {
	body := []byte(`{
	  "next": "/api/page2",
	  "items": [
	    {"url": "/api/item/1", "id": 42},
	    {"href": "/api/item/2"},
	    {"endpoint": "https://api.example.com/v3/thing"}
	  ],
	  "callbackUrl": "/hook",
	  "count": 7,
	  "nested": {"deeper": {"uri": "/api/deep"}}
	}`)
	got := Extract(mustBase(t), body, "application/json", allOpts())
	links := linksOf(got)

	for _, want := range []string{
		"/api/page2", "/api/item/1", "/api/item/2",
		"https://api.example.com/v3/thing", "/hook", "/api/deep",
	} {
		if !has(links, want) {
			t.Errorf("did not extract %q; got %v", want, links)
		}
	}
	// A number is not a URL, and a bare "id" key is not an endpoint hint.
	if has(links, "42") || has(links, "7") {
		t.Errorf("a non-URL value was extracted: %v", links)
	}
}

// TestJSONLDVocabularyIsNotFollowed covers the branch that exists to stop a
// document steering the crawler at JSON-LD vocabulary URIs.
func TestJSONLDVocabularyIsNotFollowed(t *testing.T) {
	body := []byte(`{
	  "@context": "https://schema.org/",
	  "@id": "https://example.com/thing#id",
	  "@type": "WebPage",
	  "$schema": "https://json-schema.org/draft/2020-12/schema",
	  "url": "/api/real"
	}`)
	got := Extract(mustBase(t), body, "application/ld+json", allOpts())
	links := linksOf(got)

	for _, unwanted := range []string{"https://schema.org/", "https://json-schema.org/draft/2020-12/schema"} {
		if has(links, unwanted) {
			t.Errorf("a JSON-LD vocabulary URI was followed: %q", unwanted)
		}
	}
	// The document's own url key is a real endpoint and must survive.
	if !has(links, "/api/real") {
		t.Errorf("the document's own url was dropped: %v", links)
	}
}

// TestMalformedJSONStillYieldsLinks covers the fallback: a truncated response
// is common and should not throw away everything it did contain.
func TestMalformedJSONStillYieldsLinks(t *testing.T) {
	body := []byte(`{"data": {"url": "/api/found"}, "broken": `)
	got := Extract(mustBase(t), body, "application/json", allOpts())
	if !has(linksOf(got), "/api/found") {
		t.Errorf("a link in a truncated document was lost: %v", linksOf(got))
	}
}

// TestHostileJSONIsBounded covers a document shaped to exhaust the walker: deep
// nesting and a very wide object.
func TestHostileJSONIsBounded(t *testing.T) {
	deep := strings.Repeat(`{"a":`, 500) + `"leaf"` + strings.Repeat(`}`, 500)
	if got := Extract(mustBase(t), []byte(deep), "application/json", allOpts()); len(got.Links) > MaxLinks {
		t.Errorf("a deeply nested document produced %d links", len(got.Links))
	}

	var wide strings.Builder
	wide.WriteString(`{`)
	for i := range 20000 {
		if i > 0 {
			wide.WriteByte(',')
		}
		wide.WriteString(`"url":"/p`)
		wide.WriteString(strings.Repeat("x", 3))
		wide.WriteString(`"`)
	}
	wide.WriteString(`}`)
	got := Extract(mustBase(t), []byte(wide.String()), "application/json", allOpts())
	if len(got.Links) > MaxLinks {
		t.Errorf("a very wide document produced %d links, above the %d cap", len(got.Links), MaxLinks)
	}
}

func TestJSONParametersAreCollected(t *testing.T) {
	body := []byte(`{"url":"/search?q=test&page=2","other":"/plain"}`)
	got := Extract(mustBase(t), body, "application/json", allOpts())
	if len(got.Parameters) == 0 {
		t.Fatal("no parameters were collected from a JSON URL")
	}
	names := map[string]bool{}
	for _, p := range got.Parameters {
		names[p.Name] = true
	}
	for _, want := range []string{"q", "page"} {
		if !names[want] {
			t.Errorf("parameter %q was not collected: %v", want, names)
		}
	}
}

func TestJSONParametersSkippedWhenNotRequested(t *testing.T) {
	body := []byte(`{"url":"/search?q=test"}`)
	opts := ExtractOptions{Parameters: false}
	if got := Extract(mustBase(t), body, "application/json", opts); len(got.Parameters) != 0 {
		t.Errorf("parameters were collected when they were not requested: %v", got.Parameters)
	}
}

// --- XML and sitemaps --------------------------------------------------------

// TestSitemapLocationsAreFound covers the primary use of the XML path, which is
// reading a sitemap: the URLs are in <loc> elements, not in attributes.
func TestSitemapLocationsAreFound(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/a</loc><lastmod>2026-01-01</lastmod></url>
  <url><loc>https://example.com/b?q=1</loc></url>
  <url><loc>  https://example.com/c  </loc></url>
</urlset>`)
	got := Extract(mustBase(t), body, "application/xml", allOpts())
	links := linksOf(got)

	for _, want := range []string{"https://example.com/a", "https://example.com/b?q=1", "https://example.com/c"} {
		if !has(links, want) {
			t.Errorf("did not extract %q; got %v", want, links)
		}
	}
	// lastmod is a date, not an endpoint.
	if has(links, "2026-01-01") {
		t.Errorf("a date was treated as an endpoint: %v", links)
	}
	// Sitemap URLs are labelled as such so a report can say where they came from.
	if len(got.Links) > 0 && got.Links[0].Kind != models.EndpointSitemap {
		t.Errorf("kind = %q, want %q", got.Links[0].Kind, models.EndpointSitemap)
	}
}

// TestXMLAnchorsAndLinks covers generic XML carrying ordinary anchors.
func TestXMLAnchorsAndLinks(t *testing.T) {
	body := []byte(`<?xml version="1.0"?><doc><a href="/one">x</a><link href="/two"/></doc>`)
	got := Extract(mustBase(t), body, "application/xml", allOpts())
	links := linksOf(got)
	if !has(links, "/one") || !has(links, "/two") {
		t.Errorf("anchors were not extracted: %v", links)
	}
}

// TestLargeXMLTokenDoesNotAbortExtraction covers a document carrying one very
// large text node, which is what an inline script or a base64 blob looks like.
// The tokenizer's buffer limit is a byte limit, and it has to be generous enough
// that a single big token cannot silently truncate the whole document.
func TestLargeXMLTokenDoesNotAbortExtraction(t *testing.T) {
	big := strings.Repeat("A", 64<<10) // 64 KiB in one text node
	body := []byte(`<?xml version="1.0"?><urlset><url><loc>/first</loc></url>` +
		`<note>` + big + `</note><url><loc>/last</loc></url></urlset>`)

	got := Extract(mustBase(t), []byte(body), "application/xml", allOpts())
	links := linksOf(got)
	if !has(links, "/first") {
		t.Errorf("the link before the large token was lost: %v", links)
	}
	if !has(links, "/last") {
		t.Errorf("SECURITY REGRESSION: a large token aborted extraction; got %v", links)
	}
}

// --- HTML --------------------------------------------------------------------

func TestHTMLLinksFormsAndScripts(t *testing.T) {
	body := []byte(`<html><body>
	  <a href="/one">a</a>
	  <link rel="stylesheet" href="/style.css">
	  <script src="/app.js"></script>
	  <form action="/submit" method="post"><input name="q"></form>
	  <iframe src="/frame"></iframe>
	</body></html>`)
	got := Extract(mustBase(t), body, "text/html", allOpts())
	links := linksOf(got)

	for _, want := range []string{"/one", "/style.css", "/app.js", "/submit", "/frame"} {
		if !has(links, want) {
			t.Errorf("did not extract %q; got %v", want, links)
		}
	}
	if got.Forms != 1 {
		t.Errorf("forms = %d, want 1", got.Forms)
	}
	if got.Scripts == 0 {
		t.Error("no scripts were counted")
	}
	// A form's method must be recorded, because it says how the endpoint is
	// reached, and it must never be replayed automatically.
	var found bool
	for _, l := range got.Links {
		if l.URL == "/submit" {
			found = true
			if !strings.EqualFold(l.Method, "POST") {
				t.Errorf("form method = %q, want POST", l.Method)
			}
		}
	}
	if !found {
		t.Error("the form action was not recorded")
	}
}

// TestImagesAreNotEndpoints records a deliberate exclusion: an image source is
// not crawlable work, so it is recorded as neither a link nor an endpoint. The
// test exists so that a future "extract everything" change is a conscious one.
func TestImagesAreNotEndpoints(t *testing.T) {
	body := []byte(`<html><body><img src="/pic.png"><video src="/clip.mp4"></video></body></html>`)
	got := Extract(mustBase(t), body, "text/html", allOpts())
	for _, l := range linksOf(got) {
		if strings.HasSuffix(l, ".png") || strings.HasSuffix(l, ".mp4") {
			t.Errorf("a media source was recorded as an endpoint: %q", l)
		}
	}
}

func TestNonCrawlableSchemesAreNotExtracted(t *testing.T) {
	// A hostile or merely careless page can point the crawler at schemes that
	// are not URLs to fetch. Recording them would put "javascript:alert(1)" in
	// a report as though it were an endpoint.
	body := []byte(`<html><body>
	  <a href="javascript:alert(1)">x</a>
	  <a href="data:text/html,<script>1</script>">y</a>
	  <a href="file:///etc/passwd">z</a>
	  <a href="/real">ok</a>
	</body></html>`)
	got := Extract(mustBase(t), body, "text/html", allOpts())
	for _, l := range linksOf(got) {
		lower := strings.ToLower(l)
		for _, bad := range []string{"javascript:", "data:", "file:"} {
			if strings.HasPrefix(lower, bad) {
				t.Errorf("SECURITY: a non-crawlable scheme was recorded: %q", l)
			}
		}
	}
	if !has(linksOf(got), "/real") {
		t.Errorf("the legitimate link was lost: %v", linksOf(got))
	}
}

// TestBaseHrefCannotRedirectTheCrawl covers the guard on <base href>. A base
// element re-points every relative reference on the page, so a cross-origin one
// would let a page aim the crawler wherever it liked without linking to it.
func TestBaseHrefCannotRedirectTheCrawl(t *testing.T) {
	body := []byte(`<html><head><base href="https://cdn.example.com/app/"></head>
	<body><a href="x.html">x</a></body></html>`)
	got := Extract(mustBase(t), body, "text/html", allOpts())
	for _, l := range linksOf(got) {
		if strings.Contains(l, "cdn.example.com") {
			t.Errorf("SECURITY: a cross-origin base href was adopted as a target: %q", l)
		}
	}

	// A same-origin base is not a redirect either: it is recorded as a link
	// candidate and never as a new authority.
	same := []byte(`<html><head><base href="/app/"></head><body><a href="x.html">x</a></body></html>`)
	got2 := Extract(mustBase(t), same, "text/html", allOpts())
	if !has(linksOf(got2), "https://example.com/app/") {
		t.Errorf("a same-origin base was not recorded: %v", linksOf(got2))
	}
}

// --- limits ------------------------------------------------------------------

// TestLinkCapIsEnforced covers the bound that keeps one large page from filling
// the crawl queue.
func TestLinkCapIsEnforced(t *testing.T) {
	var b strings.Builder
	b.WriteString("<html><body>")
	// Unique hrefs, so dedup cannot mask an overrun.
	for i := range MaxLinks + 500 {
		b.WriteString(`<a href="/p`)
		b.WriteString(strconv.Itoa(i))
		b.WriteString(`">x</a>`)
	}
	b.WriteString("</body></html>")

	got := Extract(mustBase(t), []byte(b.String()), "text/html", allOpts())
	if len(got.Links) > MaxLinks {
		t.Errorf("extracted %d links, above the cap of %d", len(got.Links), MaxLinks)
	}
}

func TestDuplicateLinksAreCollapsed(t *testing.T) {
	body := []byte(`<html><body><a href="/same">1</a><a href="/same">2</a><a href="/same">3</a></body></html>`)
	got := Extract(mustBase(t), body, "text/html", allOpts())
	n := 0
	for _, l := range got.Links {
		if l.URL == "/same" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("the same link was recorded %d times", n)
	}
}

func TestEmptyAndUnknownTypesAreSafe(t *testing.T) {
	base := mustBase(t)
	if got := Extract(base, nil, "text/html", allOpts()); len(got.Links) != 0 {
		t.Errorf("an empty body produced links: %v", got.Links)
	}
	// An unknown content type falls through to the plain-text scanner, which
	// must still be bounded and must not panic.
	body := []byte("see https://example.com/from-text for details")
	got := Extract(base, body, "application/x-unknown", allOpts())
	if len(got.Links) > MaxLinks {
		t.Errorf("a plain-text body produced %d links", len(got.Links))
	}
}
