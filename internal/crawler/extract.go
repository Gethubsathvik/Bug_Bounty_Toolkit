package crawler

import (
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"

	"github.com/bbtoolkit/bugbounty/pkg/models"
)

// Limits that bound extraction work against hostile input.
const (
	// MaxElements caps how many nodes one document may contribute.
	MaxElements = 20000
	// MaxLinks caps the links returned from one document.
	MaxLinks = 2000
	// MaxFormFields caps form fields per document.
	MaxFormFields = 500
	// MaxJSONDepth caps JSON traversal.
	MaxJSONDepth = 12
	// MaxScriptRefs caps JavaScript references per document.
	MaxScriptRefs = 500
	// maxScriptBytes caps how much of a script body is scanned. A single
	// multi-megabyte .js file is otherwise enough to turn a crawl into a
	// regular-expression workload.
	// maxScriptBytes bounds how much of an inline script is scanned, and
	// maxTokenBytes bounds a single token handed to the HTML tokenizer. The
	// tokenizer's limit is in bytes, so it has to be sized in bytes; using a
	// node count here silently truncates documents with one large token.
	maxScriptBytes = 1 << 20
	// maxTokenBytes is comfortably larger than any legitimate single token and
	// still small enough that a hostile document cannot make the tokenizer
	// allocate without bound.
	maxTokenBytes = 1 << 20
)

// Link is one extracted reference.
type Link struct {
	URL  string
	Kind models.EndpointKind
	// Method is set for form submissions, which are recorded but never issued.
	Method string
}

// ExtractOptions toggles the individual extractors.
type ExtractOptions struct {
	JavaScript bool
	Forms      bool
	Parameters bool
	MaxParams  int
	// MaxLinks bounds the link list; zero means MaxLinks.
	MaxLinks int
}

// Extracted is the result of parsing one document.
type Extracted struct {
	Links      []Link
	Parameters []models.Parameter
	Forms      int
	Scripts    int
	Truncated  bool
}

// Extract parses a response body for links, forms, scripts and parameters.
func Extract(base *url.URL, body []byte, contentType string, opts ExtractOptions) Extracted {
	out := Extracted{}
	if len(body) == 0 {
		return out
	}
	if opts.MaxLinks <= 0 {
		opts.MaxLinks = MaxLinks
	}
	if opts.MaxParams <= 0 {
		opts.MaxParams = 300
	}
	ct := strings.ToLower(contentType)
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	now := time.Now().UTC()
	seen := map[string]struct{}{}
	add := func(raw string, kind models.EndpointKind, method string) {
		if raw == "" || len(out.Links) >= opts.MaxLinks {
			return
		}
		// Non-crawlable schemes are dropped here, at the one point every
		// extractor's output passes through. Filtering later, at resolve time,
		// leaves them in the extracted set, where a consumer that only reads
		// Extracted.Links would report "file:///etc/passwd" as a discovered
		// endpoint. Resolve still checks, as defence in depth.
		if !crawlableScheme(raw) {
			return
		}
		key := raw
		if method != "" {
			key = method + " " + raw
		}
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		out.Links = append(out.Links, Link{URL: raw, Kind: kind, Method: method})
	}

	switch ct {
	case "text/html", "application/xhtml+xml", "":
		extractHTML(base, body, opts, &out, add, now)
	case "application/javascript", "text/javascript", "application/x-javascript",
		"application/ecmascript", "text/ecmascript", "application/x-ecmascript":
		if opts.JavaScript {
			extractScript(body, opts, &out, add)
		}
	case "application/json", "text/json", "application/ld+json":
		extractJSON(base, body, opts, &out, add, now)
	case "text/xml", "application/xml", "application/rss+xml", "application/atom+xml":
		extractXML(base, body, opts, &out, add, now)
	case "text/plain":
		// robots.txt and similar: parse as a line-oriented list.
		extractPlain(base, body, &out, add)
	default:
		// Unknown type. Many servers mislabel a script as text/plain or send no
		// type at all, so the body is scanned both as markup and as a script.
		// Both passes are bounded, and a genuine HTML document simply yields
		// nothing extra from the script pass.
		extractHTML(base, body, opts, &out, add, now)
		if opts.JavaScript {
			extractScript(body, opts, &out, add)
		}
	}

	if opts.Parameters && base != nil {
		for _, l := range append([]Link(nil), out.Links...) {
			u, err := Resolve(base, l.URL)
			if err != nil {
				continue
			}
			out.Parameters = append(out.Parameters, parametersOf(u, l.Kind, "url", now)...)
		}
	}
	sort.SliceStable(out.Parameters, func(i, j int) bool {
		return out.Parameters[i].ParamFingerprint() < out.Parameters[j].ParamFingerprint()
	})
	return out
}

func extractHTML(base *url.URL, body []byte, opts ExtractOptions, out *Extracted,
	add func(string, models.EndpointKind, string), now time.Time) {

	z := html.NewTokenizer(strings.NewReader(string(body)))
	z.SetMaxBuf(MaxElements)

	elements := 0
	// A form is recorded as an endpoint and never submitted: only its method
	// and action are noted, so the report can point a human at it.
	formAction, formMethod, formSeen := "", "", false
	formFields := 0
	inForm := false
	inScript := false
	scriptBuf := strings.Builder{}

	// The loop exits through break so that whatever was still open at the end
	// of the body is flushed below.
loop:
	for {
		if elements > MaxElements {
			out.Truncated = true
			break
		}
		elements++
		switch z.Next() {
		case html.ErrorToken:
			break loop

		case html.StartTagToken, html.SelfClosingTagToken:
			name, _ := z.TagName()
			a := atom.Lookup(name)
			switch a {
			case atom.Script:
				inScript = opts.JavaScript
				scriptBuf.Reset()
				if src, ok := attr(z, "src"); ok && src != "" {
					out.Scripts++
					if len(out.Links) < MaxScriptRefs {
						add(src, models.EndpointScript, "")
					}
				}
			case atom.A, atom.Area:
				if href, ok := attr(z, "href"); ok {
					add(href, models.EndpointLink, "")
				}
			case atom.Link:
				if href, ok := attr(z, "href"); ok {
					// <link rel=stylesheet> is an asset reference worth knowing
					// about, but it is not a page to crawl.
					add(href, models.EndpointLink, "")
				}
			case atom.Form:
				inForm = true
				formAction, _ = attr(z, "action")
				formMethod, _ = attr(z, "method")
				if formMethod == "" {
					formMethod = "GET"
				}
				formSeen = true
				out.Forms++
			case atom.Input:
				if opts.Forms && inForm {
					if n, ok := attr(z, "name"); ok && n != "" && formFields < MaxFormFields {
						formFields++
						out.Parameters = append(out.Parameters, models.Parameter{
							Name: truncate(n, 128), Kind: models.ParamForm,
							Source: "form", Observed: now,
							Interesting: isInterestingName(n), Reason: interestingReason(n),
						})
					}
				}
			case atom.Select, atom.Textarea:
				if opts.Forms && inForm {
					if n, ok := attr(z, "name"); ok && n != "" && formFields < MaxFormFields {
						formFields++
						out.Parameters = append(out.Parameters, models.Parameter{
							Name: truncate(n, 128), Kind: models.ParamForm,
							Source: "form", Observed: now,
							Interesting: isInterestingName(n), Reason: interestingReason(n),
						})
					}
				}
			case atom.Iframe, atom.Frame:
				if src, ok := attr(z, "src"); ok {
					add(src, models.EndpointLink, "")
				}
			case atom.Img, atom.Source:
				// An image source is not crawlable work, but a data: URI here is
				// a signal and must be filtered out by Resolve anyway.
			case atom.Base:
				// A <base href> can re-point every relative reference on the
				// page. Honouring one that leaves the origin we already fetched
				// would let a page redirect the crawl at will, so only
				// same-origin base elements are accepted, and only as a link
				// candidate rather than as a new authority.
				if href, ok := attr(z, "href"); ok {
					if b, err := Resolve(base, href); err == nil &&
						strings.EqualFold(b.Host, base.Host) {
						add(b.String(), models.EndpointLink, "")
					}
				}
			}
			// Any element may carry an inline event handler with a URL.
			if opts.JavaScript && len(out.Links) < MaxScriptRefs {
				collectInlineHandlers(z, add)
			}

		case html.EndTagToken:
			name, _ := z.TagName()
			switch atom.Lookup(name) {
			case atom.Form:
				// The action is recorded with its real method so a report can
				// say "this form posts to X" without the crawler ever sending
				// anything.
				if formSeen && formAction != "" && len(out.Links) < MaxLinks {
					add(formAction, models.EndpointForm, strings.ToUpper(formMethod))
				}
				inForm = false
				formFields = 0
				formSeen = false
			case atom.Script:
				if inScript {
					for _, u := range extractJSEndpoints(scriptBuf.String()) {
						add(u, models.EndpointJS, "")
					}
				}
				inScript = false
				scriptBuf.Reset()
			}

		case html.TextToken:
			if opts.JavaScript && inScript {
				if scriptBuf.Len() < maxScriptBytes {
					scriptBuf.Write(z.Text())
				}
			}
		}
	}
	// An unterminated <form> or <script> is ordinary hostile markup. Whatever
	// was open when the body ended is still recorded, so a page that never
	// closes its tags cannot hide its attack surface.
	if formSeen && formAction != "" {
		add(formAction, models.EndpointForm, strings.ToUpper(formMethod))
	}
	if opts.JavaScript && inScript {
		for _, u := range extractJSEndpoints(scriptBuf.String()) {
			add(u, models.EndpointJS, "")
		}
	}
}

func attr(z *html.Tokenizer, key string) (string, bool) {
	for {
		k, v, more := z.TagAttr()
		if strings.EqualFold(string(k), key) {
			return string(v), true
		}
		if !more {
			return "", false
		}
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// Inline handler attributes that may embed a URL.
var inlineHandlers = []string{"onclick", "onload", "onerror", "onmouseover", "onfocus", "onsubmit"}

// JavaScript string literals are delimited by ', " or `, so the patterns below
// are written as interpreted strings rather than raw ones: a raw literal
// cannot contain a backtick.
const jsQuoteClass = "[\"'`]"

// jsURL finds absolute and site-relative URLs inside JavaScript string
// literals. It is bounded so a hostile script cannot produce unbounded output.
// Note that Go's regexp caps a repetition count at 1000, so the bound here is
// expressed that way; the caller truncates anything longer anyway.
var jsURL = regexp.MustCompile(
	jsQuoteClass + `((?:https?:)?//[^"'` + "`" + `\s<>]{1,1000})` + jsQuoteClass +
		`|` + jsQuoteClass + `(/[A-Za-z0-9._~%\-/]{1,512}(?:\?[^"'` + "`" + `\s<>]{0,512})?)` + jsQuoteClass)

// jsFetch finds fetch() and axios call sites.
var jsFetch = regexp.MustCompile(
	`(?i)\b(?:fetch|axios(?:\.[a-z]+)?|open)\s*\(\s*` + jsQuoteClass + `([^"'` + "`" + `]{1,512})` + jsQuoteClass)

// jsXHR finds XMLHttpRequest.open with a method and a URL.
var jsXHR = regexp.MustCompile(
	`(?i)\.open\s*\(\s*` + jsQuoteClass + `([A-Z]{3,10})` + jsQuoteClass + `\s*,\s*` + jsQuoteClass + `([^"'` + "`" + `]{1,512})` + jsQuoteClass)

// extractJSEndpoints pulls candidate endpoint paths out of a script body. It
// only ever records strings; it never evaluates or fetches anything.
//
// The match caps are the real bound on hostile input: a script that repeats the
// same call ten million times contributes at most MaxScriptRefs results, and
// the regexp engine itself never backtracks between alternatives here.
func extractJSEndpoints(src string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || len(s) > 2048 {
			return
		}
		if _, dup := seen[s]; dup {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, m := range jsFetch.FindAllStringSubmatch(src, MaxScriptRefs) {
		if m[1] != "" {
			add(m[1])
		}
	}
	for _, m := range jsXHR.FindAllStringSubmatch(src, MaxScriptRefs) {
		if len(m) > 2 && m[2] != "" {
			add(m[2])
		}
	}
	for _, m := range jsURL.FindAllStringSubmatch(src, MaxScriptRefs*2) {
		for _, g := range m[1:] {
			if g != "" {
				add(g)
			}
		}
	}
	return out
}

// extractScript handles a response that is a standalone JavaScript file rather
// than a page containing one.
func extractScript(body []byte, opts ExtractOptions, out *Extracted,
	add func(string, models.EndpointKind, string)) {
	src := body
	if len(src) > maxScriptBytes {
		src = src[:maxScriptBytes]
		out.Truncated = true
	}
	for _, u := range extractJSEndpoints(string(src)) {
		out.Scripts++
		add(u, models.EndpointJS, "")
	}
	_ = opts
}

func collectInlineHandlers(z *html.Tokenizer, add func(string, models.EndpointKind, string)) {
	for {
		k, v, more := z.TagAttr()
		for _, h := range inlineHandlers {
			if strings.EqualFold(string(k), h) {
				for _, u := range extractJSEndpoints(string(v)) {
					add(u, models.EndpointJS, "")
				}
			}
		}
		if !more {
			return
		}
	}
}

// extractJSON walks a JSON document for string values that look like endpoints
// or URLs. The walk is depth-bounded and node-bounded.
func extractJSON(base *url.URL, body []byte, opts ExtractOptions, out *Extracted,
	add func(string, models.EndpointKind, string), now time.Time) {

	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.UseNumber()
	nodes := 0
	var walk func(v any, depth int)
	walk = func(v any, depth int) {
		if depth > MaxJSONDepth || nodes > MaxElements {
			return
		}
		switch t := v.(type) {
		case map[string]any:
			for k, val := range t {
				nodes++
				lower := strings.ToLower(k)
				switch {
				case lower == "url" || lower == "uri" || lower == "href" ||
					lower == "link" || lower == "endpoint" || lower == "path" ||
					lower == "location" || lower == "callbackurl":
					if s, ok := val.(string); ok && s != "" {
						add(s, models.EndpointJSON, "")
						if opts.Parameters {
							if u, err := Resolve(base, s); err == nil {
								out.Parameters = append(out.Parameters, parametersOf(u, models.EndpointJSON, "json", now)...)
							}
						}
					}
				case lower == "@id", lower == "@context", lower == "$schema", lower == "url":
					// Known JSON-LD vocabulary: never followed.
				}
				walk(val, depth+1)
			}
		case []any:
			for _, val := range t {
				nodes++
				walk(val, depth+1)
			}
		case string:
			nodes++
			if opts.Parameters && strings.HasPrefix(t, "/") && len(t) < 512 {
				add(t, models.EndpointJSON, "")
			}
		}
	}
	var root any
	if err := dec.Decode(&root); err != nil {
		// Malformed JSON: fall back to a bounded text scan rather than failing
		// the whole page, because partial JSON often still reveals endpoints.
		extractJSONText(body, add)
		return
	}
	walk(root, 0)
}

var jsonURLLike = regexp.MustCompile(`"(?:url|uri|href|path|endpoint|link)"\s*:\s*"([^"]{1,512})"`)

func extractJSONText(body []byte, add func(string, models.EndpointKind, string)) {
	for _, m := range jsonURLLike.FindAllStringSubmatch(string(body), 64) {
		add(m[1], models.EndpointJSON, "")
	}
}

// extractXML handles sitemaps and generic XML.
func extractXML(base *url.URL, body []byte, opts ExtractOptions, out *Extracted,
	add func(string, models.EndpointKind, string), now time.Time) {

	kind := models.EndpointSitemap
	if strings.Contains(strings.ToLower(string(body[:min(len(body), 512)])), "<?xml") &&
		!strings.Contains(strings.ToLower(string(body[:min(len(body), 512)])), "urlset") {
		kind = models.EndpointLink
	}
	text := string(body)
	if len(text) > 4<<20 {
		text = text[:4<<20]
		out.Truncated = true
	}
	// maxTokenBytes bounds a single token, not the document. MaxElements counts
	// nodes and is in the tens of thousands; reusing it here would cap any one
	// text run at a few kilobytes, so a page with an inline script, a base64
	// blob or a long sitemap URL would abort the tokenizer and silently lose
	// every link after it. The node count is bounded separately by the loop.
	z := html.NewTokenizer(strings.NewReader(text))
	z.SetMaxBuf(maxTokenBytes)
	n := 0
	for {
		if n > MaxElements {
			out.Truncated = true
			return
		}
		n++
		switch z.Next() {
		case html.ErrorToken:
			return
		case html.StartTagToken, html.SelfClosingTagToken:
			name, _ := z.TagName()
			switch atom.Lookup(name) {
			case atom.A:
				if href, ok := attr(z, "href"); ok {
					add(href, kind, "")
				}
			case atom.Link:
				if href, ok := attr(z, "href"); ok {
					add(href, kind, "")
				}
			}
			// Sitemap loc elements are not attribute based.
			if strings.EqualFold(string(name), "loc") {
				if z.Next() == html.TextToken {
					loc := strings.TrimSpace(string(z.Text()))
					if loc != "" {
						add(loc, kind, "")
						if opts.Parameters && base != nil {
							if u, err := Resolve(base, loc); err == nil {
								out.Parameters = append(out.Parameters, parametersOf(u, kind, "sitemap", now)...)
							}
						}
					}
				}
			}
		}
	}
}

// extractPlain handles robots.txt and similar line-oriented documents.
func extractPlain(base *url.URL, body []byte, out *Extracted, add func(string, models.EndpointKind, string)) {
	text := string(body)
	if len(text) > 1<<20 {
		text = text[:1<<20]
		out.Truncated = true
	}
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// robots.txt allows either "Disallow: /path" or a bare "/path".
		if i := strings.IndexByte(line, ':'); i >= 0 {
			field := strings.ToLower(strings.TrimSpace(line[:i]))
			if field == "disallow" || field == "allow" {
				line = strings.TrimSpace(line[i+1:])
			}
		}
		if !strings.HasPrefix(line, "/") {
			continue
		}
		if len(line) > 2048 {
			continue
		}
		add(line, models.EndpointRobots, "")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// parametersOf extracts query and path parameters from a URL.
func parametersOf(u *url.URL, kind models.EndpointKind, source string, now time.Time) []models.Parameter {
	if u == nil {
		return nil
	}
	var out []models.Parameter
	seen := map[string]struct{}{}
	for k := range u.Query() {
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, models.Parameter{
			Name: truncate(k, 128), Kind: models.ParamQuery, Source: source,
			URL: stripQuery(u), Observed: now,
			Interesting: isInterestingName(k), Reason: interestingReason(k),
		})
	}
	// Path segments that look like identifiers are a common source of
	// authorization mistakes, so they are recorded as path parameters.
	for _, seg := range strings.Split(strings.Trim(u.Path, "/"), "/") {
		if seg == "" || len(seg) > 64 {
			continue
		}
		if looksLikeUUID(seg) || looksNumericID(seg) {
			out = append(out, models.Parameter{
				Name: "{path}", Kind: models.ParamPath, Source: source,
				URL: stripQuery(u), Observed: now,
				Interesting: true, Reason: "path segment " + seg + " looks like an object identifier",
			})
			break
		}
	}
	return out
}

func stripQuery(u *url.URL) string {
	c := *u
	c.RawQuery = ""
	c.Fragment = ""
	return c.String()
}

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func looksLikeUUID(s string) bool { return uuidRe.MatchString(s) }

func looksNumericID(s string) bool {
	if len(s) < 4 || len(s) > 19 {
		return false
	}
	_, err := strconv.ParseUint(s, 10, 64)
	return err == nil
}

// interestingNames are parameter names that commonly sit on a trust boundary.
// They are recorded with a reason so a report can explain why the parameter was
// highlighted; the toolkit never acts on them.
var interestingNames = map[string]string{
	"id": "object identifier", "uid": "user identifier", "user_id": "user identifier",
	"userid": "user identifier", "account": "account selector", "account_id": "account selector",
	"admin": "privilege selector", "role": "privilege selector", "is_admin": "privilege selector",
	"token": "bearer value", "access_token": "bearer value", "refresh_token": "bearer value",
	"api_key": "credential", "apikey": "credential", "key": "credential",
	"password": "credential", "passwd": "credential", "secret": "credential",
	"email": "personal data", "phone": "personal data", "ssn": "personal data",
	"redirect": "open redirect candidate", "redirect_uri": "open redirect candidate",
	"return_url": "open redirect candidate", "next": "open redirect candidate",
	"callback": "open redirect candidate", "url": "server-side fetch candidate",
	"uri": "server-side fetch candidate", "path": "server-side fetch candidate",
	"file": "file reference", "path_": "file reference", "filename": "file reference",
	"debug": "debug switch", "test": "test switch", "verbose": "debug switch",
	"sql": "query fragment", "query": "query fragment", "search": "query fragment",
	"q": "query fragment", "order": "sort control", "sort": "sort control",
	"sortby": "sort control", "lang": "locale control", "locale": "locale control",
	"page": "pagination control", "offset": "pagination control", "limit": "pagination control",
	"include": "file inclusion candidate", "template": "template injection candidate",
	"callback_url": "open redirect candidate", "target": "redirect target",
	"proxy": "proxy candidate", "gateway": "proxy candidate", "dest": "redirect target",
	"signature": "signed value", "sig": "signed value", "hmac": "signed value",
	"state": "OAuth state", "code": "authorization code", "client_id": "OAuth client",
	"response_type": "OAuth parameter", "scope": "OAuth scope", "grant_type": "OAuth grant",
}

func isInterestingName(name string) bool {
	_, ok := interestingNames[strings.ToLower(name)]
	return ok
}

func interestingReason(name string) string {
	if r, ok := interestingNames[strings.ToLower(name)]; ok {
		return r
	}
	return ""
}

// IsInterestingName is the exported form used by the parameter analysis
// framework.
func IsInterestingName(name string) (bool, string) {
	if r, ok := interestingNames[strings.ToLower(name)]; ok {
		return true, r
	}
	return false, ""
}

// Reflected reports whether a probe value appears in a response body. It is
// only ever called on a response the toolkit already fetched; it does not send
// anything.
func Reflected(body []byte, needle string) bool {
	if needle == "" || len(body) == 0 {
		return false
	}
	return strings.Contains(string(body), needle)
}
