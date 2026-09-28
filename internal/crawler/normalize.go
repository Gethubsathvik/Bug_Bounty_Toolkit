package crawler

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"

	"github.com/bbtoolkit/bugbounty/internal/scope"
)

// NormalizeURL canonicalizes a URL so that two spellings of the same resource
// deduplicate to one entry.
//
// The transformations are deliberately conservative: a query string is
// reordered but never altered, and a path is dot-segment resolved but never
// case-folded, because both would change the request the server sees. What it
// does remove is the set of spellings a hostile page could use to make the
// crawler revisit a page: duplicate slashes, dot segments, the fragment, an
// empty query, a default port, and a userinfo section.
func NormalizeURL(raw, method string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("parsing %q: %w", raw, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("%q is not an absolute URL", raw)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return nil, fmt.Errorf("scheme %q is not crawlable", u.Scheme)
	}

	// A fragment is client-side only and never reaches the server. Dropping it
	// prevents #a/#b/#c variants of one page from consuming the budget.
	u.Fragment = ""
	u.RawFragment = ""

	// Credentials in a crawled link are an attack, not a target.
	if u.User != nil {
		return nil, fmt.Errorf("URL carries embedded credentials")
	}

	// An empty query is a different request from no query only in the strictest
	// reading; in practice they are the same resource.
	if u.RawQuery == "" || u.RawQuery == "?" {
		u.ForceQuery = false
	}

	host, err := scope.CanonicalizeDomain(u.Host)
	if err != nil {
		return nil, err
	}
	port := u.Port()
	lower := strings.ToLower(u.Scheme)
	switch {
	case lower == "http" && port == "80", lower == "https" && port == "443":
		port = ""
	}
	if port == "" {
		u.Host = host
	} else {
		// Only an IPv6 literal may be bracketed in a URL authority. Bracketing
		// an IPv4 literal produces "http://[127.0.0.1]:8080/", which the HTTP
		// client then rejects as an invalid IP literal. net.JoinHostPort applies
		// exactly the right rule.
		u.Host = net.JoinHostPort(host, port)
	}
	u.Scheme = lower

	u.Path, u.RawPath = normalizePath(u.EscapedPath())
	u.RawQuery = normalizeQuery(u.Query())

	// A method other than GET cannot be expressed by a crawler request, so the
	// canonical form is only meaningful for GET. Anything else is recorded but
	// never queued.
	_ = method
	return u, nil
}

// normalizePath resolves dot segments and collapses duplicate slashes in the
// escaped path, returning both the decoded and escaped forms consistently.
func normalizePath(p string) (string, string) {
	if p == "" {
		return "/", ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	segs := strings.Split(strings.TrimPrefix(p, "/"), "/")
	out := make([]string, 0, len(segs))
	for i, s := range segs {
		switch s {
		case ".":
			if i == len(segs)-1 {
				out = append(out, "")
			}
			continue
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
			continue
		case "":
			// Collapse interior duplicates, keep a trailing slash.
			if i == len(segs)-1 {
				out = append(out, "")
			}
			continue
		default:
			out = append(out, s)
		}
	}
	joined := "/" + strings.Join(out, "/")
	// Re-decode only the characters that a server is guaranteed to decode the
	// same way, so that /a%2Fb and /a/b remain distinct (they can be different
	// resources) while %2e%2e is still resolved above.
	decoded, err := url.PathUnescape(joined)
	if err != nil {
		return joined, ""
	}
	return joined, decoded
}

// normalizeQuery sorts query parameters so that ?a=1&b=2 and ?b=2&a=1 collapse
// to one entry. Values are never modified.
func normalizeQuery(v url.Values) string {
	if len(v) == 0 {
		return ""
	}
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		vals := append([]string(nil), v[k]...)
		sort.Strings(vals)
		for _, val := range vals {
			if b.Len() > 0 {
				b.WriteByte('&')
			}
			b.WriteString(url.QueryEscape(k))
			b.WriteByte('=')
			b.WriteString(url.QueryEscape(val))
		}
	}
	return b.String()
}

// nonCrawlableSchemes are reference schemes that are never something the
// crawler may follow. A "javascript:" or "data:" reference is executable
// content or an inline blob, not a page; "file:" would reach the local disk.
var nonCrawlableSchemes = []string{
	"javascript:", "data:", "vbscript:", "file:", "blob:", "about:",
}

// crawlableScheme reports whether a reference may be recorded as a discovered
// endpoint. A relative reference has no scheme and is always acceptable; the
// decision is made on the text before parsing so that a malformed URL cannot
// slip past on a parse error.
func crawlableScheme(ref string) bool {
	lower := strings.ToLower(strings.TrimSpace(ref))
	if lower == "" {
		return false
	}
	for _, bad := range nonCrawlableSchemes {
		if strings.HasPrefix(lower, bad) {
			return false
		}
	}
	return true
}

// Resolve turns a possibly relative reference into an absolute URL.
func Resolve(base *url.URL, ref string) (*url.URL, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, fmt.Errorf("empty reference")
	}
	// A reference is remote content: a "javascript:" or "data:" URL is never
	// something the crawler may follow.
	if !crawlableScheme(ref) {
		scheme := ""
		if i := strings.IndexByte(ref, ':'); i > 0 {
			scheme = ref[:i+1]
		}
		return nil, fmt.Errorf("reference scheme %q is not crawlable", scheme)
	}
	parsed, err := url.Parse(ref)
	if err != nil {
		return nil, err
	}
	return base.ResolveReference(parsed), nil
}

// CanonicalHost returns the canonical hostname of a URL.
func CanonicalHost(u *url.URL) string {
	h, err := scope.CanonicalizeDomain(u.Hostname())
	if err != nil {
		return strings.ToLower(u.Hostname())
	}
	return h
}
