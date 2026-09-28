package httpclient

import (
	"bytes"
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// ExtractTitle pulls a human-readable page title out of a response body.
//
// Remote HTML is hostile input. The parser used here is the WHATWG-conformant
// html package rather than a regular expression, and the tokenizer has an
// explicit input bound, so a response consisting of deeply nested or
// unterminated markup cannot cause unbounded work or unbounded memory.
func ExtractTitle(body []byte, contentType string) string {
	if len(body) == 0 {
		return ""
	}
	if contentType != "" && !isHTMLContentType(contentType) {
		return ""
	}
	// A title is a short string; anything beyond this is not a document we
	// need to walk in full.
	const maxScan = 512 << 10
	if len(body) > maxScan {
		body = body[:maxScan]
	}
	if !bytes.Contains(bytes.ToLower(body[:min(len(body), 4096)]), []byte("<title")) {
		return ""
	}

	z := html.NewTokenizer(bytes.NewReader(body))
	z.SetMaxBuf(0)
	depth := 0
	for {
		switch z.Next() {
		case html.ErrorToken:
			return ""
		case html.StartTagToken, html.SelfClosingTagToken:
			// The second return of TagName reports whether the tag carries
			// attributes, not whether the name is usable; a <title> with no
			// attributes is still a title.
			name, _ := z.TagName()
			switch atom.Lookup(name) {
			case atom.Title:
				if z.Next() != html.TextToken {
					return ""
				}
				return cleanTitle(string(z.Text()))
			case atom.Head, atom.Body, atom.Html:
				depth++
				if depth > 64 {
					// Deeply nested markup is not a document worth walking.
					return ""
				}
			}
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func isHTMLContentType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	switch ct {
	case "text/html", "application/xhtml+xml", "text/xml", "application/xml":
		return true
	case "":
		return true
	default:
		return false
	}
}

var (
	wsCollapse = regexp.MustCompile(`\s+`)
	// A title is rendered into CSV, Markdown and HTML reports, so it is
	// stripped of control characters and bounded in length.
	ctrl = regexp.MustCompile("[\x00-\x1f\x7f]")
)

func cleanTitle(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	s = ctrl.ReplaceAllString(s, " ")
	s = wsCollapse.ReplaceAllString(strings.TrimSpace(s), " ")
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}
