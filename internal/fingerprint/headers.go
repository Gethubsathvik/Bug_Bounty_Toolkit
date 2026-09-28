package fingerprint

import (
	"fmt"
	"sort"
	"strings"

	"github.com/bbtoolkit/bugbounty/pkg/models"
)

// securityHeader describes a header the toolkit considers worth reporting on.
type securityHeader struct {
	Name        string
	Why         string
	Remediation string
	// Optional marks a header whose absence is informational rather than a
	// weakness, because its value depends entirely on the application.
	Optional bool
}

// securityHeaders is the catalogue used by the analyzer. It is data so that the
// report wording and the detection stay in one place.
var securityHeaders = []securityHeader{
	{"Content-Security-Policy",
		"The response does not set a Content-Security-Policy header.",
		"Deploy a Content-Security-Policy appropriate to the application, starting from report-only and tightening as the application is verified.",
		false},
	{"Strict-Transport-Security",
		"The response over HTTPS does not set Strict-Transport-Security.",
		"Serve HSTS with a max-age appropriate to the risk, includeSubDomains once every subdomain is HTTPS-only, and consider preload.",
		false},
	{"X-Content-Type-Options",
		"The response does not set X-Content-Type-Options, so a browser may MIME-sniff the payload.",
		"Send X-Content-Type-Options: nosniff on every response.",
		false},
	{"X-Frame-Options",
		"The response does not restrict framing, so clickjacking protection depends on a Content-Security-Policy frame-ancestors directive that is not present.",
		"Send X-Frame-Options: DENY or SAMEORIGIN, and add a frame-ancestors directive to the CSP.",
		false},
	{"Referrer-Policy",
		"The response does not set Referrer-Policy, so full URLs including any query string may leak to third parties.",
		"Send Referrer-Policy: strict-origin-when-cross-origin, or stricter.",
		true},
	{"Permissions-Policy",
		"The response does not set Permissions-Policy to restrict unused browser capabilities.",
		"Send a Permissions-Policy disabling the features the application does not use.",
		true},
	{"Cross-Origin-Opener-Policy",
		"The response does not set Cross-Origin-Opener-Policy.",
		"Consider COOP: same-origin where the application does not need to share a browsing context group with cross-origin pages.",
		true},
}

// HSTSAnalysis inspects a Strict-Transport-Security header value.
func HSTSAnalysis(value string) (present bool, notes []string) {
	if strings.TrimSpace(value) == "" {
		return false, nil
	}
	v := strings.ToLower(value)
	if !strings.Contains(v, "max-age=") {
		notes = append(notes, "max-age directive is absent, so the policy has no effect")
		return true, notes
	}
	maxAge, rest := extractMaxAge(value)
	if maxAge == 0 {
		notes = append(notes, "max-age=0 disables the policy entirely")
	}
	if maxAge > 0 && maxAge < 15552000 {
		notes = append(notes, fmt.Sprintf("max-age=%d is below 180 days; browsers may drop the header", maxAge))
	}
	if !strings.Contains(rest, "includesubdomains") {
		notes = append(notes, "includeSubDomains is absent, so subdomains are not covered")
	}
	if !strings.Contains(rest, "preload") {
		notes = append(notes, "the header is not preload-eligible without a preload token")
	}
	return true, notes
}

func extractMaxAge(v string) (int64, string) {
	i := strings.Index(strings.ToLower(v), "max-age=")
	if i < 0 {
		return 0, ""
	}
	rest := v[i+len("max-age="):]
	j := 0
	for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
		j++
	}
	var n int64
	for k := 0; k < j; k++ {
		n = n*10 + int64(rest[k]-'0')
		if n > 1<<40 {
			// A value this large is a denial-of-service vector against the
			// operator's own estate; stop parsing rather than overflow.
			return 1 << 40, rest[j:]
		}
	}
	return n, rest[j:]
}

// CSPAnalysis reports the directives a Content-Security-Policy carries and the
// ones it is missing.
type CSPAnalysis struct {
	Present    bool
	Raw        string
	Directives map[string][]string
	Missing    []string
	Notes      []string
}

// ParseCSP parses a CSP header value. Malformed input yields a report with
// notes rather than an error, because a broken policy is itself the finding.
func ParseCSP(value string) CSPAnalysis {
	out := CSPAnalysis{Raw: value, Directives: map[string][]string{}}
	if strings.TrimSpace(value) == "" {
		return out
	}
	out.Present = true
	for _, part := range strings.Split(value, ";") {
		fields := strings.Fields(strings.TrimSpace(part))
		if len(fields) == 0 {
			continue
		}
		name := strings.ToLower(fields[0])
		out.Directives[name] = append(out.Directives[name], fields[1:]...)
	}
	for _, want := range []string{"default-src", "object-src", "base-uri", "frame-ancestors"} {
		if _, ok := out.Directives[want]; !ok {
			out.Missing = append(out.Missing, want)
		}
	}
	if v, ok := out.Directives["default-src"]; ok && containsUnsafeSource(v) {
		out.Notes = append(out.Notes, "default-src includes a wildcard or 'unsafe-inline'/'unsafe-eval', which substantially weakens the policy")
	}
	if _, ok := out.Directives["object-src"]; !ok {
		out.Notes = append(out.Notes, "without object-src the default-src applies to plugins, which is usually not intended")
	}
	return out
}

func containsUnsafeSource(v []string) bool {
	for _, s := range v {
		switch strings.ToLower(s) {
		case "*", "'unsafe-inline'", "'unsafe-eval'", "data:", "http:":
			return true
		}
	}
	return false
}

// CookieAnalysis inspects one Set-Cookie header.
type CookieAnalysis struct {
	Name     string
	Issues   []string
	Secure   bool
	HTTPOnly bool
	SameSite string
}

// ParseSetCookie inspects a Set-Cookie header value.
func ParseSetCookie(value string) CookieAnalysis {
	c := CookieAnalysis{Name: cookieName(value)}
	for _, attr := range strings.Split(value, ";")[1:] {
		a := strings.ToLower(strings.TrimSpace(attr))
		switch {
		case a == "secure":
			c.Secure = true
		case a == "httponly":
			c.HTTPOnly = true
		case strings.HasPrefix(a, "samesite="):
			// Canonicalised so a report reads "Strict" rather than whatever
			// casing the server happened to use.
			switch v := strings.ToLower(strings.TrimSpace(a[len("samesite="):])); v {
			case "strict":
				c.SameSite = "Strict"
			case "lax":
				c.SameSite = "Lax"
			case "none":
				c.SameSite = "None"
			default:
				c.SameSite = v
			}
		}
	}
	if !c.Secure {
		c.Issues = append(c.Issues, "no Secure attribute, so the cookie is sent over plaintext HTTP")
	}
	if !c.HTTPOnly {
		c.Issues = append(c.Issues, "no HttpOnly attribute, so the cookie is readable from script")
	}
	switch strings.ToLower(c.SameSite) {
	case "none":
		c.Issues = append(c.Issues, "SameSite=None without Secure allows cross-site sending")
	case "":
		c.Issues = append(c.Issues, "no SameSite attribute; the browser default differs between browsers")
	case "lax", "strict":
	default:
		c.Issues = append(c.Issues, "SameSite value is not one of Strict, Lax or None")
	}
	return c
}

// AnalyzeSecurityHeaders produces the report stored on a service and consumed
// by the finding engine.
func AnalyzeSecurityHeaders(header map[string][]string, isHTTPS bool) models.SecurityHeaderReport {
	rep := models.SecurityHeaderReport{Present: map[string]string{}}
	lookup := map[string]string{}
	// all keeps every value of a repeated header, which matters for Set-Cookie:
	// each cookie is hardened independently.
	all := map[string][]string{}
	for k, vs := range header {
		lk := strings.ToLower(k)
		all[lk] = append(all[lk], vs...)
		if len(vs) > 0 {
			lookup[lk] = vs[0]
		}
	}
	for _, sh := range securityHeaders {
		v, ok := lookup[strings.ToLower(sh.Name)]
		if !ok || strings.TrimSpace(v) == "" {
			rep.Missing = append(rep.Missing, sh.Name)
			continue
		}
		// Header values are shown truncated and only for the headers whose value
		// is itself the signal; nothing here can carry a session identifier
		// because the redaction pass already ran.
		rep.Present[sh.Name] = v
	}
	if isHTTPS {
		if present, notes := HSTSAnalysis(lookup["strict-transport-security"]); !present {
			rep.Notes = append(rep.Notes, "no HSTS on an HTTPS response")
		} else {
			rep.Notes = append(rep.Notes, notes...)
		}
	}
	if csp := lookup["content-security-policy"]; csp != "" {
		a := ParseCSP(csp)
		if len(a.Missing) > 0 {
			rep.Weak = append(rep.Weak, a.Missing...)
		}
		rep.Notes = append(rep.Notes, a.Notes...)
	}
	// Report the CORS posture, which is a common misconfiguration.
	if acao := lookup["access-control-allow-origin"]; acao != "" {
		if strings.TrimSpace(acao) == "*" {
			rep.Notes = append(rep.Notes, "Access-Control-Allow-Origin is a wildcard, which permits any origin to read responses")
		} else if strings.Contains(acao, "null") {
			rep.Notes = append(rep.Notes, "Access-Control-Allow-Origin includes the 'null' origin, which sandboxed and data: documents can send")
		}
	}
	if lookup["access-control-allow-credentials"] == "true" && strings.TrimSpace(lookup["access-control-allow-origin"]) != "*" {
		rep.Notes = append(rep.Notes, "Access-Control-Allow-Credentials is true with a specific origin; verify that origin is intended")
	}
	// Cookie hardening. A Set-Cookie without Secure, HttpOnly and SameSite is a
	// routine finding, and the raw value is never reproduced here: only the
	// cookie's name and the attributes it carries.
	for _, one := range all["set-cookie"] {
		rep.Notes = append(rep.Notes, cookieNotes(one, isHTTPS)...)
	}
	sort.Strings(rep.Missing)
	sort.Strings(rep.Weak)
	return rep
}

// cookieNotes describes how a single Set-Cookie header is hardened. It reports
// the cookie's name and the attributes it carries, never its value, which may
// be a live session identifier.
func cookieNotes(raw string, isHTTPS bool) []string {
	c := ParseSetCookie(raw)
	if c.Name == "" {
		return nil
	}
	var out []string
	prefix := "cookie " + c.Name + ":"
	if isHTTPS && !c.Secure {
		out = append(out, prefix+" missing Secure on an HTTPS response")
	}
	if !c.HTTPOnly {
		out = append(out, prefix+" missing HttpOnly, so it is readable from script")
	}
	switch c.SameSite {
	case "":
		out = append(out, prefix+" missing SameSite, so cross-site requests carry it by default")
	case "none":
		if !c.Secure {
			out = append(out, prefix+" uses SameSite=None without Secure, which browsers reject")
		}
	}
	return out
}

// HeaderCatalogue returns the security headers the analyzer considers, for
// documentation and for the `fingerprint` command's explain output.
func HeaderCatalogue() []string {
	out := make([]string, 0, len(securityHeaders))
	for _, h := range securityHeaders {
		out = append(out, h.Name)
	}
	sort.Strings(out)
	return out
}

// HeaderMeta returns the rationale and remediation for a header name.
func HeaderMeta(name string) (why, remediation string, found bool) {
	for _, h := range securityHeaders {
		if strings.EqualFold(h.Name, name) {
			return h.Why, h.Remediation, true
		}
	}
	return "", "", false
}
