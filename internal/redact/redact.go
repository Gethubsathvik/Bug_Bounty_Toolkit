// Package redact provides the single, central secret-redaction implementation
// used by logging, storage, and reporting.
//
// Design rules:
//
//   - Deny by default for known-sensitive header and query-parameter names.
//   - Pattern matching for well-known credential formats (JWT, AWS, GCP,
//     GitHub, Slack, PEM blocks, bearer tokens, key=value secrets).
//   - Control characters are always stripped so that hostile remote content
//     cannot forge log records (log injection).
//   - Redaction is deterministic and allocation-light enough for hot paths.
package redact

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Placeholder is what every redacted value is replaced with. It is a constant
// so that downstream consumers can never accidentally match on a secret.
const Placeholder = "[REDACTED]"

// Header names whose values are never safe to log or persist.
var sensitiveHeaders = map[string]struct{}{
	"authorization":             {},
	"proxy-authorization":       {},
	"cookie":                    {},
	"set-cookie":                {},
	"x-api-key":                 {},
	"api-key":                   {},
	"apikey":                    {},
	"x-auth-token":              {},
	"x-access-token":            {},
	"x-csrf-token":              {},
	"x-xsrf-token":              {},
	"x-session-token":           {},
	"x-amz-security-token":      {},
	"x-goog-api-key":            {},
	"x-forwarded-authorization": {},
	"authentication":            {},
	"proxy-authenticate":        {},
	"x-api-secret":              {},
	"secret":                    {},
	"x-client-secret":           {},
	"x-refresh-token":           {},
}

// sensitiveKeys are query/form parameter names whose values are treated as
// secrets. Matching is done on a normalized name (lowercased, -/_ removed).
var sensitiveKeys = map[string]struct{}{
	"password": {}, "passwd": {}, "pwd": {}, "pass": {},
	"secret": {}, "clientsecret": {}, "token": {}, "accesstoken": {},
	"refreshtoken": {}, "idtoken": {}, "authtoken": {}, "apikey": {},
	"apisecret": {}, "key": {}, "session": {}, "sessionid": {}, "jsessionid": {},
	"jwt": {}, "bearer": {}, "signature": {}, "sig": {}, "hmac": {},
	"credential": {}, "credentials": {}, "auth": {}, "authorization": {},
	"privatekey": {}, "accesskey": {}, "secretaccesskey": {}, "xapikey": {},
	"otp": {}, "code": {}, "sso": {}, "samlresponse": {},
}

// IsSensitiveKey reports whether a header or parameter name is sensitive.
// The name is normalized first, so "X-API-Key", "x_api_key", "XApiKey" and
// "Authorization-Token" are all recognized.
func IsSensitiveKey(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if _, ok := sensitiveHeaders[n]; ok {
		return true
	}
	if _, ok := normalizedKeys[normalizeKey(n)]; ok {
		return true
	}
	return false
}

func normalizeKey(k string) string {
	k = strings.ToLower(k)
	k = strings.ReplaceAll(k, "-", "")
	k = strings.ReplaceAll(k, "_", "")
	k = strings.ReplaceAll(k, ".", "")
	return k
}

var (
	// Bearer / Basic authorization values anywhere in free text.
	reBearer = regexp.MustCompile(`(?i)\b(bearer|basic|token)\s+([A-Za-z0-9._~+/=-]{8,})`)
	// key = "value" / key: value pairs for sensitive names.
	reKVSecret    = regexp.MustCompile(`(?i)\b([a-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|private[_-]?key|auth[_-]?key|signature|credential|session|sessid|sess|sid|phpsessid|jsessionid|connect\.sid|jwt|bearer|cookie|passphrase)[a-z0-9_.-]*)\s*([=:])\s*(?:"([^"\n]{3,})"|'([^'\n]{3,})'|([^\s,;&"']{3,}))`)
	reJWT         = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\b`)
	reAWSKey      = regexp.MustCompile(`\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b`)
	reGCPKey      = regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)
	reGHToken     = regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b`)
	reSlack       = regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)
	rePEM         = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)
	reBasicB64    = regexp.MustCompile(`(?i)\bbasic\s+[A-Za-z0-9+/]{16,}={0,2}`)
	reURLUserinfo = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*)://([^/\s:@]+):([^/\s@]+)@`)
	// Control characters used for log forging and terminal escape injection.
	reControl = regexp.MustCompile(`[\x00-\x1f\x7f]`)
	reSpace   = regexp.MustCompile(`[ \t]+`)
)

// normalizedKeys is the separator-stripped, lowercased form of every known
// sensitive name. Matching against it means Authorization-Token,
// authorization_token and AUTHORIZATIONTOKEN are all recognized, which a plain
// lowercase comparison would miss.
var normalizedKeys = func() map[string]struct{} {
	out := make(map[string]struct{}, len(sensitiveHeaders)+len(sensitiveKeys))
	for k := range sensitiveHeaders {
		out[normalizeKey(k)] = struct{}{}
	}
	for k := range sensitiveKeys {
		out[normalizeKey(k)] = struct{}{}
	}
	// Compound names that only appear when two concepts are joined.
	for _, k := range []string{
		"authorizationtoken", "authtoken", "proxyauthorization",
		"sessiontoken", "sessionid", "jsessionid", "csrftoken", "xsrftoken",
		"xsecuritytoken", "xamzsecuritytoken", "xgoogapikey", "xapikey",
		"refreshtoken", "accesstoken", "idtoken", "clientsecret", "apikey",
		"xapikeyheader", "securitytoken", "bearertoken", "jwttoken",
		"xauthtoken", "xcsrftoken", "xxsrftoken", "xauthtoken2",
	} {
		out[k] = struct{}{}
	}
	return out
}()

// Sanitize removes control characters and replaces newlines with a visible
// escape, so that hostile remote content cannot forge additional log records
// (log injection) or smuggle ANSI escape sequences into a terminal.
func Sanitize(s string) string {
	if s == "" {
		return s
	}
	s = strings.ReplaceAll(s, "\r\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\n`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = reControl.ReplaceAllString(s, "")
	if len(s) > 4096 {
		s = s[:4096] + "...[truncated]"
	}
	return s
}

// SanitizeMultiline is an alias of Sanitize. Both a single log line and a
// multi-line evidence blob end up with newlines rendered inert, so there is
// only one sanitizing path to audit.
func SanitizeMultiline(s string) string { return Sanitize(s) }

// Text redacts well-known credential formats found in free-form text, then
// sanitizes the result so the return value is always safe to log.
func Text(s string) string {
	if s == "" {
		return s
	}
	s = rePEM.ReplaceAllString(s, "-----BEGIN PRIVATE KEY----- "+Placeholder)
	s = reURLUserinfo.ReplaceAllString(s, "$1://$2:"+Placeholder+"@")
	s = reBearer.ReplaceAllString(s, "$1 "+Placeholder)
	s = reBasicB64.ReplaceAllString(s, "Basic "+Placeholder)
	s = reJWT.ReplaceAllString(s, Placeholder)
	s = reAWSKey.ReplaceAllString(s, Placeholder)
	s = reGCPKey.ReplaceAllString(s, Placeholder)
	s = reGHToken.ReplaceAllString(s, Placeholder)
	s = reSlack.ReplaceAllString(s, Placeholder)
	s = reKVSecret.ReplaceAllStringFunc(s, func(m string) string {
		g := reKVSecret.FindStringSubmatch(m)
		if len(g) < 6 {
			return Placeholder
		}
		for i := 3; i <= 5; i++ {
			if g[i] != "" {
				return g[1] + g[2] + Placeholder
			}
		}
		return Placeholder
	})
	return Sanitize(s)
}

// Header redacts a header value by name.
func Header(name, value string) string {
	if IsSensitiveKey(name) {
		return Placeholder
	}
	return Sanitize(Text(value))
}

// Headers returns a redacted, lowercased copy of a header map. The original is
// never mutated.
func Headers(in map[string][]string) map[string][]string {
	if in == nil {
		return nil
	}
	out := make(map[string][]string, len(in))
	for k, vs := range in {
		lk := strings.ToLower(k)
		if IsSensitiveKey(lk) {
			out[lk] = []string{Placeholder}
			continue
		}
		cp := make([]string, 0, len(vs))
		for _, v := range vs {
			cp = append(cp, Sanitize(Text(v)))
		}
		out[lk] = cp
	}
	return out
}

// URL redacts sensitive query-parameter values in a URL. The URL is parsed, not
// string-matched, so an unparseable input is returned sanitized but unaltered
// apart from control-character removal.
func URL(raw string) string {
	if raw == "" {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return Sanitize(Text(raw))
	}
	q := u.Query()
	changed := false
	for k := range q {
		if IsSensitiveKey(k) {
			q.Set(k, Placeholder)
			changed = true
		}
	}
	if u.User != nil {
		u.User = url.UserPassword(u.User.Username(), Placeholder)
		changed = true
	}
	if !changed {
		return Sanitize(Text(u.String()))
	}
	u.RawQuery = q.Encode()
	return Sanitize(Text(u.String()))
}

// URLValues redacts a url.Values map in place on a copy.
func URLValues(v url.Values) url.Values {
	if v == nil {
		return nil
	}
	out := make(url.Values, len(v))
	for k, vals := range v {
		if IsSensitiveKey(k) {
			out[k] = []string{Placeholder}
			continue
		}
		cp := make([]string, 0, len(vals))
		for _, val := range vals {
			cp = append(cp, Sanitize(Text(val)))
		}
		out[k] = cp
	}
	return out
}

// Map redacts a string map by key, falling back to pattern redaction.
func Map(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		if IsSensitiveKey(k) {
			out[k] = Placeholder
			continue
		}
		out[k] = Sanitize(Text(v))
	}
	return out
}

// StringSlice redacts each element of a slice.
func StringSlice(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, Sanitize(Text(s)))
	}
	return out
}

// Scrub removes any value that looks like a secret from an arbitrary string map
// and returns a flag indicating whether redaction occurred. Used by evidence
// ingestion so the caller can record that the evidence was scrubbed.
func Scrub(in map[string]string) (map[string]string, bool) {
	out := Map(in)
	for k := range in {
		if out[k] != in[k] {
			return out, true
		}
	}
	return out, false
}

// SensitiveKeyList returns the sorted set of sensitive key names. Exposed for
// documentation/tests and for the `bugbounty config redaction` command.
func SensitiveKeyList() []string {
	seen := map[string]struct{}{}
	for k := range sensitiveKeys {
		seen[k] = struct{}{}
	}
	for k := range sensitiveHeaders {
		seen[k] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var _ = reSpace
