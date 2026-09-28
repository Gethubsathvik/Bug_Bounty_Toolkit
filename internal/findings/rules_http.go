package findings

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/bbtoolkit/bugbounty/pkg/models"
)

// Rule IDs. These are part of the toolkit's public contract: they appear in
// reports, in SARIF rule metadata and in the operator's suppress list, so a
// retired ID must not be reused for a different meaning.
const (
	RuleMissingHSTS           = "http-missing-hsts"
	RuleMissingCSP            = "http-missing-csp"
	RuleCSPFrameAncestors     = "http-csp-frame-ancestors"
	RuleMissingXFrameOptions  = "http-missing-x-frame-options"
	RuleMissingXContentType   = "http-missing-x-content-type-options"
	RuleCookieNoSecure        = "http-cookie-without-secure"
	RuleCookieNoHTTPOnly      = "http-cookie-without-httponly"
	RuleServerVersionLeak     = "http-server-version-disclosure"
	RuleHTTPSPresent          = "http-no-https"
	RuleOpenRedirectCandidate = "http-open-redirect-candidate"
	RuleAdminSurface          = "http-admin-surface-exposed"

	RuleTLSCertificateExpired = "tls-certificate-expired"
	RuleTLSSelfSigned         = "tls-self-signed-certificate"
	RuleTLSWeakVersion        = "tls-weak-protocol-version"
	RuleTLSWeakCipher         = "tls-weak-cipher-suite"
	RuleTLSHostnameMismatch   = "tls-hostname-mismatch"
	RuleTLSSANOutOfScope      = "tls-san-out-of-scope"

	RuleDNSMissingSPF          = "dns-missing-spf"
	RuleDNSPermissiveSPF       = "dns-permissive-spf"
	RuleDNSMissingDMARC        = "dns-missing-dmarc"
	RuleDNSMissingCAA          = "dns-missing-caa"
	RuleDNSSubdomain           = "dns-subdomain-discovered"
	RuleDNSUnconnectableTarget = "dns-unconnectable-target"

	RuleTechOutdated = "technology-outdated-version"
	RuleTechEOL      = "technology-end-of-life"
)

// DefaultRules returns the standard rule set, in a stable order.
func DefaultRules() []Rule {
	rules := make([]Rule, 0, 24)
	rules = append(rules, httpHeaderRules()...)
	rules = append(rules, httpSurfaceRules()...)
	rules = append(rules, tlsRules()...)
	rules = append(rules, dnsRules()...)
	rules = append(rules, techRules()...)
	return rules
}

// httpServices returns only the records that represent a real HTTP response,
// which is what most HTTP rules need.
func httpServices(in Input) []models.HTTPSvc {
	out := make([]models.HTTPSvc, 0, len(in.HTTP))
	for _, s := range in.HTTP {
		if s.StatusCode == 0 {
			continue
		}
		out = append(out, s)
	}
	return out
}

func isHTTPSURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && strings.EqualFold(u.Scheme, "https")
}

func httpHeaderRules() []Rule {
	return []Rule{
		{
			ID:          RuleMissingHSTS,
			Title:       "Strict-Transport-Security header is absent",
			Severity:    models.SeverityLow,
			Confidence:  models.ConfidenceHigh,
			Tags:        []string{"headers", "transport"},
			Description: "The host serves HTTPS but never tells browsers to keep using it. Without HSTS, a user who visits the host over plain HTTP first can be downgraded before any certificate is checked.",
			Impact:      "An attacker able to intercept the first plaintext request can inject content or capture cookies, and the browser has no standing instruction to refuse a downgrade.",
			Remediation: "Set `Strict-Transport-Security: max-age=31536000; includeSubDomains` once HTTPS is confirmed working everywhere, and consider `preload` only after the whole domain is HTTPS-only.",
			References:  []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security", "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"},
			Check: func(_ context.Context, in Input) []Result {
				var out []Result
				for _, s := range httpServices(in) {
					if !isHTTPSURL(s.URL) {
						continue
					}
					if _, ok := s.Security.Present["strict-transport-security"]; ok {
						continue
					}
					sev := models.SeverityLow
					res := Result{
						Endpoint: s.URL,
						Summary:  fmt.Sprintf("%s serves HTTPS without a Strict-Transport-Security header", hostOf(s.URL)),
						Data: map[string]string{
							"url":          s.URL,
							"status":       fmt.Sprintf("%d", s.StatusCode),
							"weak_headers": fmt.Sprintf("%d", len(s.Security.Weak)),
						},
					}
					// HSTS matters far more on a host that sets session
					// cookies: losing one over a plaintext request is an
					// account takeover, not a hardening nit.
					if len(s.Security.Weak) > 0 {
						sev = models.SeverityMedium
						res.Data["reason"] = "other response headers are also weak on this host"
						res.Confidence = confidencePtr(models.ConfidenceHigh)
					}
					res.Severity = &sev
					out = append(out, res)
				}
				return out
			},
		},
		{
			ID:          RuleMissingCSP,
			Title:       "Content-Security-Policy header is absent",
			Severity:    models.SeverityLow,
			Confidence:  models.ConfidenceHigh,
			Tags:        []string{"headers", "xss"},
			Description: "The response sets no Content-Security-Policy, so the browser applies no restrictions on where scripts, styles and frames may load from. A CSP is defence in depth: it does not prevent an XSS, but it decides whether an injected script can exfiltrate data or load a payload.",
			Impact:      "Any content injection on the host has the browser's full default privileges, including reading and sending data off-origin.",
			Remediation: "Start with a report-only policy that logs violations, then adopt a policy naming the origins the application actually needs. Do not ship `unsafe-inline` or `*` and expect it to constrain anything.",
			References:  []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy", "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"},
			Check: func(_ context.Context, in Input) []Result {
				var out []Result
				for _, s := range httpServices(in) {
					if _, ok := s.Security.Present["content-security-policy"]; ok {
						continue
					}
					ct := strings.ToLower(s.ContentType)
					// A CSP only governs documents. Reporting one missing
					// from a JSON API is noise.
					if ct != "" && !strings.Contains(ct, "html") {
						continue
					}
					out = append(out, Result{
						Endpoint: s.URL,
						Summary:  fmt.Sprintf("%s serves an HTML response without a Content-Security-Policy", hostOf(s.URL)),
						Data: map[string]string{
							"url":          s.URL,
							"content_type": s.ContentType,
						},
					})
				}
				return out
			},
		},
		{
			ID:          RuleCSPFrameAncestors,
			Title:       "Content-Security-Policy does not restrict framing",
			Severity:    models.SeverityInformational,
			Confidence:  models.ConfidenceHigh,
			Tags:        []string{"headers", "clickjacking"},
			Description: "A Content-Security-Policy is present but does not set `frame-ancestors`, and no X-Frame-Options header covers the gap. The policy therefore says nothing about which origins may frame the page.",
			Impact:      "The page can be embedded by another site, which is the precondition for clickjacking.",
			Remediation: "Add `frame-ancestors 'none'` to the policy, or an explicit allowlist of the origins that genuinely need to frame the page.",
			References:  []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors"},
			Check: func(_ context.Context, in Input) []Result {
				var out []Result
				for _, s := range httpServices(in) {
					csp, ok := s.Security.Present["content-security-policy"]
					if !ok {
						continue
					}
					ct := strings.ToLower(s.ContentType)
					if ct != "" && !strings.Contains(ct, "html") {
						continue
					}
					if _, hasXFO := s.Security.Present["x-frame-options"]; hasXFO {
						// The legacy header already restricts framing; the CSP
						// gap is not a gap.
						continue
					}
					if fingerprintHasDirective(csp, "frame-ancestors") {
						continue
					}
					out = append(out, Result{
						Endpoint: s.URL,
						Summary:  fmt.Sprintf("%s sets a Content-Security-Policy without frame-ancestors", hostOf(s.URL)),
						Data: map[string]string{
							"url":                     s.URL,
							"csp":                     csp,
							"csp_has_frame_ancestors": "false",
						},
					})
				}
				return out
			},
		},
		{
			ID:          RuleMissingXFrameOptions,
			Title:       "X-Frame-Options header is absent and no CSP frame-ancestors applies",
			Severity:    models.SeverityInformational,
			Confidence:  models.ConfidenceHigh,
			Tags:        []string{"headers", "clickjacking"},
			Description: "Nothing in the response stops the page being framed by another origin. A modern Content-Security-Policy `frame-ancestors` directive covers this, so this finding is suppressed when one was observed.",
			Impact:      "A framed page can be made to receive clicks intended for the surrounding site, which is how clickjacking credential theft works.",
			Remediation: "Set `Content-Security-Policy: frame-ancestors 'none'` (or an allowlist), or `X-Frame-Options: DENY` where CSP is not yet deployed.",
			References:  []string{"https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"},
			Check: func(_ context.Context, in Input) []Result {
				var out []Result
				for _, s := range httpServices(in) {
					if _, ok := s.Security.Present["x-frame-options"]; ok {
						continue
					}
					// A policy that already names frame-ancestors does the same
					// job with better browser coverage. Reporting the legacy
					// header as missing here would be telling the client to fix
					// something that is not broken.
					if csp, ok := s.Security.Present["content-security-policy"]; ok && fingerprintHasDirective(csp, "frame-ancestors") {
						continue
					}
					out = append(out, Result{
						Endpoint: s.URL,
						Summary:  fmt.Sprintf("%s can be framed by another origin", hostOf(s.URL)),
						Data:     map[string]string{"url": s.URL},
					})
				}
				return out
			},
		},
		{
			ID:          RuleMissingXContentType,
			Title:       "X-Content-Type-Options header is absent",
			Severity:    models.SeverityInformational,
			Confidence:  models.ConfidenceHigh,
			Tags:        []string{"headers"},
			Description: "The response does not set `X-Content-Type-Options: nosniff`, so a browser may second-guess the declared content type.",
			Impact:      "A user-uploaded file served from the same origin can be reinterpreted as script or markup in some browsers.",
			Remediation: "Set `X-Content-Type-Options: nosniff` on every response, and serve user uploads from a separate origin if possible.",
			References:  []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"},
			Check: func(_ context.Context, in Input) []Result {
				var out []Result
				for _, s := range httpServices(in) {
					if _, ok := s.Security.Present["x-content-type-options"]; ok {
						continue
					}
					out = append(out, Result{
						Endpoint: s.URL,
						Summary:  fmt.Sprintf("%s does not set X-Content-Type-Options", hostOf(s.URL)),
						Data:     map[string]string{"url": s.URL},
					})
				}
				return out
			},
		},
		{
			ID:          RuleHTTPSPresent,
			Title:       "Host does not serve HTTPS",
			Severity:    models.SeverityMedium,
			Confidence:  models.ConfidenceHigh,
			Tags:        []string{"transport"},
			Description: "The host answered over plain HTTP. Everything sent to it, including credentials and cookies, is visible and modifiable to anyone on the path.",
			Impact:      "Session material and page content can be captured or altered in transit, and downgrade attacks have no defence.",
			Remediation: "Serve the site over HTTPS and redirect HTTP to HTTPS, then set HSTS once the redirect is reliable.",
			References:  []string{"https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"},
			Check: func(_ context.Context, in Input) []Result {
				var out []Result
				for _, s := range httpServices(in) {
					if isHTTPSURL(s.URL) {
						continue
					}
					sev := models.SeverityMedium
					if strings.EqualFold(hostOf(s.URL), hostOf(in.Asset)) {
						// The whole engagement runs through this host, so the
						// exposure is not one page, it is the assessment.
						sev = models.SeverityHigh
					}
					out = append(out, Result{
						Endpoint: s.URL,
						Severity: &sev,
						Summary:  fmt.Sprintf("%s answered over plain HTTP with status %d", hostOf(s.URL), s.StatusCode),
						Data: map[string]string{
							"url":    s.URL,
							"status": fmt.Sprintf("%d", s.StatusCode),
						},
					})
				}
				return out
			},
		},
		{
			ID:                         RuleServerVersionLeak,
			Title:                      "Server software discloses its exact version",
			Severity:                   models.SeverityInformational,
			Confidence:                 models.ConfidenceHigh,
			Tags:                       []string{"disclosure"},
			Description:                "A `Server` or `X-Powered-By` header names a specific, dated release of server software, which narrows an attacker's search to known issues in that release.",
			Impact:                     "Reduces the work needed to find a matching public exploit; on its own it is not a vulnerability.",
			Remediation:                "Suppress or normalise the identifying headers at the edge, and keep the software patched rather than relying on hiding it.",
			References:                 []string{"https://owasp.org/www-project-secure-headers/"},
			ManualVerification:         []string{"Confirm the header is not added by an intermediate proxy you do not control before filing it."},
			ManualVerificationRequired: true,
			Check: func(_ context.Context, in Input) []Result {
				var out []Result
				for _, s := range httpServices(in) {
					for _, hdr := range []string{"server", "x-powered-by"} {
						v, ok := s.Security.Present[hdr]
						if !ok || !disclosesVersion(v) {
							continue
						}
						out = append(out, Result{
							Endpoint: s.URL,
							Summary:  fmt.Sprintf("%s returns %s: %s", hostOf(s.URL), hdr, v),
							Data:     map[string]string{"url": s.URL, "header": hdr, "value": v},
						})
					}
				}
				return out
			},
		},
		{
			ID:          RuleCookieNoSecure,
			Title:       "Cookie is set without the Secure attribute",
			Severity:    models.SeverityLow,
			Confidence:  models.ConfidenceHigh,
			Tags:        []string{"cookies"},
			Description: "A cookie was issued without `Secure`, so the browser will also send it over plain HTTP.",
			Impact:      "The cookie is exposed to anyone who can observe or downgrade the connection, which is enough to hijack a session.",
			Remediation: "Set `Secure` on every cookie that matters, and serve the site only over HTTPS.",
			References:  []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies"},
			Check:       cookieRule("secure", RuleCookieNoSecure, "without Secure"),
		},
		{
			ID:          RuleCookieNoHTTPOnly,
			Title:       "Cookie is set without the HttpOnly attribute",
			Severity:    models.SeverityLow,
			Confidence:  models.ConfidenceMedium,
			Tags:        []string{"cookies"},
			Description: "A cookie was issued without `HttpOnly`, so client-side script can read it.",
			Impact:      "Any content injection on the origin can read the cookie directly, which upgrades a script-injection bug to a session theft.",
			Remediation: "Set `HttpOnly` on session and authentication cookies. A cookie that genuinely must be read by script is usually better moved to a non-cookie mechanism.",
			References:  []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie"},
			Check:       cookieRule("httponly", RuleCookieNoHTTPOnly, "without HttpOnly"),
		},
	}
}

// cookieRule builds a rule that reports cookies missing one attribute, using
// the notes the header analyser already produced.
func cookieRule(attribute, id, phrase string) func(context.Context, Input) []Result {
	return func(_ context.Context, in Input) []Result {
		var out []Result
		needle := "missing " + attribute
		for _, s := range httpServices(in) {
			for _, note := range s.Security.Notes {
				low := strings.ToLower(note)
				if !strings.Contains(low, "set-cookie") || !strings.Contains(low, needle) {
					continue
				}
				out = append(out, Result{
					Endpoint: s.URL,
					Summary:  fmt.Sprintf("%s sets a cookie %s", hostOf(s.URL), phrase),
					Data: map[string]string{
						"url":     s.URL,
						"note":    note,
						"missing": attribute,
					},
				})
			}
		}
		return out
	}
}

// disclosesVersion reports whether a Server-style header names a release
// rather than a product family. "nginx" alone is not a disclosure; "nginx/1.18.0"
// is.
func disclosesVersion(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" || v == "-" {
		return false
	}
	// A bare product name with no slash and no digit is not a version.
	if !strings.ContainsAny(v, "/0123456789") {
		return false
	}
	// Require an actual number somewhere, not just a slash.
	return strings.ContainsAny(v, "0123456789")
}

// fingerprintHasDirective reports whether a Content-Security-Policy names a
// directive. Directive names are case-insensitive, and quoted string sources
// may contain the word, so a naive substring search would report a policy of
// `script-src 'unsafe-inline'` as covering frames.
func fingerprintHasDirective(csp, directive string) bool {
	d := strings.ToLower(strings.TrimSpace(directive))
	for _, part := range strings.Split(csp, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, _, _ := strings.Cut(part, " ")
		if strings.EqualFold(strings.TrimSpace(name), d) {
			return true
		}
	}
	return false
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return u.Hostname()
}

func confidencePtr(c models.Confidence) *models.Confidence { return &c }

func tlsRules() []Rule {
	return []Rule{
		{
			ID:          RuleTLSCertificateExpired,
			Title:       "TLS certificate has expired",
			Severity:    models.SeverityHigh,
			Confidence:  models.ConfidenceHigh,
			Tags:        []string{"tls"},
			Description: "The certificate presented by the host is outside its validity window, or the handshake was refused because of it.",
			Impact:      "Browsers show a full-page warning that users routinely click through, and any confidentiality guarantee over the connection is void.",
			Remediation: "Renew the certificate and shorten the lifetime so renewal is a routine, automated event rather than an incident.",
			References:  []string{"https://developer.mozilla.org/en-US/docs/Web/Security/Certificate_Transparency"},
			Check: func(_ context.Context, in Input) []Result {
				var out []Result
				for _, s := range httpServices(in) {
					if s.TLS == nil {
						continue
					}
					if !s.TLS.Expired && s.TLS.NotAfter.After(time.Now()) {
						continue
					}
					data := map[string]string{
						"url":       s.URL,
						"not_after": s.TLS.NotAfter.UTC().Format(time.RFC3339),
						"issuer":    s.TLS.Issuer,
					}
					summary := fmt.Sprintf("%s presented a certificate that expired on %s", hostOf(s.URL), s.TLS.NotAfter.UTC().Format("2006-01-02"))
					sev := models.SeverityHigh
					if s.TLS.Expired {
						data["observed_state"] = "handshake reported an expired certificate"
					}
					if pathLooksSensitive(s.URL) {
						sev = models.SeverityCritical
						summary += "; the host serves a path that appears to handle credentials"
						data["path"] = "sensitive"
					}
					out = append(out, Result{
						Endpoint: s.URL,
						Severity: &sev,
						Summary:  summary,
						Data:     data,
					})
				}
				return out
			},
		},
		{
			ID:          RuleTLSSelfSigned,
			Title:       "TLS certificate is self-signed or issued by an unknown authority",
			Severity:    models.SeverityMedium,
			Confidence:  models.ConfidenceMedium,
			Tags:        []string{"tls"},
			Description: "The certificate does not chain to a publicly trusted authority. This is expected on internal or staging hosts and is a real finding on an internet-facing production host.",
			Impact:      "Users cannot distinguish the host from an impersonator, so the connection offers no protection against an active attacker.",
			Remediation: "Issue the certificate from a publicly trusted authority. If the host is internal, confirm that before filing.",
			References:  []string{"https://developer.mozilla.org/en-US/docs/Web/Security/Certificate_Transparency"},
			ManualVerification: []string{
				"Confirm the host is genuinely internet-facing and not a development or staging system.",
				"Confirm no corporate root CA is intentionally trusted by the target's audience.",
			},
			ManualVerificationRequired: true,
			Check: func(_ context.Context, in Input) []Result {
				var out []Result
				for _, s := range httpServices(in) {
					if s.TLS == nil || !s.TLS.SelfSigned {
						continue
					}
					out = append(out, Result{
						Endpoint: s.URL,
						Summary:  fmt.Sprintf("%s presented a self-signed certificate for %q", hostOf(s.URL), s.TLS.Subject),
						Data: map[string]string{
							"url":     s.URL,
							"issuer":  s.TLS.Issuer,
							"subject": s.TLS.Subject,
						},
					})
				}
				return out
			},
		},
		{
			ID:          RuleTLSWeakVersion,
			Title:       "TLS connection uses a deprecated protocol version",
			Severity:    models.SeverityMedium,
			Confidence:  models.ConfidenceHigh,
			Tags:        []string{"tls"},
			Description: "The host negotiated a protocol version that is no longer considered safe, most often TLS 1.0 or TLS 1.1.",
			Impact:      "Older protocol versions have known weaknesses in their record and handshake construction, and many compliance frameworks prohibit them outright.",
			Remediation: "Disable TLS 1.0 and 1.1 and require TLS 1.2 as a minimum, ideally TLS 1.3 where clients allow it.",
			References:  []string{"https://datatracker.ietf.org/doc/html/rfc8996"},
			Check: func(_ context.Context, in Input) []Result {
				var out []Result
				for _, s := range httpServices(in) {
					if s.TLS == nil {
						continue
					}
					if !weakTLSVersion(s.TLS.Version) {
						continue
					}
					out = append(out, Result{
						Endpoint: s.URL,
						Summary:  fmt.Sprintf("%s negotiated %s", hostOf(s.URL), s.TLS.Version),
						Data:     map[string]string{"url": s.URL, "version": s.TLS.Version},
					})
				}
				return out
			},
		},
		{
			ID:          RuleTLSWeakCipher,
			Title:       "TLS connection uses a weak cipher suite",
			Severity:    models.SeverityMedium,
			Confidence:  models.ConfidenceHigh,
			Tags:        []string{"tls"},
			Description: "The negotiated cipher suite is an export, NULL or RC4 grade suite, or one that lacks forward secrecy.",
			Impact:      "Traffic encrypted under these suites can be recovered if the server's static key is ever exposed, and export suites are effectively not encryption at all.",
			Remediation: "Restrict the cipher list to modern AEAD suites, and put `forward secrecy` suites first.",
			References:  []string{"https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml"},
			Check: func(_ context.Context, in Input) []Result {
				var out []Result
				for _, s := range httpServices(in) {
					if s.TLS == nil {
						continue
					}
					if !weakCipher(s.TLS.CipherSuite) {
						continue
					}
					out = append(out, Result{
						Endpoint: s.URL,
						Summary:  fmt.Sprintf("%s negotiated weak cipher %s", hostOf(s.URL), s.TLS.CipherSuite),
						Data:     map[string]string{"url": s.URL, "cipher": s.TLS.CipherSuite},
					})
				}
				return out
			},
		},
		{
			ID:          RuleTLSSANOutOfScope,
			Title:       "Certificate names hosts outside the engagement scope",
			Severity:    models.SeverityInformational,
			Confidence:  models.ConfidenceHigh,
			Tags:        []string{"tls", "scope"},
			Description: "A subject alternative name on the certificate belongs to a different organisation. Shared certificates and acquired domains make this common, and it is a lead rather than a defect.",
			Impact:      "If the named host belongs to another tenant, infrastructure may be shared in ways that expose one to the other.",
			Remediation: "Review the certificate's SAN list and confirm each name is expected for this engagement before pursuing it.",
			References:  []string{"https://crt.sh/"},
			ManualVerification: []string{
				"Confirm the named host is not a third party before requesting any testing against it.",
			},
			ManualVerificationRequired: true,
			Check: func(_ context.Context, in Input) []Result {
				if in.Asset == "" {
					return nil
				}
				assetHost := strings.ToLower(hostOf(in.Asset))
				seen := map[string]struct{}{}
				var out []Result
				for _, s := range httpServices(in) {
					if s.TLS == nil {
						continue
					}
					for _, san := range s.TLS.SANs {
						san = strings.ToLower(strings.TrimSpace(san))
						if san == "" {
							continue
						}
						if _, dup := seen[san]; dup {
							continue
						}
						seen[san] = struct{}{}
						if san == assetHost || strings.HasSuffix(san, "."+assetHost) || isIPLiteral(san) {
							continue
						}
						out = append(out, Result{
							Endpoint: s.URL,
							Summary:  fmt.Sprintf("Certificate for %s also names %s", hostOf(s.URL), san),
							Data:     map[string]string{"url": s.URL, "san": san},
						})
					}
				}
				return out
			},
		},
	}
}

// weakTLSVersion reports whether a negotiated version string is deprecated.
func weakTLSVersion(v string) bool {
	u := strings.ToUpper(strings.TrimSpace(v))
	if u == "" {
		return false
	}
	// SSL 2, SSL 3, TLS 1.0 and TLS 1.1 are all deprecated. Matching on the
	// minor version is deliberate: the string comes from the probe, not from a
	// parsed structure, and Go reports "TLS 1.2" with a space.
	if strings.Contains(u, "SSL") {
		return true
	}
	if !strings.Contains(u, "1.0") && !strings.Contains(u, "1.1") {
		return false
	}
	// Guard against matching "1.10" or a cipher name that happens to contain
	// the digits.
	return strings.Contains(u, "TLS") || strings.Contains(u, "V1")
}

// weakCipher reports whether a named cipher suite should not be accepted on an
// internet-facing host.
func weakCipher(name string) bool {
	u := strings.ToUpper(strings.TrimSpace(name))
	if u == "" {
		// An empty suite name means the probe did not complete a handshake;
		// reporting a weak cipher for that would be a guess.
		return false
	}
	weakSubstrings := []string{
		"NULL", "EXPORT", "RC4", "DES", "3DES", "ANON", "MD5", "IDEA",
	}
	for _, w := range weakSubstrings {
		if strings.Contains(u, w) {
			return true
		}
	}
	return false
}

func isIPLiteral(s string) bool {
	return strings.Contains(s, ":") || strings.Count(s, ".") == 3 && strings.Trim(s, "0123456789.") == ""
}

// pathLooksSensitive reports whether a URL looks like it handles credentials.
// It is a heuristic used only to raise the severity of a TLS problem that is
// already real, never to create one.
func pathLooksSensitive(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	p := strings.ToLower(u.Path)
	for _, needle := range []string{"login", "signin", "sign-in", "auth", "account", "password", "session", "checkout", "payment", "admin"} {
		if strings.Contains(p, needle) {
			return true
		}
	}
	return false
}

// techRules reports outdated or end-of-life technology from fingerprint hits.
//
// Version currency is driven by the caller's baseline rather than by a
// hardcoded table here, because "outdated" depends on when the engagement runs
// and which branch the operator cares about.
func techRules() []Rule {
	return []Rule{
		{
			ID:          RuleTechOutdated,
			Title:       "Identified technology is past its supported window",
			Severity:    models.SeverityLow,
			Confidence:  models.ConfidenceMedium,
			Tags:        []string{"technology", "supply-chain"},
			Description: "A fingerprint identified a specific product version that the configured baseline considers past end of support or carrying known issues.",
			Impact:      "Unmaintained software stops receiving security fixes, and its public issue tracker is the first place an attacker looks.",
			Remediation: "Plan the upgrade, or record a documented and reviewed exception with a compensating control.",
			References:  []string{"https://endoflife.date/"},
			ManualVerification: []string{
				"Confirm the fingerprinted version matches what is actually deployed; banners are frequently spoofed or stale.",
			},
			ManualVerificationRequired: true,
			Check: func(_ context.Context, in Input) []Result {
				baseline := BaselineFromInput(in)
				var out []Result
				for _, hit := range in.Tech {
					if hit.Version == "" {
						continue
					}
					state, ok := baseline.Lookup(hit.Name)
					if !ok || !state.Outdated {
						continue
					}
					sev := models.SeverityLow
					if state.EndOfLife {
						sev = models.SeverityMedium
					}
					out = append(out, Result{
						Endpoint: baseline.assetFor(hit),
						Severity: &sev,
						Tags:     []string{"tech:" + normalizeTechName(hit.Name)},
						Summary:  fmt.Sprintf("%s %s was fingerprinted; the baseline marks it %s", hit.Name, hit.Version, state.Reason),
						Data: map[string]string{
							"technology": hit.Name,
							"version":    hit.Version,
							"reason":     state.Reason,
							"evidence":   hit.Evidence,
						},
					})
				}
				return out
			},
		},
	}
}

// BaselineFromInput returns the technology baseline attached to the input. The
// field lives on Input through a small wrapper so rules stay free of global
// state.
func BaselineFromInput(in Input) *Baseline {
	if in.Baseline == nil {
		return EmptyBaseline()
	}
	return in.Baseline
}
