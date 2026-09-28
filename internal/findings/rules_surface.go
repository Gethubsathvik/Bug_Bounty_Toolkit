package findings

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/bbtoolkit/bugbounty/pkg/models"
)

// httpSurfaceRules reports on things discovered by crawling rather than on
// response headers.
//
// Both rules here are candidates for manual confirmation, never
// vulnerabilities on their own. A URL containing "admin" may be a real
// administration panel, a documentation page, or a login form; claiming
// otherwise without a human looking is the fastest way to lose a client's
// trust in a report.
func httpSurfaceRules() []Rule {
	return []Rule{
		{
			ID:          RuleAdminSurface,
			Title:       "An administrative surface is reachable",
			Severity:    models.SeverityInformational,
			Confidence:  models.ConfidenceLow,
			Tags:        []string{"surface"},
			Description: "Crawling found a path that looks like an administrative or account interface. This is inventory, not a defect: it tells the reviewer where to start looking.",
			Impact:      "If the surface is not meant to be reachable, it is a direct route to credentials and data that the rest of the application's defences were not designed to protect.",
			Remediation: "Restrict administrative interfaces to a management network or VPN, and require single sign-on with MFA.",
			References:  []string{"https://owasp.org/www-project-application-security-verification-standard/"},
			ManualVerification: []string{
				"Open the path and confirm whether it is an administrative interface.",
				"Check whether it requires authentication before any testing beyond a single unauthenticated request.",
				"Compare against the client's own asset inventory; an unknown administrative interface is a finding in itself.",
			},
			ManualVerificationRequired: true,
			Check: func(_ context.Context, in Input) []Result {
				var out []Result
				seen := map[string]struct{}{}
				for _, ep := range in.Endpoints {
					host, path, ok := splitAdminPath(ep.URL)
					if !ok {
						continue
					}
					key := host + path
					if _, dup := seen[key]; dup {
						continue
					}
					seen[key] = struct{}{}
					out = append(out, Result{
						Asset:    host,
						Endpoint: ep.URL,
						Summary:  fmt.Sprintf("%s exposes a path that looks administrative: %s", host, path),
						Data: map[string]string{
							"url":        ep.URL,
							"status":     fmt.Sprintf("%d", ep.StatusCode),
							"discovered": string(ep.Kind),
							"depth":      fmt.Sprintf("%d", ep.Depth),
						},
					})
				}
				// A deterministic order keeps report diffs meaningful.
				sort.SliceStable(out, func(i, j int) bool { return out[i].Endpoint < out[j].Endpoint })
				return out
			},
		},
		{
			ID:          RuleOpenRedirectCandidate,
			Title:       "A parameter on this endpoint may control a redirect target",
			Severity:    models.SeverityLow,
			Confidence:  models.ConfidenceLow,
			Tags:        []string{"surface", "redirect"},
			Description: "An endpoint accepts a parameter whose name is conventionally used to carry a redirect target. The toolkit does not test it; the parameter is simply a candidate for a human to check.",
			Impact:      "An unvalidated redirect target is routinely abused for phishing, because the link a victim clicks still begins with the trusted domain.",
			Remediation: "Where a redirect parameter is unavoidable, restrict targets to a fixed allowlist and never accept a full URL from the client.",
			References:  []string{"https://owasp.org/www-project-cheat-sheets/"},
			ManualVerification: []string{
				"Request the endpoint with a single harmless off-site redirect value and see whether the server reflects it.",
				"Stop after confirming reflection; do not build a phishing flow.",
			},
			ManualVerificationRequired: true,
			Check: func(_ context.Context, in Input) []Result {
				var out []Result
				seen := map[string]struct{}{}
				for _, ep := range in.Endpoints {
					for _, p := range ep.Parameters {
						if !redirectParameter(p.Name) {
							continue
						}
						key := ep.URL + "|" + strings.ToLower(p.Name)
						if _, dup := seen[key]; dup {
							continue
						}
						seen[key] = struct{}{}
						out = append(out, Result{
							Endpoint: ep.URL,
							Summary:  fmt.Sprintf("%s accepts parameter %q on %s", hostOf(ep.URL), p.Name, ep.URL),
							Data: map[string]string{
								"url":        ep.URL,
								"parameter":  p.Name,
								"kind":       string(p.Kind),
								"discovered": string(ep.Kind),
							},
						})
					}
				}
				sort.SliceStable(out, func(i, j int) bool { return out[i].Endpoint < out[j].Endpoint })
				return out
			},
		},
	}
}

// adminPathMarkers are path fragments that conventionally indicate an
// administrative or account interface.
var adminPathMarkers = []string{
	"/admin", "/administrator", "/manage", "/manager", "/console", "/panel",
	"/dashboard", "/wp-admin", "/phpmyadmin", "/cpanel", "/_admin", "/cms",
	"/backoffice", "/back-office", "/internal", "/actuator", "/api/admin",
	"/login", "/signin", "/sign-in", "/auth", "/account", "/password",
	"/reset-password", "/forgot", "/register", "/signup", "/user/profile",
}

// splitAdminPath reports whether a URL looks administrative, returning the
// host and the matched marker.
func splitAdminPath(raw string) (host, marker string, ok bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", "", false
	}
	host = u.Hostname()
	p := strings.ToLower(u.Path)
	for _, m := range adminPathMarkers {
		if matchesPathMarker(p, m) {
			return host, m, true
		}
	}
	return "", "", false
}

// matchesPathMarker reports whether a path contains a marker as a whole path
// segment, so "/administration" is not mistaken for "/admin" and "/login-page"
// is not treated as a login form.
func matchesPathMarker(path, marker string) bool {
	idx := 0
	for {
		i := strings.Index(path[idx:], marker)
		if i < 0 {
			return false
		}
		start := idx + i
		end := start + len(marker)
		beforeOK := start == 0 || path[start-1] == '/'
		afterOK := end == len(path) || path[end] == '/' || path[end] == '.'
		if beforeOK && afterOK {
			return true
		}
		idx = start + 1
		if idx >= len(path) {
			return false
		}
	}
}

// redirectParameter reports whether a parameter name conventionally carries a
// redirect target.
func redirectParameter(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	switch n {
	case "redirect", "redirect_uri", "redirect_url", "return", "return_url",
		"returnto", "return_to", "next", "url", "target", "dest", "destination",
		"continue", "goto", "rurl", "checkout_url", "success_url", "callback_url":
		return true
	default:
		return false
	}
}
