package pipeline

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/bbtoolkit/bugbounty/internal/fingerprint"
	httpclient "github.com/bbtoolkit/bugbounty/internal/http"
	"github.com/bbtoolkit/bugbounty/internal/recon"
	"github.com/bbtoolkit/bugbounty/pkg/models"
)

// DefaultStages returns the standard stage set with the modules they need.
//
// The dependencies are interfaces rather than concrete types so a stage can be
// exercised without a network, a resolver or a database. That is not only for
// tests: it is what lets a reviewer confirm the ordering and the passive-only
// guarantees without sending a single packet.
func DefaultStages(deps Dependencies) []Stage {
	return []Stage{
		passiveReconStage(deps),
		dnsStage(deps),
		httpStage(deps),
		fingerprintStage(deps),
		crawlStage(deps),
	}
}

// Dependencies are the modules the stages call. Any of them may be nil, in
// which case the stage that needs it is skipped with a warning rather than
// failing the run.
type Dependencies struct {
	// Recon discovers names passively.
	Recon *recon.Collector
	// DNS collects records for in-scope names.
	DNS DNSCollector
	// HTTP probes URLs.
	HTTP *httpclient.Client
	// Crawl walks a site.
	Crawl Crawler
	// Fingerprint identifies technologies in a response.
	Fingerprint *fingerprint.Set
}

// DNSCollector collects DNS records for a name.
type DNSCollector interface {
	Collect(ctx context.Context, name string, types []models.RecordType) (models.DNSResult, error)
	SecurityPosture(ctx context.Context, zone string) (models.SecurityPosture, error)
}

// Crawler walks a site and returns its endpoints.
type Crawler interface {
	Crawl(ctx context.Context, seed string) ([]models.Endpoint, error)
}

// --- passive recon -----------------------------------------------------------

func passiveReconStage(deps Dependencies) Stage {
	return Stage{
		Name:   StagePassiveRecon,
		Active: false,
		Run: func(ctx context.Context, in Input) (Observation, error) {
			var out Observation
			if deps.Recon == nil {
				out.Warnings = append(out.Warnings,
					"stage "+StagePassiveRecon+": no passive sources are configured")
				return out, nil
			}
			if in.Seed == "" {
				return out, fmt.Errorf("no seed domain was given")
			}
			seed := seedDomain(in.Seed)
			if seed == "" {
				return out, fmt.Errorf("%q is not a domain that can be enumerated passively", in.Seed)
			}

			res, err := deps.Recon.Collect(ctx, seed)
			if res != nil {
				out.Assets = res.Assets
				if res.Truncated {
					out.Warnings = append(out.Warnings, fmt.Sprintf(
						"passive recon hit its %d-name cap; results are incomplete", len(res.Assets)))
				}
				if res.Rejected > 0 {
					out.Warnings = append(out.Warnings, fmt.Sprintf(
						"passive recon discarded %d out-of-scope or malformed names", res.Rejected))
				}
				for name, reason := range res.Skipped {
					out.Warnings = append(out.Warnings, fmt.Sprintf("passive source %s was skipped: %s", name, reason))
				}
				for _, e := range res.Errs {
					out.Warnings = append(out.Warnings, "passive recon: "+e.Error())
				}
			}
			return out, err
		},
	}
}

// seedDomain reduces a URL or host to the domain that can be enumerated
// passively.
func seedDomain(in string) string {
	in = strings.TrimSpace(strings.ToLower(in))
	if in == "" {
		return ""
	}
	if u, err := url.Parse(in); err == nil && u.Host != "" {
		in = u.Hostname()
	}
	if i := strings.Index(in, "/"); i >= 0 {
		in = in[:i]
	}
	if i := strings.Index(in, ":"); i >= 0 {
		in = in[:i]
	}
	return strings.TrimSuffix(in, ".")
}

// --- DNS ---------------------------------------------------------------------

func dnsStage(deps Dependencies) Stage {
	return Stage{
		Name:   StageDNS,
		Active: true,
		Run: func(ctx context.Context, in Input) (Observation, error) {
			var out Observation
			if deps.DNS == nil {
				out.Warnings = append(out.Warnings, "stage "+StageDNS+": no resolver is configured")
				return out, nil
			}
			// Names discovered passively are included, because a subdomain
			// nobody has resolved is the cheapest way to miss an entire
			// subsystem. Every one of them is scope-checked by the collector.
			names := in.Observed.dnsNames()
			if in.Seed != "" {
				names = append([]string{seedDomain(in.Seed)}, names...)
			}

			for _, name := range names {
				if err := ctx.Err(); err != nil {
					return out, err
				}
				// An in-scope zone's own mail configuration is what the
				// posture rules read, and it is only meaningful for the apex.
				if name == seedDomain(in.Seed) {
					if p, err := deps.DNS.SecurityPosture(ctx, name); err != nil {
						out.Warnings = append(out.Warnings, fmt.Sprintf("dns posture for %s: %v", name, err))
					} else {
						out.Posture = append(out.Posture, p)
					}
				}
				res, err := deps.DNS.Collect(ctx, name, models.AllRecordTypes)
				if err != nil {
					out.Warnings = append(out.Warnings, fmt.Sprintf("dns %s: %v", name, err))
					continue
				}
				out.DNS = append(out.DNS, res)
			}
			return out, nil
		},
	}
}

// --- HTTP --------------------------------------------------------------------

// ProbeURLs is the set of URLs the HTTP and fingerprint stages work from.
func (o *Observation) ProbeURLs(limit int) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(raw string) {
		if raw == "" || limit > 0 && len(out) >= limit {
			return
		}
		if _, dup := seen[raw]; dup {
			return
		}
		seen[raw] = struct{}{}
		out = append(out, raw)
	}
	for _, s := range o.HTTP {
		add(s.URL)
	}
	for _, e := range o.Endpoints {
		add(e.URL)
	}
	for _, a := range o.Assets {
		add("https://" + a.Name)
	}
	return out
}

// dnsNames returns the distinct names worth resolving.
func (o *Observation) dnsNames() []string {
	seen := map[string]struct{}{}
	var out []string
	for _, a := range o.Assets {
		if a.Name != "" {
			if _, dup := seen[a.Name]; !dup {
				seen[a.Name] = struct{}{}
				out = append(out, a.Name)
			}
		}
	}
	return out
}

func httpStage(deps Dependencies) Stage {
	return Stage{
		Name:   StageHTTP,
		Active: true,
		Run: func(ctx context.Context, in Input) (Observation, error) {
			var out Observation
			if deps.HTTP == nil {
				out.Warnings = append(out.Warnings, "stage "+StageHTTP+": no HTTP client is configured")
				return out, nil
			}

			urls := in.Observed.ProbeURLs(probeLimit)
			if in.Seed != "" {
				urls = append([]string{normalizeSeedURL(in.Seed)}, urls...)
			}
			for _, raw := range urls {
				if err := ctx.Err(); err != nil {
					return out, err
				}
				resp, err := deps.HTTP.Do(ctx, httpclient.Request{URL: raw, Method: "GET", TruncateBody: true})
				if err != nil {
					// A refused request is a normal outcome in scope testing:
					// the host may be down, may refuse the port, or may be
					// outside the rules for this URL. It is a note, not a
					// stage failure.
					out.Warnings = append(out.Warnings, fmt.Sprintf("probe %s: %v", raw, err))
					continue
				}
				out.HTTP = append(out.HTTP, toHTTPSvc(resp, in.Now))
			}
			return out, nil
		},
	}
}

// probeLimit bounds how many URLs one run probes directly. Crawling covers the
// rest; a run that probed every discovered URL would not be a recon tool.
const probeLimit = 50

// normalizeSeedURL turns a bare domain into a URL the client will accept.
func normalizeSeedURL(seed string) string {
	if seed == "" {
		return ""
	}
	if strings.Contains(seed, "://") {
		return seed
	}
	return "https://" + seed
}

func toHTTPSvc(r *httpclient.Response, now time.Time) models.HTTPSvc {
	svc := models.HTTPSvc{
		URL:           r.URL,
		FinalURL:      r.FinalURL,
		Method:        r.Method,
		StatusCode:    r.StatusCode,
		Title:         r.Title,
		ContentType:   r.ContentType,
		ContentLength: r.ContentLength,
		BodyHash:      r.BodyHash,
		HeaderHash:    r.HeaderHash,
		IPs:           r.IPs,
		Observed:      r.Timestamp,
	}
	if svc.Observed.IsZero() {
		svc.Observed = now
	}
	if len(r.Header) > 0 {
		if v := firstHeader(r.Header, "Server"); v != "" {
			svc.Server = v
		}
		if v := firstHeader(r.Header, "X-Powered-By"); v != "" {
			svc.WebServer = v
		}
		if v := firstHeader(r.Header, "Content-Security-Policy"); v != "" {
			svc.CSP = v
		}
	}
	if r.TLS != nil {
		svc.TLS = &models.TLSInfo{
			Version:            r.TLS.Version,
			CipherSuite:        r.TLS.CipherSuite,
			Subject:            r.TLS.Subject,
			Issuer:             r.TLS.Issuer,
			SerialNumber:       r.TLS.Serial,
			NotBefore:          r.TLS.NotBefore,
			NotAfter:           r.TLS.NotAfter,
			Expired:            r.TLS.Expired,
			SelfSigned:         r.TLS.SelfSigned,
			SANs:               r.TLS.SANs,
			WildcardSANPresent: r.TLS.WildcardSAN,
			NegotiatedProtocol: r.TLS.ALPN,
			Fingerprint:        r.TLS.Fingerprint,
		}
	}
	return svc
}

func firstHeader(h map[string][]string, name string) string {
	for k, v := range h {
		if strings.EqualFold(k, name) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

// --- fingerprint -------------------------------------------------------------

func fingerprintStage(deps Dependencies) Stage {
	return Stage{
		Name:   StageFingerprint,
		Active: true,
		Run: func(ctx context.Context, in Input) (Observation, error) {
			var out Observation
			if deps.Fingerprint == nil {
				out.Warnings = append(out.Warnings, "stage "+StageFingerprint+": no signature set is loaded")
				return out, nil
			}
			for _, svc := range in.Observed.HTTP {
				if err := ctx.Err(); err != nil {
					return out, err
				}
				hits := deps.Fingerprint.Match(fingerprint.Input{
					URL:         svc.URL,
					ContentType: svc.ContentType,
					Title:       svc.Title,
					Server:      svc.Server,
				})
				out.Tech = append(out.Tech, hits...)
			}
			return out, nil
		},
	}
}

// --- crawl -------------------------------------------------------------------

func crawlStage(deps Dependencies) Stage {
	return Stage{
		Name:   StageCrawl,
		Active: true,
		Run: func(ctx context.Context, in Input) (Observation, error) {
			var out Observation
			if deps.Crawl == nil {
				out.Warnings = append(out.Warnings, "stage "+StageCrawl+": no crawler is configured")
				return out, nil
			}
			seed := normalizeSeedURL(in.Seed)
			if seed == "" {
				return out, fmt.Errorf("no seed URL to crawl")
			}
			eps, err := deps.Crawl.Crawl(ctx, seed)
			out.Endpoints = eps
			if err != nil {
				return out, err
			}
			if len(eps) == 0 {
				out.Warnings = append(out.Warnings,
					"crawling found no endpoints; the surface rules could not run")
			}
			return out, nil
		},
	}
}
