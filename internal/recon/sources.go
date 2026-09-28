package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/bbtoolkit/bugbounty/internal/redact"
	"github.com/bbtoolkit/bugbounty/pkg/models"
)

// Passive sources talk to third-party aggregators, never to the target. They
// therefore do not go through the scope engine's client: the scope engine
// governs what the toolkit may touch on the client's infrastructure, and
// refusing to reach crt.sh because crt.sh is out of scope would defeat the
// point. What they may send is one seed domain and nothing else.
const (
	// defaultPassiveResponseBytes bounds a passive API response. A public
	// endpoint that streams without limit is a memory exhaustion vector, and
	// these responses are not trusted input.
	defaultPassiveResponseBytes = 32 << 20
	// defaultPassiveTimeout bounds one passive request. A slow aggregator must
	// not hold up a run that has other sources.
	defaultPassiveTimeout = 30 * time.Second
	// maxUserAgent is irrelevant beyond honesty, but an honest User-Agent
	// matters for a tool that consumes other people's free quotas.
	defaultUserAgent = "bugbounty-toolkit/1.0 (+passive-recon)"
)

// HTTPFetcher is the subset of HTTP behaviour a passive source needs. It is an
// interface so tests can drive a source without network access.
type HTTPFetcher interface {
	Do(ctx context.Context, req *http.Request) (*http.Response, error)
}

// PassiveFetcher is a bounded HTTP client for third-party APIs.
type PassiveFetcher struct {
	client  *http.Client
	MaxBody int64
}

// NewPassiveFetcher returns a fetcher with conservative limits.
func NewPassiveFetcher() *PassiveFetcher {
	return &PassiveFetcher{
		client: &http.Client{
			Timeout: defaultPassiveTimeout,
			// A passive aggregator should never redirect us, and following a
			// redirect would let the destination see the request that led to
			// it. Refusing is the conservative choice.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		MaxBody: defaultPassiveResponseBytes,
	}
}

// Do performs one bounded request.
func (p *PassiveFetcher) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	if p.MaxBody <= 0 {
		p.MaxBody = defaultPassiveResponseBytes
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		resp.Body = http.MaxBytesReader(nil, resp.Body, p.MaxBody)
	}
	return resp, nil
}

// readBounded reads a response body up to the configured limit.
func readBounded(r io.Reader, max int64) ([]byte, error) {
	if max <= 0 {
		max = defaultPassiveResponseBytes
	}
	return io.ReadAll(io.LimitReader(r, max+1))
}

// --- certificate transparency ------------------------------------------------

// CrtShSource enumerates names from crt.sh, a public certificate transparency
// aggregator. It needs no credential and touches nothing in the engagement.
type CrtShSource struct {
	// BaseURL is the query endpoint, overrideable for a mirror or a test.
	BaseURL string
	// Fetcher performs the request.
	Fetcher HTTPFetcher
	// MaxRows bounds how many certificate rows are parsed.
	MaxRows int
	// Clock supplies the observation time.
	Clock func() time.Time
}

// NewCrtShSource returns a source pointed at the public crt.sh endpoint.
func NewCrtShSource() *CrtShSource {
	return &CrtShSource{
		BaseURL: "https://crt.sh/",
		Fetcher: NewPassiveFetcher(),
		MaxRows: MaxNamesPerSeedSource,
		Clock:   time.Now,
	}
}

func (s *CrtShSource) Name() string { return "crt.sh" }

func (s *CrtShSource) Available() error {
	if s.Fetcher == nil {
		return fmt.Errorf("recon: %s has no fetcher", s.Name())
	}
	return nil
}

func (s *CrtShSource) clock() time.Time {
	if s.Clock != nil {
		return s.Clock()
	}
	return time.Now()
}

// crtEntry is one row of crt.sh's JSON output. Only the fields that matter for
// name discovery are declared; the rest are ignored rather than trusted.
type crtEntry struct {
	CommonName     string `json:"common_name"`
	NameValue      string `json:"name_value"`
	IssuerName     string `json:"issuer_name"`
	NotBefore      string `json:"not_before"`
	EntryTimestamp string `json:"entry_timestamp"`
	Id             int64  `json:"id"`
}

func (s *CrtShSource) Enumerate(ctx context.Context, seed string) ([]Record, error) {
	base := s.BaseURL
	if base == "" {
		base = "https://crt.sh/"
	}
	q := url.Values{}
	q.Set("q", "%."+seed)
	q.Set("output", "json")

	endpoint := base
	if strings.Contains(endpoint, "?") {
		endpoint += "&" + q.Encode()
	} else {
		endpoint += "?" + q.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", defaultUserAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := s.Fetcher.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned %s", resp.Status)
	}
	body, err := readBounded(resp.Body, defaultPassiveResponseBytes)
	if err != nil {
		return nil, err
	}
	var entries []crtEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		// A truncated or error-page body is not a finding. Report the decode
		// failure rather than returning nothing, or the operator reads a
		// silent miss as "no subdomains exist".
		return nil, fmt.Errorf("decoding crt.sh response: %w", err)
	}

	max := s.MaxRows
	if max <= 0 || max > len(entries) {
		max = len(entries)
	}
	now := s.clock()
	out := make([]Record, 0, max)
	for _, e := range entries[:max] {
		for _, name := range splitCTName(e.NameValue) {
			// A name appearing in a certificate says the name was requested
			// at issuance time. It does not prove the name is live now, so
			// the confidence is medium and never high.
			out = append(out, Record{
				Name:       name,
				Kind:       KindSubdomain,
				Confidence: models.ConfidenceMedium,
				Data: map[string]string{
					"certificate_id": strconv.FormatInt(e.Id, 10),
					"issuer":         redact.Text(truncate(e.IssuerName, 120)),
					"common_name":    redact.Text(truncate(e.CommonName, 120)),
				},
				Observed: parseCTTime(e.EntryTimestamp, e.NotBefore, now),
			})
		}
	}
	return out, nil
}

// splitCTName breaks a certificate's name_value, which is a newline-separated
// list that may include wildcards, and drops the entries that cannot be names.
func splitCTName(v string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(v, func(r rune) bool { return r == '\n' || r == '\r' || r == ' ' || r == ',' }) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "@") {
			out = append(out, part)
			continue
		}
		out = append(out, strings.TrimPrefix(part, "*."))
	}
	return out
}

func parseCTTime(entryTS, notBefore string, fallback time.Time) time.Time {
	for _, candidate := range []string{entryTS, notBefore} {
		if candidate == "" {
			continue
		}
		for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05"} {
			if t, err := time.Parse(layout, candidate); err == nil {
				return t.UTC()
			}
		}
	}
	return fallback
}

// --- credential-backed providers --------------------------------------------

// Provider is a passive aggregator that needs an API credential.
type Provider struct {
	// ID names the provider in findings and reports.
	ID string
	// Endpoint is the URL template; %s is replaced with the escaped seed.
	Endpoint string
	// KeyEnv is the environment variable holding the credential. The value
	// itself is never read from configuration.
	KeyEnv string
	// QueryParams are added to every request.
	QueryParams map[string]string
	// Parse extracts records from a response body. It is a field so a
	// provider can be added without touching the request path.
	Parse func(body []byte, observed time.Time) ([]Record, error)
	// Fetcher performs the request.
	Fetcher HTTPFetcher
	// Clock supplies the observation time.
	Clock func() time.Time
	// Secret resolves the credential. It returns false when none is set.
	Secret func() (string, bool)
}

func (p *Provider) Name() string { return p.ID }

func (p *Provider) Available() error {
	if p.Parse == nil {
		return fmt.Errorf("recon: provider %s has no parser", p.ID)
	}
	if p.Fetcher == nil {
		return fmt.Errorf("recon: provider %s has no fetcher", p.ID)
	}
	if p.Endpoint == "" {
		return fmt.Errorf("recon: provider %s has no endpoint", p.ID)
	}
	return nil
}

func (p *Provider) clock() time.Time {
	if p.Clock != nil {
		return p.Clock()
	}
	return time.Now()
}

func (p *Provider) Enumerate(ctx context.Context, seed string) ([]Record, error) {
	if p.Secret == nil {
		return nil, fmt.Errorf("recon: provider %s cannot resolve a credential", p.ID)
	}
	key, ok := p.Secret()
	if !ok || key == "" {
		return nil, fmt.Errorf("recon: provider %s has no credential configured", p.ID)
	}

	endpoint, err := p.endpointFor(seed)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", defaultUserAgent)
	req.Header.Set("Accept", "application/json")
	// The credential travels in a header, never in the URL, so it cannot end
	// up in a proxy log or an error message that quotes the request line.
	req.Header.Set("Authorization", "Bearer "+key)

	resp, err := p.Fetcher.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		// Never echo the response body: providers sometimes reflect the key
		// back in their error payload.
		return nil, fmt.Errorf("provider %s rejected the credential (%s)", p.ID, resp.Status)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("provider %s returned %s", p.ID, resp.Status)
	}
	body, err := readBounded(resp.Body, defaultPassiveResponseBytes)
	if err != nil {
		return nil, err
	}
	return p.Parse(body, p.clock())
}

func (p *Provider) endpointFor(seed string) (string, error) {
	if !strings.Contains(p.Endpoint, "%s") {
		return "", fmt.Errorf("recon: provider %s endpoint has no %%s placeholder for the seed", p.ID)
	}
	u, err := url.Parse(strings.Replace(p.Endpoint, "%s", url.QueryEscape(seed), 1))
	if err != nil {
		return "", fmt.Errorf("recon: provider %s endpoint is not a URL: %w", p.ID, err)
	}
	q := u.Query()
	for k, v := range p.QueryParams {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// --- DNS record source -------------------------------------------------------

// DNSRecordsSource reads names out of TXT records published by the seed's own
// zone, which some organisations use to advertise internal tooling.
//
// It is passive in the sense that matters for authorisation only: it performs
// no request to any application. It still performs a DNS query, so the caller
// decides whether that is appropriate for the engagement.
type DNSRecordsSource struct {
	// Lookup returns the TXT strings for a name. It is injected so the source
	// is testable and so the caller can reuse its existing, scope-checked
	// resolver.
	Lookup func(ctx context.Context, name string) ([]string, error)
	// Prefixes are the record labels to read.
	Prefixes []string
}

// NewDNSRecordsSource returns a source reading the conventional TXT labels.
func NewDNSRecordsSource(lookup func(context.Context, string) ([]string, error)) *DNSRecordsSource {
	return &DNSRecordsSource{
		Lookup:   lookup,
		Prefixes: []string{"_git", "_github-pages-challenge", "_npm", "_registry", "_acme-challenge", "_dmarc"},
	}
}

func (s *DNSRecordsSource) Name() string { return "dns-txt" }

func (s *DNSRecordsSource) Available() error {
	if s.Lookup == nil {
		return fmt.Errorf("recon: dns-txt source has no resolver")
	}
	if len(s.Prefixes) == 0 {
		return fmt.Errorf("recon: dns-txt source has no labels to read")
	}
	return nil
}

func (s *DNSRecordsSource) Enumerate(ctx context.Context, seed string) ([]Record, error) {
	now := time.Now()
	var out []Record
	var firstErr error
	for _, p := range s.Prefixes {
		label := p + "." + seed
		values, err := s.Lookup(ctx, label)
		if err != nil {
			// Keep going. One unresolvable label says nothing about the
			// others, and aborting would discard whatever was found.
			if firstErr == nil {
				firstErr = fmt.Errorf("looking up %s: %w", label, err)
			}
			continue
		}
		for _, v := range values {
			for _, name := range namesFromTXT(v, seed) {
				out = append(out, Record{
					Name:       name,
					Kind:       KindSubdomain,
					Confidence: models.ConfidenceMedium,
					Data: map[string]string{
						"record": label,
					},
					Observed: now,
				})
			}
		}
	}
	return out, firstErr
}

// namesFromTXT pulls host-shaped tokens out of a TXT record. A TXT record is
// free-form text controlled by whoever controls the zone, so only tokens that
// canonicalize into the seed's own domain are kept: a record claiming
// "victim.com" is evidence, a record claiming "attacker.net" is not.
func namesFromTXT(value, seed string) []string {
	var out []string
	for _, field := range strings.FieldsFunc(value, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '\r', ',', '"', '\'', ';', '=', '<', '>':
			return true
		}
		return false
	}) {
		field = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(field), "."))
		if field == "" {
			continue
		}
		// Strip a URL prefix if the record embedded one.
		if i := strings.Index(field, "://"); i >= 0 {
			field = field[i+3:]
		}
		if i := strings.IndexAny(field, "/:"); i > 0 {
			field = field[:i]
		}
		if at := strings.LastIndex(field, "@"); at >= 0 {
			field = field[at+1:]
		}
		if field == seed || strings.HasSuffix(field, "."+seed) {
			if name, _, ok := classify(field, KindSubdomain); ok {
				out = append(out, name)
			}
		}
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
