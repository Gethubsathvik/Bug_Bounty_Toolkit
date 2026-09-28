package recon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bbtoolkit/bugbounty/internal/scope"
	"github.com/bbtoolkit/bugbounty/pkg/models"
)

func testScope(t *testing.T, allowed ...string) *scope.Engine {
	t.Helper()
	sc, err := scope.New(allowed, nil, scope.Policy{})
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	return sc
}

// domainScope allows an apex and its subdomains. The scope engine matches an
// allowlist entry against the apex only unless it is written as a wildcard,
// which is the whole point of the asymmetry: "example.com" authorises the
// bare domain, not everything beneath it.
func domainScope(t *testing.T, domain string) *scope.Engine {
	t.Helper()
	return testScope(t, domain, "*."+domain)
}

var reconNow = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// stubSource returns canned records and an optional error.
type stubSource struct {
	name    string
	records []Record
	err     error
	avail   error
	calls   int
	delay   time.Duration
}

func (s *stubSource) Name() string { return s.name }
func (s *stubSource) Available() error {
	if s.avail != nil {
		return s.avail
	}
	return nil
}
func (s *stubSource) Enumerate(ctx context.Context, seed string) ([]Record, error) {
	s.calls++
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return s.records, s.err
}

// --- construction ------------------------------------------------------------

func TestCollectorRequiresScope(t *testing.T) {
	src := &stubSource{name: "s"}
	if _, err := NewCollector(nil, []Source{src}, Options{}); !errors.Is(err, ErrNoScope) {
		t.Fatalf("a collector with no scope engine was accepted: %v", err)
	}
}

func TestCollectorRequiresAUsableSource(t *testing.T) {
	sc := domainScope(t, "example.com")

	if _, err := NewCollector(sc, nil, Options{}); !errors.Is(err, ErrNoSources) {
		t.Errorf("NewCollector with no sources = %v, want ErrNoSources", err)
	}
	if _, err := NewCollector(sc, []Source{(*stubSource)(nil)}, Options{}); !errors.Is(err, ErrNoSources) {
		t.Errorf("a nil source was not skipped: %v", err)
	}

	unavailable := &stubSource{name: "no-key", avail: errors.New("no credential")}
	if _, err := NewCollector(sc, []Source{unavailable}, Options{}); !errors.Is(err, ErrNoSources) {
		t.Errorf("a source with no credential should be skipped, got %v", err)
	}
	if unavailable.calls != 0 {
		t.Error("an unavailable source was queried anyway")
	}
}

func TestCollectorSkipsANilSourceWithoutPanicking(t *testing.T) {
	// An interface holding a nil pointer is not itself nil, and sources come
	// from plugin and configuration lists. Calling through it must not take
	// the run down.
	sc := domainScope(t, "example.com")
	if _, err := NewCollector(sc, []Source{(*stubSource)(nil)}, Options{}); !errors.Is(err, ErrNoSources) {
		t.Errorf("a nil source was not reported as unusable: %v", err)
	}
}

func TestCollectorSurvivesAPanickingSource(t *testing.T) {
	sc := domainScope(t, "example.com")
	good := &stubSource{name: "good", records: []Record{{Name: "a.example.com"}}}
	bad := &panickingSource{}
	c, err := NewCollector(sc, []Source{good, bad}, Options{Now: reconNow})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Collect(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("a panicking source aborted the run: %v", err)
	}
	if len(res.Assets) != 1 {
		t.Errorf("the healthy source's results were lost: %+v", res.Assets)
	}
	if len(res.Errs) == 0 {
		t.Error("the panic was not reported; a clean result would be a lie")
	}
}

type panickingSource struct{}

func (panickingSource) Name() string     { return "boom" }
func (panickingSource) Available() error { return nil }
func (panickingSource) Enumerate(context.Context, string) ([]Record, error) {
	panic("plugin bug")
}

func TestCollectorSkipsUnavailableSourcesButKeepsTheRest(t *testing.T) {
	sc := domainScope(t, "example.com")
	good := &stubSource{name: "good", records: []Record{{Name: "a.example.com"}}}
	dead := &stubSource{name: "dead", avail: errors.New("no credential")}

	c, err := NewCollector(sc, []Source{good, dead}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Collect(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Assets) != 1 {
		t.Errorf("assets = %+v", res.Assets)
	}
	if good.calls != 1 {
		t.Errorf("the usable source was called %d times", good.calls)
	}
}

// --- collection --------------------------------------------------------------

func TestCollectFiltersToScope(t *testing.T) {
	sc := domainScope(t, "example.com")
	src := &stubSource{name: "s", records: []Record{
		{Name: "www.example.com"},
		{Name: "example.com"},
		{Name: "other-target.net"},
		{Name: "example.com.evil.net"},
		{Name: "notexample.com"},
	}}
	c, _ := NewCollector(sc, []Source{src}, Options{Now: reconNow})

	res, err := c.Collect(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, a := range res.Assets {
		names = append(names, a.Name)
	}
	// "example.com.evil.net" ends with the string "example.com" but is a
	// completely different registrable domain; catching that is the whole
	// point of checking scope on the parsed host.
	for _, n := range names {
		if strings.Contains(n, "evil.net") || n == "other-target.net" || n == "notexample.com" {
			t.Errorf("SECURITY: an out-of-scope name was accepted: %s", n)
		}
	}
	if len(res.Assets) != 2 {
		t.Errorf("names = %v, want only the two in-scope ones", names)
	}
	if res.Rejected != 3 {
		t.Errorf("Rejected = %d, want 3", res.Rejected)
	}
}

func TestCollectSurvivesOneSourceFailing(t *testing.T) {
	sc := domainScope(t, "example.com")
	good := &stubSource{name: "good", records: []Record{{Name: "a.example.com"}}}
	bad := &stubSource{name: "bad", err: errors.New("upstream 503")}

	c, _ := NewCollector(sc, []Source{good, bad}, Options{Now: reconNow})
	res, err := c.Collect(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("one failing source aborted the run: %v", err)
	}
	if len(res.Assets) != 1 {
		t.Errorf("the healthy source's results were lost: %+v", res.Assets)
	}
	if len(res.Errs) != 1 || !strings.Contains(res.Errs[0].Error(), "upstream 503") {
		t.Errorf("errs = %v, want the failure reported", res.Errs)
	}
}

func TestCollectHonoursPerSourceCap(t *testing.T) {
	sc := domainScope(t, "example.com")
	var many []Record
	for i := range 100 {
		many = append(many, Record{Name: fmt.Sprintf("h%03d.example.com", i)})
	}
	src := &stubSource{name: "chatty", records: many}
	c, _ := NewCollector(sc, []Source{src}, Options{MaxPerSource: 10, Now: reconNow})

	res, err := c.Collect(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Assets) != 10 {
		t.Errorf("assets = %d, want the per-source cap of 10", len(res.Assets))
	}
}

func TestCollectBoundsTotalAndFlagsTruncation(t *testing.T) {
	sc := domainScope(t, "example.com")
	var many []Record
	for i := range 50 {
		many = append(many, Record{Name: fmt.Sprintf("h%03d.example.com", i)})
	}
	c, _ := NewCollector(sc, []Source{&stubSource{name: "s", records: many}}, Options{MaxNames: 5, Now: reconNow})

	res, _ := c.Collect(context.Background(), "example.com")
	if len(res.Assets) != 5 {
		t.Errorf("assets = %d, want 5", len(res.Assets))
	}
	if !res.Truncated {
		t.Error("a truncated result was not marked as truncated")
	}
}

func TestCorroborationDoesNotInflateConfidence(t *testing.T) {
	// Ten sources all reading the same wildcard certificate is one weak
	// observation, not ten strong ones.
	sc := domainScope(t, "example.com")
	var sources []Source
	for i := range 10 {
		sources = append(sources, &stubSource{
			name:    fmt.Sprintf("s%d", i),
			records: []Record{{Name: "wild.example.com", Confidence: models.ConfidenceMedium}},
		})
	}
	c, _ := NewCollector(sc, sources, Options{Now: reconNow})
	res, _ := c.Collect(context.Background(), "example.com")

	if len(res.Assets) != 1 {
		t.Fatalf("assets = %+v, want one merged entry", res.Assets)
	}
	if res.Assets[0].Confidence != models.ConfidenceMedium {
		t.Errorf("confidence = %q, want it held at medium", res.Assets[0].Confidence)
	}
	if !strings.Contains(res.Assets[0].Source, "s0") || !strings.Contains(res.Assets[0].Source, "s9") {
		t.Errorf("provenance = %q, want every contributing source named", res.Assets[0].Source)
	}
}

func TestHigherConfidenceSourceWinsOnMerge(t *testing.T) {
	sc := domainScope(t, "example.com")
	weak := &stubSource{name: "ct", records: []Record{{Name: "a.example.com", Confidence: models.ConfidenceMedium}}}
	strong := &stubSource{name: "resolver", records: []Record{{Name: "a.example.com", Confidence: models.ConfidenceHigh}}}
	c, _ := NewCollector(sc, []Source{weak, strong}, Options{Now: reconNow})

	res, _ := c.Collect(context.Background(), "example.com")
	if res.Assets[0].Confidence != models.ConfidenceHigh {
		t.Errorf("confidence = %q, want the strongest source's value", res.Assets[0].Confidence)
	}
}

func TestCollectIsDeterministic(t *testing.T) {
	sc := domainScope(t, "example.com")
	src := &stubSource{name: "s", records: []Record{
		{Name: "b.example.com", Confidence: models.ConfidenceLow},
		{Name: "a.example.com", Confidence: models.ConfidenceHigh},
		{Name: "c.example.com", Confidence: models.ConfidenceMedium},
	}}
	c, _ := NewCollector(sc, []Source{src}, Options{Now: reconNow})

	first, _ := c.Collect(context.Background(), "example.com")
	for i := range 5 {
		again, _ := c.Collect(context.Background(), "example.com")
		for j := range first.Assets {
			if again.Assets[j].Name != first.Assets[j].Name {
				t.Fatalf("run %d differs at %d: %s vs %s", i, j, again.Assets[j].Name, first.Assets[j].Name)
			}
		}
	}
	if first.Assets[0].Name != "a.example.com" {
		t.Errorf("first asset = %s, want the highest confidence first", first.Assets[0].Name)
	}
}

func TestSourceTimeoutIsEnforced(t *testing.T) {
	sc := domainScope(t, "example.com")
	slow := &stubSource{name: "slow", records: []Record{{Name: "a.example.com"}}, delay: 2 * time.Second}
	fast := &stubSource{name: "fast", records: []Record{{Name: "b.example.com"}}}

	c, _ := NewCollector(sc, []Source{slow, fast}, Options{SourceTimeout: 50 * time.Millisecond, Now: reconNow})
	start := time.Now()
	res, err := c.Collect(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > time.Second {
		t.Error("a hung source was allowed to delay the whole run")
	}
	if len(res.Assets) != 1 || res.Assets[0].Name != "b.example.com" {
		t.Errorf("assets = %+v, want the fast source's result", res.Assets)
	}
}

func TestCollectStopsOnCallerCancellation(t *testing.T) {
	sc := domainScope(t, "example.com")
	slow := &stubSource{name: "slow", records: []Record{{Name: "a.example.com"}}, delay: 5 * time.Second}
	c, _ := NewCollector(sc, []Source{slow}, Options{Now: reconNow})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Collect(ctx, "example.com"); err != nil {
		t.Errorf("a cancelled collection returned an error instead of an empty result: %v", err)
	}
}

// --- hostile input -----------------------------------------------------------

func TestClassifyRejectsHostileNames(t *testing.T) {
	bad := []string{
		"", " ", ".", "..", "a..b.com", ".example.com",
		"exam ple.com", "example\x00.com", "example\n.com", "ex\tample.com",
		"https://example.com/path", "-example.com", "example-.com",
		strings.Repeat("a", 300) + ".com", "example.123", "192.168.0.1.5", "exa_mple..com",
	}
	for _, in := range bad {
		if name, kind, ok := classify(in, KindSubdomain); ok {
			t.Errorf("classify(%q) accepted it as %q (%s)", in, name, kind)
		}
	}
}

func TestClassifyAcceptsUsefulNames(t *testing.T) {
	cases := map[string]struct {
		name string
		kind string
	}{
		"example.com":               {"example.com", KindSubdomain},
		"WWW.Example.COM":           {"www.example.com", KindSubdomain},
		"www.example.com.":          {"www.example.com", KindSubdomain},
		"*.example.com":             {"example.com", KindSubdomain},
		"api-1.eu-west.example.com": {"api-1.eu-west.example.com", KindSubdomain},
		"_dmarc.example.com":        {"_dmarc.example.com", KindSubdomain},
		"admin@example.com":         {"example.com", KindEmail},
		"192.0.2.1":                 {"192.0.2.1", KindIP},
		"[2001:db8::1]":             {"2001:db8::1", KindIP},
		"a.b.c.d.e.example.com":     {"a.b.c.d.e.example.com", KindSubdomain},
	}
	for in, want := range cases {
		name, kind, ok := classify(in, KindSubdomain)
		if !ok {
			t.Errorf("classify(%q) rejected a usable name", in)
			continue
		}
		if name != want.name || kind != want.kind {
			t.Errorf("classify(%q) = (%q, %s), want (%q, %s)", in, name, kind, want.name, want.kind)
		}
	}
}

func TestNormalizeSeed(t *testing.T) {
	good, err := normalizeSeed(" Example.COM. ")
	if err != nil || good != "example.com" {
		t.Errorf("normalizeSeed = (%q, %v)", good, err)
	}
	for _, bad := range []string{"", "   ", "example", "192.0.2.1", "exa mple.com", "..."} {
		if _, err := normalizeSeed(bad); err == nil {
			t.Errorf("normalizeSeed(%q) was accepted", bad)
		}
	}
}

// --- crt.sh source -----------------------------------------------------------

type fakeFetcher struct {
	resp  *http.Response
	err   error
	calls int
	urls  []string
}

func (f *fakeFetcher) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	f.calls++
	f.urls = append(f.urls, req.URL.String())
	if f.err != nil {
		return nil, f.err
	}
	return f.resp, nil
}

func jsonResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
}

func TestCrtShEnumeratesAndStripsWildcards(t *testing.T) {
	payload, _ := json.Marshal([]crtEntry{
		{Id: 1, NameValue: "*.example.com\nexample.com\nwww.example.com", EntryTimestamp: "2026-01-01T00:00:00Z", IssuerName: "Test CA"},
		{Id: 2, NameValue: "other.net"},
	})
	f := &fakeFetcher{resp: jsonResponse(string(payload))}
	src := &CrtShSource{BaseURL: "https://crt.sh/", Fetcher: f, Clock: func() time.Time { return reconNow }}

	recs, err := src.Enumerate(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, r := range recs {
		names = append(names, r.Name)
		if r.Confidence != models.ConfidenceMedium {
			t.Errorf("a certificate-derived name claimed %q confidence; it proves issuance, not liveness", r.Confidence)
		}
	}
	joined := strings.Join(names, ",")
	if !strings.Contains(joined, "example.com") || !strings.Contains(joined, "www.example.com") {
		t.Errorf("names = %v", names)
	}
	for _, n := range names {
		if strings.HasPrefix(n, "*") {
			t.Errorf("the wildcard itself was returned: %s", n)
		}
	}
	if !strings.Contains(f.urls[0], "q=%25.example.com") {
		t.Errorf("request URL = %q, want the seed escaped as a %%."+"%s wildcard query", f.urls[0], "seed")
	}
}

func TestCrtShReportsDecodeFailureRatherThanReturningEmpty(t *testing.T) {
	f := &fakeFetcher{resp: jsonResponse("<html>rate limited</html>")}
	src := &CrtShSource{BaseURL: "https://crt.sh/", Fetcher: f}
	recs, err := src.Enumerate(context.Background(), "example.com")
	if err == nil {
		t.Fatal("an HTML error page was silently treated as 'no records'")
	}
	if len(recs) != 0 {
		t.Errorf("records = %v, want none", recs)
	}
}

func TestCrtShHandlesNonOKStatus(t *testing.T) {
	f := &fakeFetcher{resp: &http.Response{StatusCode: 429, Body: io.NopCloser(strings.NewReader(""))}}
	src := &CrtShSource{BaseURL: "https://crt.sh/", Fetcher: f}
	if _, err := src.Enumerate(context.Background(), "example.com"); err == nil {
		t.Error("a 429 was not reported")
	}
}

func TestCrtShIsBoundedByMaxRows(t *testing.T) {
	var entries []crtEntry
	for i := range 1000 {
		entries = append(entries, crtEntry{Id: int64(i), NameValue: fmt.Sprintf("h%04d.example.com", i)})
	}
	payload, _ := json.Marshal(entries)
	f := &fakeFetcher{resp: jsonResponse(string(payload))}
	src := &CrtShSource{BaseURL: "https://crt.sh/", Fetcher: f, MaxRows: 5}

	recs, err := src.Enumerate(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 5 {
		t.Errorf("parsed %d rows, want the cap of 5", len(recs))
	}
}

// --- provider source ---------------------------------------------------------

func TestProviderKeepsTheCredentialOutOfTheURL(t *testing.T) {
	var seen *http.Request
	f := &fakeFetcher{}
	f.resp = jsonResponse("[]")
	prov := &Provider{
		ID:       "shodan",
		Endpoint: "https://api.example.com/host/%s",
		KeyEnv:   "TOKEN",
		Parse:    func([]byte, time.Time) ([]Record, error) { return nil, nil },
		Fetcher:  recordingFetcher{&seen},
		Secret:   func() (string, bool) { return "super-secret-value", true },
	}
	if _, err := prov.Enumerate(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	if seen == nil {
		t.Fatal("no request was made")
	}
	if strings.Contains(seen.URL.String(), "super-secret-value") {
		t.Errorf("SECURITY: the credential appeared in the request URL: %s", seen.URL.String())
	}
	if seen.Header.Get("Authorization") != "Bearer super-secret-value" {
		t.Errorf("Authorization = %q", seen.Header.Get("Authorization"))
	}
}

type recordingFetcher struct{ req **http.Request }

func (r recordingFetcher) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	*r.req = req
	return jsonResponse("[]"), nil
}

func TestProviderRefusesWithoutACredential(t *testing.T) {
	prov := &Provider{
		ID: "p", Endpoint: "https://api.example.com/%s",
		Parse:   func([]byte, time.Time) ([]Record, error) { return nil, nil },
		Fetcher: &fakeFetcher{resp: jsonResponse("[]")},
		Secret:  func() (string, bool) { return "", false },
	}
	if _, err := prov.Enumerate(context.Background(), "example.com"); err == nil {
		t.Error("a provider without a credential made a request")
	}
}

func TestProviderRejectsAnEndpointWithoutAPlaceholder(t *testing.T) {
	prov := &Provider{
		ID: "p", Endpoint: "https://api.example.com/search",
		Parse:   func([]byte, time.Time) ([]Record, error) { return nil, nil },
		Fetcher: &fakeFetcher{resp: jsonResponse("[]")},
		Secret:  func() (string, bool) { return "k", true },
	}
	if _, err := prov.Enumerate(context.Background(), "example.com"); err == nil {
		t.Error("an endpoint with no seed placeholder was accepted; the seed would have been sent nowhere")
	}
}

func TestProviderRejectsMalformedResponse(t *testing.T) {
	prov := &Provider{
		ID: "p", Endpoint: "https://api.example.com/%s",
		Parse: func(b []byte, _ time.Time) ([]Record, error) {
			return nil, fmt.Errorf("bad json: %w", json.Unmarshal(b, &struct{}{}))
		},
		Fetcher: &fakeFetcher{resp: jsonResponse("not json")},
		Secret:  func() (string, bool) { return "key-with-enough-length", true },
	}
	if _, err := prov.Enumerate(context.Background(), "example.com"); err == nil {
		t.Error("a malformed provider response was accepted")
	}
}

func TestProviderDoesNotEchoAnErrorBody(t *testing.T) {
	// A provider that reflects the submitted key back in its error body must
	// not have that body reach the operator's log or the run's error list.
	f := &fakeFetcher{resp: &http.Response{
		StatusCode: 401,
		Body:       io.NopCloser(strings.NewReader(`{"error":"bad key: leaked-key-value-1234"}`)),
	}}
	prov := &Provider{
		ID: "p", Endpoint: "https://api.example.com/%s",
		Parse:   func([]byte, time.Time) ([]Record, error) { return nil, nil },
		Fetcher: f,
		Secret:  func() (string, bool) { return "leaked-key-value-1234", true },
	}
	_, err := prov.Enumerate(context.Background(), "example.com")
	if err == nil {
		t.Fatal("a 401 was not reported")
	}
	if strings.Contains(err.Error(), "leaked-key-value-1234") {
		t.Errorf("SECURITY: the credential was echoed in the error: %v", err)
	}
}

func TestPassiveFetcherRefusesRedirects(t *testing.T) {
	p := NewPassiveFetcher()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com/", nil)
	if err := p.client.CheckRedirect(req, nil); err == nil {
		t.Error("a redirect was followed from a passive source")
	}
}

// --- DNS TXT source ----------------------------------------------------------

func TestNamesFromTXTOnlyKeepsNamesInTheSeedZone(t *testing.T) {
	value := `v=spf1 include:_spf.attacker.net a mx ~all host=https://build.example.com/jenkins;`
	got := namesFromTXT(value, "example.com")
	var joined []string
	joined = append(joined, got...)
	if len(got) == 0 {
		t.Fatal("no names were extracted from a TXT record naming one")
	}
	for _, g := range joined {
		if strings.Contains(g, "attacker.net") {
			t.Errorf("a name outside the seed zone was accepted: %s", g)
		}
	}
}

func TestDNSRecordsSourceToleratesAnUnresolvableLabel(t *testing.T) {
	src := NewDNSRecordsSource(func(ctx context.Context, name string) ([]string, error) {
		if strings.HasPrefix(name, "_git.") {
			return nil, errors.New("no such host")
		}
		return []string{"https://registry.example.com/ token=abc"}, nil
	})
	if err := src.Available(); err != nil {
		t.Fatal(err)
	}
	recs, err := src.Enumerate(context.Background(), "example.com")
	if err == nil {
		t.Error("the unresolvable label was not reported at all")
	}
	found := false
	for _, r := range recs {
		if r.Name == "registry.example.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("the resolvable label's finding was discarded: %+v", recs)
	}
}

func TestDNSRecordsSourceRequiresAResolver(t *testing.T) {
	if err := (&DNSRecordsSource{}).Available(); err == nil {
		t.Error("a DNS source with no resolver reported itself as available")
	}
}

// --- observation conversion --------------------------------------------------

func TestToObservationsCarriesConfidence(t *testing.T) {
	assets := []Asset{{
		Name: "a.example.com", Kind: KindSubdomain, Source: "crt.sh",
		Confidence: models.ConfidenceMedium, FirstSeen: reconNow,
	}}
	obs := ToObservations("example.com", assets)
	if len(obs) != 1 {
		t.Fatalf("observations = %+v", obs)
	}
	if obs[0].Confidence != models.ConfidenceMedium {
		t.Errorf("confidence = %q, want the source's confidence preserved", obs[0].Confidence)
	}
	if obs[0].Data["kind"] != KindSubdomain {
		t.Errorf("data = %v, want the kind recorded", obs[0].Data)
	}
}
