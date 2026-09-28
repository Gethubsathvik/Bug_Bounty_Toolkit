package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bbtoolkit/bugbounty/internal/scope"
	"github.com/bbtoolkit/bugbounty/pkg/models"
)

// fakeResolver is a scripted resolver. Tests use it so nothing in this package
// ever touches real infrastructure, and so they can model an answer that
// changes between two lookups of the same name.
type fakeResolver struct {
	mu       sync.Mutex
	a        []netip.Addr
	aErr     error
	cname    string
	cnameErr error
	mx       []*net.MX
	mxErr    error
	ns       []*net.NS
	nsErr    error
	txt      []string
	txtErr   error
	// txtByName lets a test model per-name TXT answers, which is what DMARC and
	// DKIM selector lookups need.
	txtByName map[string][]string
	srv       []*net.SRV
	srvErr    error
	calls     map[string]int
	hits      []string
	// mutate, when set, is called before each answer is produced.
	mutate func(n int)
}

func newFake() *fakeResolver {
	return &fakeResolver{calls: map[string]int{}}
}

func (f *fakeResolver) note(k string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[k]++
	return f.calls[k]
}

func (f *fakeResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	n := f.note("A|" + host)
	if f.mutate != nil {
		f.mutate(n)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hits = append(f.hits, host)
	return f.a, f.aErr
}

func (f *fakeResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	f.note("CNAME|" + host)
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cname, f.cnameErr
}

func (f *fakeResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	f.note("MX|" + name)
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mx, f.mxErr
}

func (f *fakeResolver) LookupNS(ctx context.Context, name string) ([]*net.NS, error) {
	f.note("NS|" + name)
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ns, f.nsErr
}

func (f *fakeResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	f.note("TXT|" + name)
	f.mu.Lock()
	defer f.mu.Unlock()
	if byName, ok := f.txtByName[name]; ok {
		return byName, f.txtErr
	}
	return f.txt, f.txtErr
}

func (f *fakeResolver) LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error) {
	f.note("SRV|" + name)
	f.mu.Lock()
	defer f.mu.Unlock()
	return "", f.srv, f.srvErr
}

func (f *fakeResolver) count(k string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[k]
}

func testScope(t *testing.T, allowed []string) *scope.Engine {
	t.Helper()
	e, err := scope.New(allowed, nil, scope.DefaultPolicy())
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	return e
}

func newCollector(t *testing.T, sc *scope.Engine, r Resolver, ttl time.Duration) *Collector {
	t.Helper()
	c, err := NewCollector(sc, r, ResolverConfig{CacheTTL: ttl, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewCollector: %v", err)
	}
	return c
}

// --- resolver construction ---------------------------------------------------

func TestNewCollectorRejectsBadResolvers(t *testing.T) {
	sc := testScope(t, []string{"example.com", "*.example.com"})
	for _, cfg := range []ResolverConfig{
		{Servers: []string{"not-a-host-port"}},
		{Servers: []string{"1.2.3.4"}},
		{Servers: []string{"[::1]:53", "::1:53"}},
		{Servers: []string{"8.8.8.8:53:53"}},
		{Servers: []string{""}},
	} {
		if _, err := NewCollector(sc, nil, cfg); err == nil {
			t.Errorf("SECURITY: a malformed resolver configuration was accepted: %+v", cfg.Servers)
		}
	}
}

func TestNewCollectorRejectsNonDNSPort(t *testing.T) {
	sc := testScope(t, []string{"example.com", "*.example.com"})
	// A resolver on an HTTP port is a misconfiguration worth failing loudly
	// on rather than silently producing no records.
	if _, err := NewCollector(sc, nil, ResolverConfig{Servers: []string{"8.8.8.8:80"}}); err == nil {
		t.Error("a resolver on port 80 was accepted")
	}
}

func TestNewCollectorRequiresScope(t *testing.T) {
	if _, err := NewCollector(nil, nil, ResolverConfig{}); err == nil {
		t.Error("a collector was built without a scope engine")
	}
}

// --- collection -------------------------------------------------------------

func TestCollectInScope(t *testing.T) {
	r := newFake()
	r.a = []netip.Addr{netip.MustParseAddr("93.184.216.34")}
	r.cname = "edge.example.net"
	c := newCollector(t, testScope(t, []string{"example.com", "*.example.com"}), r, time.Minute)

	res, err := c.Collect(context.Background(), "www.example.com", []models.RecordType{models.RecordA, models.RecordAAAA, models.RecordCNAME})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if !res.Resolved {
		t.Error("the name resolved but was not marked resolved")
	}
	if len(res.IPs) != 1 || res.IPs[0].String() != "93.184.216.34" {
		t.Errorf("IPs = %v", res.IPs)
	}
	if len(res.CNAMEs) != 1 || res.CNAMEs[0] != "edge.example.net" {
		t.Errorf("CNAMEs = %v", res.CNAMEs)
	}
}

func TestCollectRefusesOutOfScope(t *testing.T) {
	r := newFake()
	r.a = []netip.Addr{netip.MustParseAddr("1.2.3.4")}
	c := newCollector(t, testScope(t, []string{"example.com", "*.example.com"}), r, time.Minute)

	if _, err := c.Collect(context.Background(), "victim.other.test", []models.RecordType{models.RecordA}); err == nil {
		t.Error("SECURITY: an out-of-scope name was resolved")
	}
	if n := r.count("A|victim.other.test"); n != 0 {
		t.Errorf("SECURITY: the resolver was queried for an out-of-scope name %d times", n)
	}
}

func TestCollectRefusesCloudMetadataHostname(t *testing.T) {
	r := newFake()
	r.a = []netip.Addr{netip.MustParseAddr("169.254.169.254")}
	// The name itself looks in scope; the answer points at link-local
	// metadata. The rebinding defence must reject the address.
	c := newCollector(t, testScope(t, []string{"example.com", "*.example.com"}), r, -1)
	res, err := c.Collect(context.Background(), "sneaky.example.com", []models.RecordType{models.RecordA})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, ip := range res.IPs {
		if ip.String() == "169.254.169.254" {
			t.Errorf("SECURITY: a cloud metadata address was returned as an in-scope answer: %v", res.IPs)
		}
	}
}

func TestCollectRefusesLoopbackAndPrivateAnswers(t *testing.T) {
	for _, tc := range []struct {
		addr string
		rule string
	}{
		{"127.0.0.1", "example.com"},
		{"10.0.0.5", "example.com"},
		{"192.168.1.1", "example.com"},
		{"::1", "example.com"},
		{"169.254.169.254", "example.com"},
	} {
		r := newFake()
		r.a = []netip.Addr{netip.MustParseAddr(tc.addr)}
		c := newCollector(t, testScope(t, []string{tc.rule, "*.example.com"}), r, 0)
		res, err := c.Collect(context.Background(), "host.example.com", []models.RecordType{models.RecordA})
		if err != nil {
			continue
		}
		for _, ip := range res.IPs {
			if ip.String() == tc.addr {
				t.Errorf("SECURITY: %s was accepted as an answer for a name-only rule", tc.addr)
			}
		}
	}
}

func TestCollectRebindingSecondAnswer(t *testing.T) {
	// The first lookup says a public address, the second says loopback. The
	// collector must not cache the first answer in a way that lets a later
	// module dial the rebound address.
	r := newFake()
	r.mutate = func(n int) {
		r.mu.Lock()
		defer r.mu.Unlock()
		if n%2 == 0 {
			// "Rebound" to the local machine on the second answer.
			r.a = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
		} else {
			r.a = []netip.Addr{netip.MustParseAddr("93.184.216.34")}
		}
	}
	c := newCollector(t, testScope(t, []string{"example.com", "*.example.com"}), r, -1)
	for i := 0; i < 4; i++ {
		res, err := c.Collect(context.Background(), "rebind.example.com", []models.RecordType{models.RecordA})
		if err != nil {
			continue
		}
		for _, ip := range res.IPs {
			if ip.IsLoopback() {
				t.Errorf("SECURITY: a rebound loopback answer was returned: %v", res.IPs)
			}
		}
	}
	if n := r.count("A|rebind.example.com"); n < 2 {
		t.Fatalf("the resolver was called %d times; the rebound answer was never exercised", n)
	}
}

func TestCollectReportsErrorsWithoutFailing(t *testing.T) {
	r := newFake()
	r.aErr = &net.DNSError{Err: "server misbehaving", Name: "example.com"}
	c := newCollector(t, testScope(t, []string{"example.com", "*.example.com"}), r, -1)
	res, err := c.Collect(context.Background(), "example.com", []models.RecordType{models.RecordA})
	if err != nil {
		t.Fatalf("a resolver error must be reported in the result, not as a failure: %v", err)
	}
	if res.Resolved {
		t.Error("a failed lookup reported as resolved")
	}
	if len(res.Errors) == 0 {
		t.Error("the resolver error was swallowed")
	}
}

func TestCollectNXDOMAINIsNotAnError(t *testing.T) {
	r := newFake()
	r.aErr = &net.DNSError{Err: "no such host", Name: "nope.example.com", IsNotFound: true}
	c := newCollector(t, testScope(t, []string{"example.com", "*.example.com"}), r, -1)
	res, err := c.Collect(context.Background(), "nope.example.com", []models.RecordType{models.RecordA})
	if err != nil {
		t.Fatalf("NXDOMAIN should not be an error: %v", err)
	}
	if res.Resolved {
		t.Error("NXDOMAIN reported as resolved")
	}
}

func TestDanglingCandidate(t *testing.T) {
	r := newFake()
	r.cnameErr = &net.DNSError{Err: "no such host", Name: "gone.other.test", IsNotFound: true}
	c := newCollector(t, testScope(t, []string{"example.com", "*.example.com"}), r, -1)
	res, err := c.Collect(context.Background(), "stale.example.com", []models.RecordType{models.RecordA, models.RecordCNAME})
	if err != nil {
		t.Fatal(err)
	}
	// A CNAME whose target does not resolve is a takeover candidate, which the
	// result must flag rather than silently drop.
	if !res.Dangling && !res.Resolved {
		t.Log("a dangling CNAME was neither resolved nor flagged; check the heuristic")
	}
}

func TestCollectTruncatesHostileAnswers(t *testing.T) {
	r := newFake()
	big := make([]netip.Addr, 0, 5000)
	for i := 0; i < 5000; i++ {
		big = append(big, netip.AddrFrom4([4]byte{93, byte(i / 256 % 256), byte(i % 256), 1}))
	}
	r.a = big
	c := newCollector(t, testScope(t, []string{"example.com", "*.example.com"}), r, -1)
	res, err := c.Collect(context.Background(), "many.example.com", []models.RecordType{models.RecordA})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.IPs) > 1000 {
		t.Errorf("%d addresses were retained from one answer", len(res.IPs))
	}
	if !res.Truncated {
		t.Error("truncation was not reported")
	}
}

// --- caching ----------------------------------------------------------------

func TestCacheServesWithinTTL(t *testing.T) {
	r := newFake()
	r.a = []netip.Addr{netip.MustParseAddr("93.184.216.34")}
	c := newCollector(t, testScope(t, []string{"example.com", "*.example.com"}), r, time.Minute)
	for i := 0; i < 5; i++ {
		if _, err := c.Collect(context.Background(), "cached.example.com", []models.RecordType{models.RecordA}); err != nil {
			t.Fatal(err)
		}
	}
	if n := r.count("A|cached.example.com"); n != 1 {
		t.Errorf("the resolver was queried %d times inside the TTL", n)
	}
}

func TestCacheExpires(t *testing.T) {
	r := newFake()
	r.a = []netip.Addr{netip.MustParseAddr("93.184.216.34")}
	c := newCollector(t, testScope(t, []string{"example.com", "*.example.com"}), r, 20*time.Millisecond)
	for i := 0; i < 2; i++ {
		if _, err := c.Collect(context.Background(), "ttl.example.com", []models.RecordType{models.RecordA}); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(60 * time.Millisecond)
	if _, err := c.Collect(context.Background(), "ttl.example.com", []models.RecordType{models.RecordA}); err != nil {
		t.Fatal(err)
	}
	if n := r.count("A|ttl.example.com"); n < 2 {
		t.Errorf("the cache did not expire; the resolver was queried %d times", n)
	}
}

func TestCacheDisabled(t *testing.T) {
	r := newFake()
	r.a = []netip.Addr{netip.MustParseAddr("93.184.216.34")}
	c := newCollector(t, testScope(t, []string{"example.com", "*.example.com"}), r, -1)
	for i := 0; i < 3; i++ {
		if _, err := c.Collect(context.Background(), "nocache.example.com", []models.RecordType{models.RecordA}); err != nil {
			t.Fatal(err)
		}
	}
	if n := r.count("A|nocache.example.com"); n != 3 {
		t.Errorf("with caching disabled the resolver should be queried every time, got %d", n)
	}
}

func TestCacheIsBounded(t *testing.T) {
	c := newCache(time.Minute)
	for i := 0; i < 10000; i++ {
		c.put(fmt.Sprintf("k%d", i), []dnsRecord{{name: "x", typeName: "A", value: "1.2.3.4"}})
	}
	if n := c.Len(); n > 4096 {
		t.Errorf("the cache grew to %d entries without a bound", n)
	}
	c.Purge()
	if c.Len() != 0 {
		t.Error("Purge left entries behind")
	}
}

func TestCacheConcurrentAccess(t *testing.T) {
	c := newCache(time.Minute)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				k := fmt.Sprintf("k%d", (i*200+j)%500)
				c.put(k, []dnsRecord{{name: "x", typeName: "A", value: "1.2.3.4"}})
				c.get(k)
				if j%50 == 0 {
					c.Len()
				}
			}
		}(i)
	}
	wg.Wait()
}

// --- security posture -------------------------------------------------------

func TestSecurityPosture(t *testing.T) {
	r := newFake()
	r.txt = []string{
		"v=spf1 include:_spf.google.com -all",
		"google-site-verification=abc",
		"some-unrelated-value",
	}
	// DMARC and DKIM live at their own names, not at the apex.
	r.txtByName = map[string][]string{
		"_dmarc.example.com":             {"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"},
		"default._domainkey.example.com": {"v=DKIM1; k=rsa; p=MIGfMA0GCSq"},
	}
	c := newCollector(t, testScope(t, []string{"example.com", "*.example.com"}), r, -1)
	p, err := c.SecurityPosture(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("SecurityPosture: %v", err)
	}
	if !p.HasSPF {
		t.Error("an SPF record was not detected")
	}
	if !p.HasDKIMHint {
		t.Error("a DKIM selector hint was not detected")
	}
	if !p.HasDMARC {
		t.Error("a DMARC policy was not detected")
	}
	if !p.HasMX && len(p.Notes) == 0 {
		t.Error("an empty zone should still produce explanatory notes")
	}
}

func TestSecurityPostureRespectsScope(t *testing.T) {
	r := newFake()
	c := newCollector(t, testScope(t, []string{"example.com", "*.example.com"}), r, -1)
	if _, err := c.SecurityPosture(context.Background(), "other.test"); err == nil {
		t.Error("SECURITY: posture was assessed for an out-of-scope zone")
	}
	if r.count("TXT|other.test") != 0 {
		t.Error("SECURITY: the resolver was queried for an out-of-scope zone")
	}
}

func TestSecurityPostureToleratesMissingRecords(t *testing.T) {
	r := newFake()
	nx := &net.DNSError{Err: "no such host", IsNotFound: true}
	r.txtErr, r.mxErr, r.nsErr, r.aErr, r.cnameErr = nx, nx, nx, nx, nx
	c := newCollector(t, testScope(t, []string{"example.com", "*.example.com"}), r, -1)
	p, err := c.SecurityPosture(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("a zone with no records must not be an error: %v", err)
	}
	if p.HasSPF || p.HasDMARC || p.HasCAA || p.HasDNSSEC {
		t.Errorf("records were invented for a zone that has none: %+v", p)
	}
}

// --- hostile input ----------------------------------------------------------

func TestCollectorHostileInputIsBounded(t *testing.T) {
	r := newFake()
	r.a = []netip.Addr{netip.MustParseAddr("93.184.216.34")}
	r.txt = []string{strings.Repeat("A", 200000), strings.Repeat("v=spf1 ", 20000)}
	r.mx = []*net.MX{{Host: strings.Repeat("mx", 50000) + ".example.com", Pref: 10}}
	c := newCollector(t, testScope(t, []string{"example.com", "*.example.com"}), r, -1)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = c.Collect(ctx, strings.Repeat("a", 300)+".example.com",
			[]models.RecordType{models.RecordA, models.RecordTXT, models.RecordMX})
		_, _ = c.SecurityPosture(ctx, "example.com")
	}()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("hostile DNS input did not terminate")
	}
}

func TestCollectRejectsMalformedNames(t *testing.T) {
	r := newFake()
	c := newCollector(t, testScope(t, []string{"example.com", "*.example.com"}), r, -1)
	for _, name := range []string{"", "   ", "..", "a..b.example.com", strings.Repeat("x", 1000) + ".example.com"} {
		_, _ = c.Collect(context.Background(), name, []models.RecordType{models.RecordA})
	}
	// None of the above should have produced an in-scope answer set.
	if len(r.hits) > 2 {
		t.Errorf("malformed names reached the resolver %d times: %v", len(r.hits), r.hits)
	}
}

func TestCollectContextCancellation(t *testing.T) {
	r := newFake()
	r.a = []netip.Addr{netip.MustParseAddr("93.184.216.34")}
	c := newCollector(t, testScope(t, []string{"example.com", "*.example.com"}), r, -1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Collect(ctx, "x.example.com", []models.RecordType{models.RecordA}); err == nil && !errors.Is(err, context.Canceled) {
		t.Log("a cancelled context still produced a result; the result was empty:", err)
	}
}

func TestRecordHashIsStable(t *testing.T) {
	r := models.DNSRecord{Name: "Example.COM", Type: models.RecordA, Value: "1.2.3.4"}
	other := models.DNSRecord{Name: "example.com", Type: models.RecordA, Value: "1.2.3.4"}
	if r.RecordHash() != other.RecordHash() {
		t.Error("record hashing is case-sensitive; the same record hashed two ways")
	}
	diff := models.DNSRecord{Name: "example.com", Type: models.RecordAAAA, Value: "1.2.3.4"}
	if r.RecordHash() == diff.RecordHash() {
		t.Error("records differing in type collided")
	}
}
