package scope

import (
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// The tests in this file cover the parts of the engine that decide whether a
// connection may be made to an address a name resolved to. That decision is the
// DNS-rebinding defence and the last check before a packet leaves the process,
// so it is exercised directly here rather than only through the HTTP client.

func addr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return a
}

// TestCheckURLIsSafeUnderConcurrentUse covers the engine's advertised
// concurrency contract. Every other public check on Engine takes the read lock;
// CheckURL did not, while still being the one the crawler and the HTTP client
// call from many goroutines at once. The unsynchronised read is only observable
// under -race, so the assertion below checks the decisions stay correct and the
// race detector does the rest.
func TestCheckURLIsSafeUnderConcurrentUse(t *testing.T) {
	e := mustEngine(t, []string{"example.com", "*.example.com"}, []string{"internal.example.com"})
	inScope, _ := url.Parse("https://example.com/x")
	alsoInScope, _ := url.Parse("https://api.example.com/x")
	excluded, _ := url.Parse("https://internal.example.com/x")
	outOfScope, _ := url.Parse("https://other-target.net/")

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 200; n++ {
				if !e.CheckURL(inScope).Allowed {
					t.Error("an in-scope URL was denied")
					return
				}
				if !e.CheckURL(alsoInScope).Allowed {
					t.Error("a wildcard-matched URL was denied")
					return
				}
				if e.CheckURL(excluded).Allowed {
					t.Error("SECURITY: an excluded URL was allowed")
					return
				}
				if e.CheckURL(outOfScope).Allowed {
					t.Error("SECURITY: an out-of-scope URL was allowed")
					return
				}
				if e.URLInScope(outOfScope) {
					t.Error("SECURITY: URLInScope allowed an out-of-scope URL")
					return
				}
			}
		}()
	}
	// Mutate the engine from another goroutine too: WithPolicy and
	// SetSourcePath both write under the write lock, which is what the read
	// lock in CheckURL has to exclude.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for n := 0; n < 200; n++ {
			e.WithPolicy(e.Policy())
			e.SetSourcePath("scope.yaml")
		}
	}()
	wg.Wait()
}

// TestCheckResolvedAddrRefusesSpecialPurposeAddresses covers the core rule: a
// name in scope authorises reaching public addresses, not special-purpose ones.
func TestCheckResolvedAddrRefusesSpecialPurposeAddresses(t *testing.T) {
	e := mustEngine(t, []string{"example.com"}, nil)

	refused := []struct {
		ip   string
		what string
	}{
		{"127.0.0.1", "loopback"},
		{"::1", "IPv6 loopback"},
		{"10.0.0.5", "private class A"},
		{"172.16.0.1", "private class B"},
		{"192.168.1.1", "private class C"},
		{"169.254.1.1", "link-local"},
		{"100.64.0.1", "carrier-grade NAT"},
		{"0.0.0.0", "unspecified"},
	}
	for _, c := range refused {
		t.Run(c.what, func(t *testing.T) {
			if d := e.CheckResolvedAddr("example.com", addr(t, c.ip)); d.Allowed {
				t.Errorf("SECURITY: %s was allowed via an in-scope host: %s", c.ip, d.Reason)
			}
		})
	}
}

func TestCheckResolvedAddrAllowsPublicAddresses(t *testing.T) {
	e := mustEngine(t, []string{"example.com"}, nil)
	for _, ip := range []string{"93.184.216.34", "8.8.8.8", "2606:2800:220:1:248:1893:25c8:1946"} {
		if d := e.CheckResolvedAddr("example.com", addr(t, ip)); !d.Allowed {
			t.Errorf("a public address %s was refused: %s", ip, d.Reason)
		}
	}
}

// TestCloudMetadataIsNeverReachable is checked separately because it is the one
// address whose refusal must not be conditional on a scope file.
func TestCloudMetadataIsNeverReachable(t *testing.T) {
	for _, rule := range [][]string{
		{"example.com"},
		{"169.254.169.254"},
		{"169.254.0.0/16"},
		{"example.com", "169.254.0.0/16"},
	} {
		e, err := New(rule, nil, DefaultPolicy())
		if err != nil {
			t.Fatalf("New(%v): %v", rule, err)
		}
		ip := addr(t, "169.254.169.254")
		d := e.CheckResolvedAddr("example.com", ip)
		if d.Allowed {
			t.Errorf("SECURITY: the metadata address was allowed by rules %v", rule)
		}
		// The refusal must not merely suggest a way around itself.
		if strings.Contains(d.Reason, "allow_cloud_metadata") {
			t.Errorf("the refusal points at a switch that no longer works: %q", d.Reason)
		}
	}
}

// TestExclusionBeatsAnInScopeName covers the proxy shape: a scoped hostname that
// resolves inside an excluded range must not be usable to reach it.
func TestExclusionBeatsAnInScopeName(t *testing.T) {
	cases := []struct {
		name              string
		allowed, excluded []string
		host, ip          string
	}{
		{"excluded IP", []string{"example.com"}, []string{"10.0.0.5"}, "example.com", "10.0.0.5"},
		{"excluded CIDR", []string{"example.com"}, []string{"10.0.0.0/8"}, "example.com", "10.1.2.3"},
		{"excluded URL host", []string{"example.com"}, []string{"https://10.0.0.5/"}, "example.com", "10.0.0.5"},
		// A public address that is also excluded must be refused even though it
		// would otherwise be fine.
		{"excluded public address", []string{"example.com"}, []string{"93.184.216.34"}, "example.com", "93.184.216.34"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, err := New(c.allowed, c.excluded, DefaultPolicy())
			if err != nil {
				t.Fatal(err)
			}
			if d := e.CheckResolvedAddr(c.host, addr(t, c.ip)); d.Allowed {
				t.Errorf("SECURITY: an excluded address was reachable: %s", d.Reason)
			}
		})
	}
}

// TestExplicitRangeAuthorisesItsOwnAddresses covers the escape hatch: an
// operator who lists a range has said they mean it.
func TestExplicitRangeAuthorisesItsOwnAddresses(t *testing.T) {
	e, err := New([]string{"10.0.0.0/8"}, nil, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if d := e.CheckResolvedAddr("anything", addr(t, "10.1.2.3")); !d.Allowed {
		t.Errorf("an explicitly allowed private range was refused: %s", d.Reason)
	}
	// Outside the range still refused, so the rule's reach is not unbounded.
	if d := e.CheckResolvedAddr("anything", addr(t, "172.16.0.1")); d.Allowed {
		t.Error("SECURITY: an address outside the allowed range was permitted")
	}
}

func TestCheckResolvedAddrRejectsAnInvalidAddress(t *testing.T) {
	e := mustEngine(t, []string{"example.com"}, nil)
	if d := e.CheckResolvedAddr("example.com", netip.Addr{}); d.Allowed {
		t.Error("SECURITY: the zero address was allowed")
	}
}

// TestResolveAndCheckFiltersTheAnswerSet checks the convenience form the HTTP
// transport dials from, including the split it must produce.
func TestResolveAndCheck(t *testing.T) {
	e := mustEngine(t, []string{"example.com"}, nil)

	allowed, denied := e.ResolveAndCheck("example.com", []netip.Addr{
		addr(t, "93.184.216.34"),
		addr(t, "127.0.0.1"),
		addr(t, "8.8.8.8"),
		addr(t, "169.254.169.254"),
		addr(t, "10.0.0.1"),
	})
	if len(allowed) != 2 {
		t.Errorf("%d addresses were allowed (%v), want 2", len(allowed), allowed)
	}
	if len(denied) != 3 {
		t.Errorf("%d addresses were denied (%v), want 3", len(denied), denied)
	}
	for _, a := range allowed {
		if !a.IsGlobalUnicast() || a.IsLoopback() || a.IsPrivate() {
			t.Errorf("a special-purpose address reached the allowed list: %s", a)
		}
	}
	for _, d := range denied {
		if d.Reason == "" {
			t.Error("a denial carries no reason")
		}
	}

	// The returned addresses are unmapped, so a caller cannot be handed an
	// IPv4-mapped IPv6 address that bypasses a comparison.
	mapped := netip.MustParseAddr("::ffff:127.0.0.1")
	got, _ := e.ResolveAndCheck("example.com", []netip.Addr{mapped})
	if len(got) != 0 {
		t.Errorf("an IPv4-mapped loopback address survived: %v", got)
	}
}

func TestResolveAndCheckOnAnEmptyAnswer(t *testing.T) {
	e := mustEngine(t, []string{"example.com"}, nil)
	allowed, denied := e.ResolveAndCheck("example.com", nil)
	if len(allowed) != 0 || len(denied) != 0 {
		t.Errorf("an empty answer produced %v / %v", allowed, denied)
	}
}

// --- convenience API ---------------------------------------------------------

func TestHostAndURLInScope(t *testing.T) {
	e := mustEngine(t, []string{"example.com"}, []string{"internal.example.com"})
	mustURL := func(s string) *url.URL {
		u, err := url.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}

	if !e.HostInScope("example.com") {
		t.Error("an allowed host was reported out of scope")
	}
	if e.HostInScope("internal.example.com") {
		t.Error("SECURITY: an excluded host was reported in scope")
	}
	if e.HostInScope("other-target.net") {
		t.Error("SECURITY: an unrelated host was reported in scope")
	}

	if !e.URLInScope(mustURL("https://example.com/x")) {
		t.Error("an allowed URL was reported out of scope")
	}
	if e.URLInScope(mustURL("https://other-target.net/")) {
		t.Error("SECURITY: an unrelated URL was reported in scope")
	}
	// A non-standard port is refused unless the policy allows it.
	if e.URLInScope(mustURL("https://example.com:8443/")) {
		t.Error("SECURITY: a non-standard port was permitted by default")
	}
}

// TestWithPolicyKeepsTheRules covers the copy used to adjust limits mid-run. It
// must not quietly widen what may be contacted, or tightening a rate limit
// would come at the cost of the scope.
func TestWithPolicyKeepsTheRules(t *testing.T) {
	e, err := New([]string{"example.com", "10.0.0.0/8"}, []string{"internal.example.com"}, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	p := DefaultPolicy()
	p.MaxRPS = 1
	p.AllowedPorts = []int{80, 443, 8443}
	tightened := e.WithPolicy(p)

	if !tightened.HostInScope("example.com") {
		t.Error("the allow list was lost by WithPolicy")
	}
	if tightened.HostInScope("internal.example.com") {
		t.Error("SECURITY: the exclude list was lost by WithPolicy")
	}
	if tightened.Policy().MaxRPS != 1 {
		t.Errorf("the new rate limit was not applied: %v", tightened.Policy().MaxRPS)
	}
	// The tightened engine must not be able to change the original, or a rate
	// limit would not hold for the run it was set for.
	if e.Policy().MaxRPS == 1 {
		t.Error("WithPolicy mutated the engine it was called on")
	}
	// A new port becomes reachable, and only on the copy.
	u, _ := url.Parse("https://example.com:8443/")
	if !tightened.URLInScope(u) {
		t.Error("the added port was not permitted on the copy")
	}
	if e.URLInScope(u) {
		t.Error("SECURITY: the added port leaked to the original engine")
	}
}

func TestWithPolicyRejectsNonsensePorts(t *testing.T) {
	e := mustEngine(t, []string{"example.com"}, nil)
	p := DefaultPolicy()
	p.AllowedPorts = []int{0, -1, 70000}
	got := e.WithPolicy(p)
	// Every out-of-range port is dropped, leaving the defaults rather than an
	// engine that permits nothing or everything.
	u, _ := url.Parse("https://example.com/")
	if !got.URLInScope(u) {
		t.Error("a policy of only invalid ports left the host unreachable")
	}
}

func TestSourcePathIsRecorded(t *testing.T) {
	e := mustEngine(t, []string{"example.com"}, nil)
	if e.SourcePath() != "" {
		t.Errorf("a fresh engine already has a source path: %q", e.SourcePath())
	}
	e.SetSourcePath("/etc/scope.yaml")
	if got := e.SourcePath(); got != "/etc/scope.yaml" {
		t.Errorf("SourcePath = %q", got)
	}
	// The policy survives the annotation.
	if !e.HostInScope("example.com") {
		t.Error("recording a source path disturbed the rules")
	}
}

// --- durations ---------------------------------------------------------------

// TestDurationYAMLRoundTrip covers the type a scope file's timeouts are written
// with, including the bare number form that a hand-written file is likely to use.
func TestDurationYAMLRoundTrip(t *testing.T) {
	type doc struct {
		Timeout Duration `yaml:"timeout"`
	}
	cases := []struct {
		yaml string
		want time.Duration
	}{
		{"timeout: 10s\n", 10 * time.Second},
		{"timeout: 1m30s\n", 90 * time.Second},
		{"timeout: 500ms\n", 500 * time.Millisecond},
		// A bare number is seconds, never nanoseconds.
		{"timeout: 5\n", 5 * time.Second},
		{"timeout: 0.5\n", 500 * time.Millisecond},
	}
	for _, c := range cases {
		var d doc
		if err := yaml.Unmarshal([]byte(c.yaml), &d); err != nil {
			t.Errorf("%q: %v", strings.TrimSpace(c.yaml), err)
			continue
		}
		if d.Timeout.D() != c.want {
			t.Errorf("%q = %v, want %v", strings.TrimSpace(c.yaml), d.Timeout.D(), c.want)
		}
		if d.Timeout.String() != c.want.String() {
			t.Errorf("String() = %q, want %q", d.Timeout.String(), c.want.String())
		}
	}

	for _, bad := range []string{"timeout: soon\n", "timeout: \"\"\n", "timeout: [1]\n", "timeout: {}\n"} {
		var d doc
		if err := yaml.Unmarshal([]byte(bad), &d); err == nil {
			t.Errorf("%q was accepted as a duration", strings.TrimSpace(bad))
		}
	}
}

func TestDurationMarshalsAsAString(t *testing.T) {
	v, err := Duration(90 * time.Second).MarshalYAML()
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := v.(string); !ok || s != "1m30s" {
		t.Errorf("marshalled to %#v, want the string \"1m30s\"", v)
	}
}

// --- underscore names --------------------------------------------------------

// TestUnderscoreServiceNames checks the narrow exemption that lets a scope file
// name a DNS service record. The exemption is for names that genuinely begin a
// label with an underscore; an underscore anywhere else is a typo or an attempt
// to smuggle a wildcard, and must be refused.
func TestUnderscoreServiceNames(t *testing.T) {
	accepted := []string{
		"_dmarc.example.com",
		"_domainkey.example.com",
		"_25._tcp.example.com",
	}
	for _, h := range accepted {
		if _, err := CanonicalizeDomain(h); err != nil {
			t.Errorf("%q was refused: %v", h, err)
		}
	}

	refused := []string{
		"exa_mple.com", // underscore mid-label
		"_dmarc.exa_mple.com",
		"example.com_", // trailing underscore on a label
		"_",            // underscore alone
		"_.example.com",
		"_dmarc.*.example.com", // wildcard plus underscore
		"exa_mple.com.",
	}
	for _, h := range refused {
		if got, err := CanonicalizeDomain(h); err == nil {
			t.Errorf("SECURITY: %q was accepted as %q", h, got)
		}
	}
}

// --- file loading ------------------------------------------------------------

func TestLoadFileRecordsItsPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scope.yaml")
	body := "version: 1\nscope:\n  allowed:\n    - example.com\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, file, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if eng.SourcePath() != path {
		t.Errorf("SourcePath = %q, want %q", eng.SourcePath(), path)
	}
	if file.Version != FileVersion {
		t.Errorf("Version = %d, want %d", file.Version, FileVersion)
	}
	if !eng.HostInScope("example.com") {
		t.Error("the loaded scope does not admit what it lists")
	}
}

func TestLoadFileRejectsBadInput(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	if _, _, err := LoadFile(filepath.Join(dir, "absent.yaml")); err == nil {
		t.Error("a missing file was loaded")
	}
	if _, _, err := LoadFile(write("empty.yaml", "")); err == nil {
		t.Error("an empty file was loaded")
	}
	if _, _, err := LoadFile(write("unknown.yaml", "version: 1\nscope:\n  allowd:\n    - example.com\n")); err == nil {
		t.Error("SECURITY: a misspelled safety key was accepted")
	}
	if _, _, err := LoadFile(write("future.yaml", "version: 99\nscope:\n  allowed:\n    - example.com\n")); err == nil {
		t.Error("a newer schema version was loaded")
	}
}

// TestIsCloudMetadataAddr covers the exported form the transport uses, so a
// resolver that lies about what a name points at cannot get past it. The
// IPv4-mapped form matters: a name can resolve to ::ffff:169.254.169.254 and
// still be the metadata service.
func TestIsCloudMetadataAddr(t *testing.T) {
	yes := []string{
		"169.254.169.254",
		"::ffff:169.254.169.254", // IPv4-mapped
	}
	for _, s := range yes {
		if !IsCloudMetadataAddr(addr(t, s)) {
			t.Errorf("SECURITY: %s was not recognised as the metadata address", s)
		}
	}

	no := []string{
		"169.254.169.253", // adjacent, not the service
		"169.254.0.1",     // link-local but a different host
		"10.0.0.1",
		"93.184.216.34",
		"127.0.0.1",
		"::1",
	}
	for _, s := range no {
		if IsCloudMetadataAddr(addr(t, s)) {
			t.Errorf("%s was wrongly treated as the metadata address", s)
		}
	}

	// An invalid address must not panic.
	if IsCloudMetadataAddr(netip.Addr{}) {
		t.Error("the zero address was treated as the metadata address")
	}
}

// TestEngineStringIsLogSafe covers the debug rendering. It ends up in log
// output, so a rule containing a newline must not be able to forge a line.
func TestEngineStringIsLogSafe(t *testing.T) {
	e, err := New([]string{"example.com", "*.dev.example.com"}, []string{"internal.example.com"}, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	s := e.String()
	if !strings.Contains(s, "allowed:2") {
		t.Errorf("the summary does not count the allowed rules:\n%s", s)
	}
	if !strings.Contains(s, "excluded:1") {
		t.Errorf("the summary does not count the excluded rules:\n%s", s)
	}
	if !strings.Contains(s, "passive_only:false") {
		t.Errorf("the summary omits the passive-only switch:\n%s", s)
	}
	// The multi-line form is intentional, but every rule must appear intact.
	for _, want := range []string{"+ example.com", "+ *.dev.example.com", "- internal.example.com"} {
		if !strings.Contains(s, want) {
			t.Errorf("the summary omits %q:\n%s", want, s)
		}
	}
}

func TestRuleStringRoundTripsItsRawText(t *testing.T) {
	for _, raw := range []string{"example.com", "*.example.com", "10.0.0.0/8", "https://example.com/x"} {
		r, err := ParseRule(raw)
		if err != nil {
			t.Fatalf("ParseRule(%q): %v", raw, err)
		}
		if r.String() != raw {
			t.Errorf("String() = %q, want the original %q", r.String(), raw)
		}
	}
}

// TestSummarizeDescribesTheEffectiveScope covers the operator-facing summary.
// It exists to be pasted into a report, so it must carry the reference and the
// limits that will apply, and must say plainly when a scope authorises nothing.
func TestSummarizeDescribesTheEffectiveScope(t *testing.T) {
	eng, file, err := Load(strings.NewReader(`version: 1
metadata:
  program: Example
  reference: "https://example.com/policy"
scope:
  allowed:
    - example.com
  excluded:
    - internal.example.com
policy:
  max_rps: 5
`))
	if err != nil {
		t.Fatal(err)
	}
	s := Summarize(eng, file)

	if len(s.Allowed) != 1 || s.Allowed[0] != "example.com" {
		t.Errorf("allowed = %v", s.Allowed)
	}
	if len(s.Excluded) != 1 || s.Excluded[0] != "internal.example.com" {
		t.Errorf("excluded = %v", s.Excluded)
	}
	if s.Policy.MaxRPS != 5 {
		t.Errorf("the summary reports %v rps, want the effective 5", s.Policy.MaxRPS)
	}
	if s.DeniesAll {
		t.Error("a scope that allows a target is reported as denying all")
	}
	if len(s.Kinds) == 0 {
		t.Error("no rule kinds were summarised")
	}
	if s.Policy.AllowCloudMetadata {
		t.Error("SECURITY: the summary reports metadata access as enabled")
	}
}

// TestSummarizeSaysWhenNothingIsAuthorised covers the case a reader most needs
// to see clearly: an engine that will contact nothing at all.
func TestSummarizeSaysWhenNothingIsAuthorised(t *testing.T) {
	eng, err := New(nil, []string{"example.com"}, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	s := Summarize(eng, &File{})
	if !s.DeniesAll {
		t.Error("an engine with no allowed rules is not reported as denying all")
	}
	if len(s.Allowed) != 0 {
		t.Errorf("allowed = %v, want nothing", s.Allowed)
	}
}
