package models

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// --- severity ----------------------------------------------------------------

// TestSeverityRankingIsTotalAndOrdered checks the ordering every report, every
// sort and the storage layer's ORDER BY rely on. If the ranks were not
// monotonic, a critical finding could sort below an informational one.
func TestSeverityRankingIsTotalAndOrdered(t *testing.T) {
	ordered := []Severity{
		SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInformational,
	}
	for i, s := range ordered {
		if !s.Valid() {
			t.Errorf("%q is not valid", s)
		}
		if s.SeverityRank() != 5-i {
			t.Errorf("%q ranked %d, want %d", s, s.SeverityRank(), 5-i)
		}
	}

	// An unknown severity must sort below every real one rather than panic or
	// sort as if it were critical.
	for _, bogus := range []Severity{"", "severe", "CRITICAL ", "0", "null"} {
		if bogus.Valid() {
			t.Errorf("%q was accepted as a valid severity", bogus)
		}
		if bogus.SeverityRank() >= SeverityInformational.SeverityRank() {
			t.Errorf("%q ranked %d, below informational (%d) is required",
				bogus, bogus.SeverityRank(), SeverityInformational.SeverityRank())
		}
	}
}

func TestParseSeverity(t *testing.T) {
	// The CLI takes this from a user, so the common spellings have to work and
	// nonsense has to be refused rather than defaulted to something severe.
	for in, want := range map[string]Severity{
		"critical": SeverityCritical, "CRITICAL": SeverityCritical, " crit ": SeverityCritical,
		"high": SeverityHigh, "HIGH": SeverityHigh,
		"medium": SeverityMedium, "med": SeverityMedium,
		"low":  SeverityLow,
		"info": SeverityInformational, "informational": SeverityInformational,
		"none": SeverityInformational,
	} {
		got, ok := ParseSeverity(in)
		if !ok {
			t.Errorf("ParseSeverity(%q) refused a valid value", in)
			continue
		}
		if got != want {
			t.Errorf("ParseSeverity(%q) = %q, want %q", in, got, want)
		}
	}

	for _, bad := range []string{"", "  ", "severe", "moderate", "3", "info!"} {
		if got, ok := ParseSeverity(bad); ok {
			t.Errorf("ParseSeverity(%q) accepted %q", bad, got)
		}
	}
}

func TestConfidenceRanking(t *testing.T) {
	if ConfidenceHigh.ConfidenceRank() <= ConfidenceMedium.ConfidenceRank() {
		t.Error("high confidence does not outrank medium")
	}
	if ConfidenceMedium.ConfidenceRank() <= ConfidenceLow.ConfidenceRank() {
		t.Error("medium confidence does not outrank low")
	}
	for _, c := range []Confidence{"", "certain", "HIGH "} {
		if c.Valid() {
			t.Errorf("%q was accepted as valid confidence", c)
		}
	}

	for in, want := range map[string]Confidence{
		"high": ConfidenceHigh, "strong": ConfidenceHigh,
		"medium": ConfidenceMedium, "med": ConfidenceMedium, "moderate": ConfidenceMedium,
		"low": ConfidenceLow, "weak": ConfidenceLow,
	} {
		got, ok := ParseConfidence(in)
		if !ok || got != want {
			t.Errorf("ParseConfidence(%q) = %q,%v want %q", in, got, ok, want)
		}
	}
	if _, ok := ParseConfidence("certain"); ok {
		t.Error("an unknown confidence was accepted")
	}
}

func TestStatusValidity(t *testing.T) {
	for _, s := range []Status{StatusNew, StatusTriaged, StatusNeedsManual, StatusFalsePositive, StatusResolved} {
		if !s.Valid() {
			t.Errorf("%q is not valid", s)
		}
	}
	for _, s := range []Status{"", "open", "New", "done"} {
		if s.Valid() {
			t.Errorf("%q was accepted as a valid status", s)
		}
	}
}

// --- findings ----------------------------------------------------------------

func validFinding() Finding {
	return Finding{
		ID: "f1", Type: "http-missing-hsts", Title: "HSTS missing",
		Severity: SeverityMedium, Confidence: ConfidenceHigh, Status: StatusNew,
		Asset: "example.com", FirstSeen: time.Now(),
	}
}

func TestFindingValidate(t *testing.T) {
	good := validFinding()
	if err := good.Validate(); err != nil {
		t.Fatalf("a valid finding was rejected: %v", err)
	}

	// Each missing invariant must be caught, because bad data must never reach
	// the database.
	cases := map[string]func(*Finding){
		"no id":          func(f *Finding) { f.ID = "  " },
		"no type":        func(f *Finding) { f.Type = "" },
		"bad severity":   func(f *Finding) { f.Severity = "severe" },
		"bad confidence": func(f *Finding) { f.Confidence = "certain" },
		"no first seen":  func(f *Finding) { f.FirstSeen = time.Time{} },
		"no steps to verify a finding that needs them": func(f *Finding) { f.ManualVerificationRequired = true },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := validFinding()
			mutate(&f)
			if err := f.Validate(); err == nil {
				t.Error("an invalid finding passed validation")
			}
		})
	}

	// An unknown status is defaulted rather than rejected, because a new status
	// from a newer build should not make a run fail to persist.
	f := validFinding()
	f.Status = "invented"
	if err := f.Validate(); err != nil {
		t.Fatalf("an unknown status was rejected: %v", err)
	}
	if f.Status != StatusNew {
		t.Errorf("status = %q, want it defaulted to %q", f.Status, StatusNew)
	}

	// A missing last-seen is backfilled from first-seen rather than rejected.
	f2 := validFinding()
	if err := f2.Validate(); err != nil {
		t.Fatal(err)
	}
	if !f2.LastSeen.Equal(f2.FirstSeen) {
		t.Errorf("last seen = %v, want it backfilled to %v", f2.LastSeen, f2.FirstSeen)
	}
}

// TestFingerprintIsStableAndDiscriminating covers the dedup key. It has to be
// stable across runs so a re-scan updates rather than duplicates, and it has to
// separate findings that differ in any of its inputs so two real problems on one
// host do not collapse into one.
func TestFingerprintIsStableAndDiscriminating(t *testing.T) {
	base := validFinding()
	first := base.ComputeFingerprint()

	if again := base.ComputeFingerprint(); again != first {
		t.Error("the fingerprint is not stable across calls")
	}

	// Case must not change identity, or a re-scan would duplicate everything.
	upper := base
	upper.Type = "HTTP-MISSING-HSTS"
	upper.Asset = "EXAMPLE.COM"
	if got := upper.ComputeFingerprint(); got != first {
		t.Error("case changed the fingerprint, so a re-scan would duplicate findings")
	}

	// Each input must actually discriminate.
	for name, mutate := range map[string]func(*Finding){
		"type":     func(f *Finding) { f.Type = "tls-old-protocol" },
		"asset":    func(f *Finding) { f.Asset = "other.example" },
		"endpoint": func(f *Finding) { f.Endpoint = "https://example.com/x" },
		"tag":      func(f *Finding) { f.Tags = []string{"strict-transport-security"} },
	} {
		t.Run(name, func(t *testing.T) {
			f := base
			mutate(&f)
			if f.ComputeFingerprint() == first {
				t.Errorf("changing the %s did not change the fingerprint", name)
			}
		})
	}

	// Two findings that differ only in severity are the same finding observed
	// at different confidence, and must not be stored twice.
	sev := base
	sev.Severity = SeverityCritical
	if sev.ComputeFingerprint() != first {
		t.Error("severity changed the fingerprint, so one finding would be stored many times")
	}
}

func TestSortFindingsOrdersBySeverityThenConfidenceThenAsset(t *testing.T) {
	mk := func(sev Severity, conf Confidence, asset string) Finding {
		return Finding{Severity: sev, Confidence: conf, Asset: asset}
	}
	in := []Finding{
		mk(SeverityLow, ConfidenceHigh, "a"),
		mk(SeverityCritical, ConfidenceLow, "z"),
		mk(SeverityHigh, ConfidenceHigh, "b"),
		mk(SeverityCritical, ConfidenceHigh, "a"),
		mk(SeverityMedium, ConfidenceMedium, "c"),
	}
	SortFindings(in)

	want := []string{
		"critical/a", "critical/z", "high/b", "medium/c", "low/a",
	}
	for i, w := range want {
		got := string(in[i].Severity) + "/" + in[i].Asset
		if got != w {
			t.Errorf("position %d = %s, want %s", i, got, w)
		}
	}
}

func TestSortParamsIsDeterministic(t *testing.T) {
	in := []Parameter{
		{Kind: ParamQuery, URL: "https://b", Name: "z"},
		{Kind: ParamForm, URL: "https://a", Name: "a"},
		{Kind: ParamQuery, URL: "https://a", Name: "b"},
		{Kind: ParamQuery, URL: "https://a", Name: "a"},
	}
	SortParams(in)

	want := []string{
		"form/https://a/a", "query/https://a/a", "query/https://a/b", "query/https://b/z",
	}
	for i, w := range want {
		got := string(in[i].Kind) + "/" + in[i].URL + "/" + in[i].Name
		if got != w {
			t.Errorf("position %d = %s, want %s", i, got, w)
		}
	}
}

// --- targets -----------------------------------------------------------------

// TestTargetCloneIsDeep covers the guarantee a caller relies on when it hands a
// target to a stage that runs concurrently: mutating the clone must not reach
// back into the original.
func TestTargetCloneIsDeep(t *testing.T) {
	orig := Target{
		Kind: TargetDomain, Value: "example.com",
		Meta: map[string]string{"a": "1"},
		Refs: map[string][]string{"host": {"h1"}},
	}
	c := orig.Clone()

	c.Meta["a"] = "changed"
	c.Meta["new"] = "x"
	c.Refs["host"][0] = "changed"
	c.Refs["other"] = []string{"z"}

	if orig.Meta["a"] != "1" {
		t.Error("mutating the clone changed the original's meta")
	}
	if _, ok := orig.Meta["new"]; ok {
		t.Error("adding a key to the clone changed the original")
	}
	if orig.Refs["host"][0] != "h1" {
		t.Error("mutating a cloned slice changed the original")
	}
	if _, ok := orig.Refs["other"]; ok {
		t.Error("adding a key to the clone changed the original")
	}

	// A nil map must stay usable rather than panicking.
	var empty Target
	if got := empty.Clone(); got.Meta != nil {
		t.Errorf("cloning a zero target produced meta: %v", got.Meta)
	}
}

// --- DNS ---------------------------------------------------------------------

func TestRecordTypeValidity(t *testing.T) {
	for _, r := range AllRecordTypes {
		if !r.Valid() {
			t.Errorf("%q in AllRecordTypes is not valid", r)
		}
	}
	if RecordPTR.Valid() == false || RecordSRV.Valid() == false {
		t.Error("a defined record type was reported invalid")
	}
	for _, r := range []RecordType{"", "HTTPS", "a", "ANY"} {
		if r.Valid() {
			t.Errorf("%q was accepted as a record type", r)
		}
	}
}

// TestRecordHashIsCaseInsensitive covers the dedup key for DNS answers. A
// resolver is free to return a differently-cased name, and treating that as a
// new record would inflate a report with duplicates.
func TestRecordHashIsCaseInsensitive(t *testing.T) {
	a := DNSRecord{Name: "WWW.Example.COM", Type: RecordCNAME, Value: "CDN.Example.NET"}
	b := DNSRecord{Name: "www.example.com", Type: RecordCNAME, Value: "cdn.example.net"}
	if a.RecordHash() != b.RecordHash() {
		t.Error("case changed the record hash, so one answer would be recorded twice")
	}

	diff := DNSRecord{Name: "www.example.com", Type: RecordA, Value: "cdn.example.net"}
	if diff.RecordHash() == a.RecordHash() {
		t.Error("a different record type produced the same hash")
	}
	other := DNSRecord{Name: "www.example.com", Type: RecordCNAME, Value: "other.example.net"}
	if other.RecordHash() == a.RecordHash() {
		t.Error("a different value produced the same hash")
	}
}

func TestParamFingerprintDiscriminates(t *testing.T) {
	base := Parameter{Kind: ParamQuery, Name: "id", URL: "https://example.com/a"}
	first := base.ParamFingerprint()

	if base.ParamFingerprint() != first {
		t.Error("the parameter fingerprint is not stable")
	}
	for name, mutate := range map[string]func(*Parameter){
		"kind": func(p *Parameter) { p.Kind = ParamForm },
		"name": func(p *Parameter) { p.Name = "q" },
		"url":  func(p *Parameter) { p.URL = "https://example.com/b" },
	} {
		p := base
		mutate(&p)
		if p.ParamFingerprint() == first {
			t.Errorf("changing the %s did not change the parameter fingerprint", name)
		}
	}
}

// --- graph -------------------------------------------------------------------

func TestGraphNodeMerging(t *testing.T) {
	g := NewGraph()
	early := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	late := early.AddDate(0, 1, 0)

	g.AddNode(Node{Kind: NodeService, Key: "a", Label: "first", First: early, Last: early,
		Attrs: map[string]string{"ip": "1.1.1.1"}})
	g.AddNode(Node{Kind: NodeService, Key: "a", Label: "second", First: late, Last: late,
		Attrs: map[string]string{"ip": "9.9.9.9", "extra": "x"}})

	nodes := g.Nodes(NodeService)
	if len(nodes) != 1 {
		t.Fatalf("the same node was stored %d times", len(nodes))
	}
	n := nodes[0]
	if !n.First.Equal(early) || !n.Last.Equal(late) {
		t.Errorf("first/last = %v/%v, want %v/%v", n.First, n.Last, early, late)
	}
	if n.Label != "first" {
		t.Errorf("label = %q, a later observation overwrote the earlier label", n.Label)
	}
	if n.Attrs["ip"] != "1.1.1.1" {
		t.Errorf("ip = %q, a later observation overwrote a known attribute", n.Attrs["ip"])
	}
	if n.Attrs["extra"] != "x" {
		t.Error("a genuinely new attribute was dropped")
	}
}

func TestGraphKindsAreDistinct(t *testing.T) {
	g := NewGraph()
	g.AddNode(Node{Kind: NodeService, Key: "shared"})
	g.AddNode(Node{Kind: NodeEndpoint, Key: "shared"})

	if g.Len() != 2 {
		t.Errorf("two nodes with different kinds collapsed into %d", g.Len())
	}
	if len(g.Nodes(NodeService)) != 1 || len(g.Nodes(NodeEndpoint)) != 1 {
		t.Error("Nodes returned the wrong set for a kind")
	}
	if len(g.Nodes("")) != 2 {
		t.Error("Nodes with no kind should return everything")
	}
}

func TestGraphRejectsIncompleteInput(t *testing.T) {
	g := NewGraph()
	g.AddNode(Node{Kind: "", Key: "a"})
	g.AddNode(Node{Kind: NodeService, Key: "  "})
	if g.Len() != 0 {
		t.Errorf("an invalid node was stored: %d nodes", g.Len())
	}

	g.AddEdge(Edge{})
	g.AddEdge(Edge{From: NodeService, Rel: "has"})
	g.AddEdge(Edge{From: NodeService, To: NodeEndpoint})
	if len(g.Edges()) != 0 {
		t.Errorf("an incomplete edge was stored: %v", g.Edges())
	}
}

func TestGraphEdgeDedupAndOrder(t *testing.T) {
	g := NewGraph()
	g.AddEdge(Edge{From: NodeService, FromK: "b", Rel: "has", To: NodeEndpoint, ToK: "2"})
	g.AddEdge(Edge{From: NodeService, FromK: "a", Rel: "has", To: NodeEndpoint, ToK: "1"})
	g.AddEdge(Edge{From: NodeService, FromK: "a", Rel: "has", To: NodeEndpoint, ToK: "1"})

	edges := g.Edges()
	if len(edges) != 2 {
		t.Fatalf("%d edges stored, want 2 after deduplication", len(edges))
	}
	if edges[0].FromK != "a" || edges[1].FromK != "b" {
		t.Errorf("edges are not in a deterministic order: %+v", edges)
	}
}

func TestGraphStats(t *testing.T) {
	g := NewGraph()
	g.AddNode(Node{Kind: NodeService, Key: "a"})
	g.AddNode(Node{Kind: NodeService, Key: "b"})
	g.AddNode(Node{Kind: NodeEndpoint, Key: "c"})

	stats := g.Stats()
	if stats[NodeService] != 2 || stats[NodeEndpoint] != 1 {
		t.Errorf("stats = %v, want 2 hosts and 1 endpoint", stats)
	}
	if len(stats) != 2 {
		t.Errorf("stats reported %d kinds, want 2", len(stats))
	}
}

// --- errors ------------------------------------------------------------------

// TestSentinelErrorsAreDistinct guards against a copy-paste that collapses two
// distinct failure modes into one, which would make a caller report the wrong
// reason for a refusal.
func TestSentinelErrorsAreDistinct(t *testing.T) {
	all := []error{
		ErrFindingNoID, ErrFindingNoType, ErrFindingBadSeverity,
		ErrFindingBadConfidence, ErrFindingNoFirstSeen, ErrFindingNoVerificationSteps,
	}
	for i, a := range all {
		if a == nil {
			t.Fatalf("error %d is nil", i)
		}
		if a.Error() == "" {
			t.Errorf("error %d has no message", i)
		}
		for j, b := range all {
			if i != j && errors.Is(a, b) {
				t.Errorf("errors %d and %d are the same value: %v", i, j, a)
			}
		}
		if !strings.Contains(a.Error(), "finding") {
			t.Errorf("error %d does not identify itself as a finding problem: %v", i, a)
		}
	}
}
