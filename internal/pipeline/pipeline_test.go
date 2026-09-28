package pipeline

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	httpclient "github.com/bbtoolkit/bugbounty/internal/http"
	"github.com/bbtoolkit/bugbounty/internal/recon"
	"github.com/bbtoolkit/bugbounty/internal/scope"
	"github.com/bbtoolkit/bugbounty/pkg/models"
)

var pipeNow = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func testScope(t *testing.T, passiveOnly bool) *scope.Engine {
	t.Helper()
	sc, err := scope.New([]string{"example.com", "*.example.com"}, []string{"internal.example.com"}, scope.Policy{PassiveOnly: passiveOnly})
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	return sc
}

func TestNewRejectsBadStageSets(t *testing.T) {
	ok := Stage{Name: StageHTTP, Active: true, Run: func(context.Context, Input) (Observation, error) { return Observation{}, nil }}

	if _, err := New(); !errors.Is(err, ErrNoStages) {
		t.Errorf("New() with no stages = %v, want ErrNoStages", err)
	}
	if _, err := New(Stage{Name: "not-a-stage", Run: ok.Run}); err == nil {
		t.Error("an unknown stage name was accepted")
	}
	if _, err := New(ok, ok); err == nil {
		t.Error("a duplicated stage was accepted")
	}
	if _, err := New(Stage{Name: StageHTTP}); err == nil {
		t.Error("a stage with no Run function was accepted")
	}
}

func TestStagesRunInCanonicalOrderRegardlessOfRegistration(t *testing.T) {
	// Discovery must precede the stages that act on what was discovered, and
	// the finding engine must see everything.
	noop := func(context.Context, Input) (Observation, error) { return Observation{}, nil }
	p, err := New(
		Stage{Name: StageFindings, Run: noop},
		Stage{Name: StageReport, Run: noop},
		Stage{Name: StageHTTP, Active: true, Run: noop},
		Stage{Name: StagePassiveRecon, Run: noop},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{StagePassiveRecon, StageHTTP, StageFindings, StageReport}
	got := p.StageNames()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("order = %v, want %v", got, want)
	}
}

// --- the central safety guarantee --------------------------------------------

func TestPassiveOnlyNeverRunsAnActiveStage(t *testing.T) {
	// This is the promise a passive engagement makes. An active stage running
	// even once would be a scope violation, so the check is on the stage being
	// invoked, not on the result.
	var activeRan, passiveRan bool
	p, err := New(
		Stage{Name: StagePassiveRecon, Run: func(context.Context, Input) (Observation, error) {
			passiveRan = true
			return Observation{}, nil
		}},
		Stage{Name: StageHTTP, Active: true, Run: func(context.Context, Input) (Observation, error) {
			activeRan = true
			return Observation{}, nil
		}},
		Stage{Name: StageCrawl, Active: true, Run: func(context.Context, Input) (Observation, error) {
			activeRan = true
			return Observation{}, nil
		}},
	)
	if err != nil {
		t.Fatal(err)
	}

	res := p.Run(context.Background(), Input{
		Scope:       testScope(t, true),
		Seed:        "example.com",
		PassiveOnly: true,
		Now:         pipeNow,
	}, Options{PassiveOnly: true, Now: pipeNow})

	if activeRan {
		t.Fatal("SECURITY: an active stage ran during a passive-only engagement")
	}
	if !passiveRan {
		t.Error("the passive stage did not run")
	}
	if res.Warnings == nil || !strings.Contains(strings.Join(res.Warnings, " "), "passive-only") {
		t.Errorf("the skip was not explained: %v", res.Warnings)
	}
	// Every skipped stage must be visible in the recorded state, not just in a
	// log line that a report may not include.
	skipped := map[string]bool{}
	for _, s := range res.StageStatus {
		if s.Status == "skipped" {
			skipped[s.Name] = true
			if s.Error == "" {
				t.Errorf("stage %s was skipped with no reason recorded", s.Name)
			}
		}
	}
	if !skipped[StageHTTP] || !skipped[StageCrawl] {
		t.Errorf("skipped stages = %v", skipped)
	}
}

func TestPassiveOnlyRespectsTheScopeEnginesOwnFlag(t *testing.T) {
	// The scope engine and the pipeline must agree. The scope file is the
	// artefact a client signs off on, so it can forbid contact on its own even
	// when the command line forgot the flag.
	var activeRan bool
	p, _ := New(Stage{Name: StageHTTP, Active: true, Run: func(context.Context, Input) (Observation, error) {
		activeRan = true
		return Observation{}, nil
	}})

	p.Run(context.Background(), Input{
		Scope: testScope(t, true),
		Seed:  "example.com",
		Now:   pipeNow,
	}, Options{Now: pipeNow})

	if activeRan {
		t.Fatal("SECURITY: the scope engine said passive-only and the pipeline ran an active stage anyway")
	}
}

func TestRunWithoutAScopeIsRefused(t *testing.T) {
	var ran bool
	p, _ := New(Stage{Name: StageHTTP, Active: true, Run: func(context.Context, Input) (Observation, error) {
		ran = true
		return Observation{}, nil
	}})
	res := p.Run(context.Background(), Input{Now: pipeNow}, Options{Now: pipeNow})
	if !errors.Is(res.Err, ErrNoScope) {
		t.Errorf("res.Err = %v, want ErrNoScope", res.Err)
	}
	if ran {
		t.Fatal("SECURITY: a stage ran with no scope engine at all")
	}
}

// --- failure handling --------------------------------------------------------

func TestAStageFailureBecomesAWarningAndTheRunContinues(t *testing.T) {
	// A run that could not finish must not look like a run that found nothing.
	var laterRan bool
	p, err := New(
		Stage{Name: StageHTTP, Active: true, Run: func(context.Context, Input) (Observation, error) {
			return Observation{}, errors.New("resolver refused")
		}},
		Stage{Name: StageFindings, Run: func(context.Context, Input) (Observation, error) {
			laterRan = true
			return Observation{}, nil
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	res := p.Run(context.Background(), Input{Scope: testScope(t, false), Seed: "example.com", Now: pipeNow}, Options{Now: pipeNow})

	if !laterRan {
		t.Error("a failing stage stopped the rest of the run")
	}
	joined := strings.Join(res.Warnings, " ")
	if !strings.Contains(joined, "resolver refused") {
		t.Errorf("the failure is not in the warnings: %v", res.Warnings)
	}
	var failed int
	for _, s := range res.StageStatus {
		if s.Status == "failed" {
			failed++
			if s.Error == "" {
				t.Error("a failed stage recorded no error")
			}
		}
	}
	if failed != 1 {
		t.Errorf("failed stages = %d, want 1", failed)
	}
}

func TestAPanickingStageDoesNotDestroyTheRun(t *testing.T) {
	var laterRan bool
	p, err := New(
		Stage{Name: StageHTTP, Active: true, Run: func(context.Context, Input) (Observation, error) {
			panic("index out of range")
		}},
		Stage{Name: StageFindings, Run: func(context.Context, Input) (Observation, error) {
			laterRan = true
			return Observation{}, nil
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	res := p.Run(context.Background(), Input{Scope: testScope(t, false), Seed: "example.com", Now: pipeNow}, Options{Now: pipeNow})

	if !laterRan {
		t.Error("a panicking stage stopped the rest of the run")
	}
	if !strings.Contains(strings.Join(res.Warnings, " "), "panicked") {
		t.Errorf("the panic is not reported: %v", res.Warnings)
	}
}

func TestACancelledContextStopsTheRun(t *testing.T) {
	var secondRan bool
	p, err := New(
		Stage{Name: StageHTTP, Active: true, Run: func(ctx context.Context, in Input) (Observation, error) {
			return Observation{}, ctx.Err()
		}},
		Stage{Name: StageFindings, Run: func(context.Context, Input) (Observation, error) {
			secondRan = true
			return Observation{}, nil
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res := p.Run(ctx, Input{Scope: testScope(t, false), Seed: "example.com", Now: pipeNow}, Options{Now: pipeNow})
	if secondRan {
		t.Error("a stage ran after cancellation")
	}
	if len(res.Warnings) == 0 {
		t.Error("cancellation produced no warning")
	}
}

func TestNoStageMatchIsAnError(t *testing.T) {
	p, _ := New(Stage{Name: StageHTTP, Active: true, Run: func(context.Context, Input) (Observation, error) {
		t.Error("a stage that was filtered out ran")
		return Observation{}, nil
	}})
	res := p.Run(context.Background(), Input{Scope: testScope(t, false), Now: pipeNow},
		Options{StagesToRun: []string{"no-such-stage"}, Now: pipeNow})
	if !errors.Is(res.Err, ErrNoStages) {
		t.Errorf("res.Err = %v, want ErrNoStages", res.Err)
	}
}

// --- observation flow --------------------------------------------------------

func TestObservationsFlowIntoLaterStagesAndTheFindingEngine(t *testing.T) {
	var sawHTTP bool
	p, err := New(
		Stage{Name: StageHTTP, Active: true, Run: func(context.Context, Input) (Observation, error) {
			return Observation{HTTP: []models.HTTPSvc{{
				URL: "https://example.com/", StatusCode: 200, ContentType: "text/html",
			}}}, nil
		}},
		Stage{Name: StageCrawl, Active: true, Run: func(_ context.Context, in Input) (Observation, error) {
			sawHTTP = len(in.Observed.HTTP) == 1
			return Observation{Endpoints: []models.Endpoint{{
				URL: "https://example.com/admin", Kind: models.EndpointLink,
			}}}, nil
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	res := p.Run(context.Background(), Input{Scope: testScope(t, false), Seed: "example.com", Now: pipeNow},
		Options{Now: pipeNow, ReportFormats: []string{"json"}})

	if !sawHTTP {
		t.Error("a later stage did not see the earlier stage's observations")
	}
	// The endpoint the crawl found should produce a surface finding.
	var found bool
	for _, f := range res.Findings {
		if strings.Contains(f.Endpoint, "/admin") {
			found = true
		}
	}
	if !found {
		t.Errorf("crawl output did not reach the finding engine: %+v", res.Findings)
	}
}

func TestStageWarningsTravelIntoTheReport(t *testing.T) {
	p, _ := New(Stage{Name: StageHTTP, Active: true, Run: func(context.Context, Input) (Observation, error) {
		return Observation{Warnings: []string{"probe https://example.com/: connection refused"}}, nil
	}})
	res := p.Run(context.Background(), Input{Scope: testScope(t, false), Seed: "example.com", Now: pipeNow},
		Options{Now: pipeNow, ReportFormats: []string{"markdown"}})

	body, ok := res.Reports["markdown"]
	if !ok {
		t.Fatal("no markdown report was produced")
	}
	if !strings.Contains(string(body), "connection refused") {
		t.Errorf("the stage warning is missing from the report:\n%s", body)
	}
}

func TestReportCarriesTheScopeThatWasAuthorised(t *testing.T) {
	// A report found on a disk months later must say what was permitted, or it
	// reads as consent to test something it did not cover.
	p, _ := New(Stage{Name: StagePassiveRecon, Run: func(context.Context, Input) (Observation, error) {
		return Observation{}, nil
	}})
	res := p.Run(context.Background(), Input{Scope: testScope(t, true), Seed: "example.com", Now: pipeNow},
		Options{Now: pipeNow, PassiveOnly: true, ReportFormats: []string{"markdown", "sarif"}})

	md := string(res.Reports["markdown"])
	for _, want := range []string{"example.com", "internal.example.com", "passive-only"} {
		if !strings.Contains(md, want) {
			t.Errorf("the markdown report does not mention %q", want)
		}
	}
	if !strings.Contains(string(res.Reports["sarif"]), `"passiveOnly": true`) {
		t.Error("the SARIF log does not record that the run was passive")
	}
}

func TestUnknownReportFormatBecomesAWarning(t *testing.T) {
	p, _ := New(Stage{Name: StagePassiveRecon, Run: func(context.Context, Input) (Observation, error) {
		return Observation{}, nil
	}})
	res := p.Run(context.Background(), Input{Scope: testScope(t, true), Seed: "example.com", Now: pipeNow},
		Options{Now: pipeNow, ReportFormats: []string{"postscript"}})
	if !strings.Contains(strings.Join(res.Warnings, " "), "unsupported format") {
		t.Errorf("warnings = %v", res.Warnings)
	}
}

func TestReportFormatSpellingIsNormalisedToTheKeyTheCLILooksUp(t *testing.T) {
	// report.New accepts several spellings of the same format. The CLI looks
	// the rendered report up by its lowercased name, so the pipeline has to key
	// it the same way. If the two disagree, --report Markdown renders perfectly
	// well and then reports "was not produced" -- a format the tool accepts on
	// the command line but cannot deliver to disk.
	for _, spelling := range []string{"Markdown", "MARKDOWN", "md", " md "} {
		t.Run(spelling, func(t *testing.T) {
			p, _ := New(Stage{Name: StagePassiveRecon, Run: func(context.Context, Input) (Observation, error) {
				return Observation{}, nil
			}})
			res := p.Run(context.Background(), Input{Scope: testScope(t, true), Seed: "example.com", Now: pipeNow},
				Options{Now: pipeNow, ReportFormats: []string{spelling}})

			// Exactly how cmd/bugbounty.writeReports resolves the key.
			key := strings.ToLower(strings.TrimSpace(spelling))
			body, ok := res.Reports[key]
			if !ok {
				t.Fatalf("no report stored under %q; keys = %v", key, keysOf(res.Reports))
			}
			if !strings.Contains(string(body), "example.com") {
				t.Errorf("the report keyed %q does not look like a report of this run", key)
			}
		})
	}
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// neverUsedSource satisfies the Source interface so a collector can be built
// without contacting anything. The seed-validation failure under test happens
// before a source is ever consulted.
type neverUsedSource struct{}

func (neverUsedSource) Name() string { return "test-never-used" }

func (neverUsedSource) Enumerate(context.Context, string) ([]recon.Record, error) {
	return nil, errors.New("Enumerate must not be called for a seed the collector rejects")
}

func (neverUsedSource) Available() error { return nil }

func TestPassiveReconStageDoesNotDereferenceANilResult(t *testing.T) {
	// recon.Collector.Collect returns (nil, err) when the seed fails its own
	// validation. seedDomain is far more permissive than that validation -- it
	// applies no length limit and rejects no label syntax -- so the stage can
	// legitimately be handed a domain that reaches this path.
	//
	// The result was read for its Errs slice outside the nil guard that exists
	// to protect against exactly that, so the stage panicked. Because runStage
	// recovers panics, the run did not crash, but the real reason the stage
	// failed was replaced by a panic warning, which is the one outcome the
	// pipeline's own contract forbids.
	sc := testScope(t, false)
	col, err := recon.NewCollector(sc, []recon.Source{neverUsedSource{}}, recon.Options{})
	if err != nil {
		t.Fatalf("recon.NewCollector: %v", err)
	}

	// Longer than recon.MaxNameLength, so the collector rejects the seed while
	// seedDomain still hands it through.
	seed := strings.Repeat("a", 300) + ".example.com"
	if got := seedDomain(seed); got == "" {
		t.Skip("seed reduction rejected the seed before the collector saw it")
	}

	var stage Stage
	for _, s := range DefaultStages(Dependencies{Recon: col}) {
		if s.Name == StagePassiveRecon {
			stage = s
		}
	}
	if stage.Run == nil {
		t.Fatal("no passive recon stage was built")
	}

	// Called directly, so a panic fails this test rather than being recovered
	// and reported as a warning.
	out, err := stage.Run(context.Background(), Input{Scope: sc, Seed: seed, Now: pipeNow})
	if err == nil {
		t.Fatal("an unusable seed was accepted by the collector")
	}
	if joined := strings.Join(out.Warnings, " "); strings.Contains(joined, "panicked") {
		t.Fatalf("the stage panicked instead of reporting the reason: %v", out.Warnings)
	}
}

func TestCleanRunProducesNoWarnings(t *testing.T) {
	p, _ := New(Stage{Name: StagePassiveRecon, Run: func(context.Context, Input) (Observation, error) {
		return Observation{}, nil
	}})
	res := p.Run(context.Background(), Input{Scope: testScope(t, true), Seed: "example.com", Now: pipeNow},
		Options{Now: pipeNow, PassiveOnly: true})
	if len(res.Warnings) != 0 {
		t.Errorf("a clean run produced warnings: %v", res.Warnings)
	}
}

func TestSprintSummarisesWithoutPadding(t *testing.T) {
	r := &Result{Findings: []models.Finding{
		{Severity: models.SeverityHigh},
		{Severity: models.SeverityHigh},
		{Severity: models.SeverityLow},
	}}
	if got := r.Sprint(); got != "2 high, 1 low" {
		t.Errorf("Sprint = %q", got)
	}
	if got := (&Result{}).Sprint(); got != "no findings" {
		t.Errorf("Sprint on an empty run = %q", got)
	}
}

// --- stage helpers -----------------------------------------------------------

func TestSeedDomain(t *testing.T) {
	cases := map[string]string{
		"example.com":               "example.com",
		"https://example.com/x?y=1": "example.com",
		"http://sub.example.com":    "sub.example.com",
		"EXAMPLE.COM.":              "example.com",
		"":                          "",
		"not a domain":              "not a domain",
	}
	for in, want := range cases {
		if got := seedDomain(in); got != want {
			t.Errorf("seedDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeSeedURL(t *testing.T) {
	if got := normalizeSeedURL("example.com"); got != "https://example.com" {
		t.Errorf("got %q", got)
	}
	if got := normalizeSeedURL("http://example.com"); got != "http://example.com" {
		t.Errorf("an explicit scheme was rewritten: %q", got)
	}
}

func TestProbeURLsIsBoundedAndDeduplicated(t *testing.T) {
	o := Observation{
		HTTP: []models.HTTPSvc{{URL: "https://example.com/a"}, {URL: "https://example.com/a"}},
		Endpoints: []models.Endpoint{
			{URL: "https://example.com/b"},
			{URL: "https://example.com/c"},
		},
	}
	got := o.ProbeURLs(2)
	if len(got) != 2 {
		t.Errorf("ProbeURLs = %v, want 2", got)
	}
	if got[0] != "https://example.com/a" || got[1] != "https://example.com/b" {
		t.Errorf("ProbeURLs = %v", got)
	}
}

func TestDefaultStagesMarksOnlyPassiveReconAsPassive(t *testing.T) {
	// Only the passive stage may be enabled in a passive engagement. If a new
	// stage were added without an Active marker, it would run against a target
	// the operator never agreed to touch.
	active := map[string]bool{}
	for _, s := range DefaultStages(Dependencies{}) {
		active[s.Name] = s.Active
	}
	if active[StagePassiveRecon] {
		t.Error("passive recon is marked active")
	}
	for _, name := range []string{StageDNS, StageHTTP, StageFingerprint, StageCrawl} {
		if !active[name] {
			t.Errorf("stage %q contacts the target but is not marked active", name)
		}
	}
}

func TestStagesWarnWhenAModuleIsMissing(t *testing.T) {
	// A nil dependency must produce a warning, not a panic and not silence. A
	// missing module means the run saw less than the operator asked it to.
	stages := DefaultStages(Dependencies{})
	byName := map[string]Stage{}
	for _, s := range stages {
		byName[s.Name] = s
	}
	for _, name := range []string{StagePassiveRecon, StageDNS, StageHTTP, StageFingerprint, StageCrawl} {
		out, err := byName[name].Run(context.Background(), Input{
			Scope: testScope(t, true),
			Seed:  "example.com",
			Now:   pipeNow,
		})
		if err != nil {
			t.Errorf("stage %s returned an error instead of a warning: %v", name, err)
		}
		if len(out.Warnings) == 0 {
			t.Errorf("stage %s did not warn that its module is missing", name)
		}
	}
}

func TestFirstHeaderIsCaseInsensitive(t *testing.T) {
	// Header names arrive in whatever case the server sent them, and Go does
	// not normalise map keys the way it normalises a live request.
	h := map[string][]string{"Server": {"nginx/1.18.0"}, "X-Powered-By": nil}
	if got := firstHeader(h, "SERVER"); got != "nginx/1.18.0" {
		t.Errorf("firstHeader = %q", got)
	}
	if got := firstHeader(h, "X-Powered-By"); got != "" {
		t.Errorf("an empty header returned %q", got)
	}
	if got := firstHeader(h, "Absent"); got != "" {
		t.Errorf("a missing header returned %q", got)
	}
}

func TestToHTTPSvcMapsTheFieldsTheRulesRead(t *testing.T) {
	notAfter := pipeNow.AddDate(1, 0, 0)
	svc := toHTTPSvc(&httpclient.Response{
		URL:         "https://example.com/",
		FinalURL:    "https://example.com/",
		StatusCode:  200,
		ContentType: "text/html",
		Title:       "Example",
		Header: map[string][]string{
			"Server":                  {"nginx/1.18.0"},
			"X-Powered-By":            {"PHP/8.1.2"},
			"Content-Security-Policy": {"default-src 'self'"},
		},
		TLS: &httpclient.TLSInfo{
			Version: "TLS 1.2", CipherSuite: "TLS_AES_128_GCM_SHA256",
			Issuer: "Test CA", Subject: "example.com",
			NotAfter: notAfter,
			SANs:     []string{"example.com", "www.example.com"},
		},
		Timestamp: pipeNow,
	}, pipeNow)

	if svc.Server != "nginx/1.18.0" || svc.WebServer != "PHP/8.1.2" {
		t.Errorf("server headers = %q / %q", svc.Server, svc.WebServer)
	}
	if svc.CSP == "" {
		t.Error("the CSP header was not carried over")
	}
	if svc.TLS == nil {
		t.Fatal("TLS information was lost")
	}
	if svc.TLS.Version != "TLS 1.2" || svc.TLS.Issuer != "Test CA" {
		t.Errorf("TLS = %+v", svc.TLS)
	}
	if !svc.TLS.NotAfter.Equal(notAfter) {
		t.Errorf("NotAfter = %v, want %v", svc.TLS.NotAfter, notAfter)
	}
	if !svc.Observed.Equal(pipeNow) {
		t.Errorf("Observed = %v, want the injected clock", svc.Observed)
	}
}

func TestToHTTPSvcToleratesAResponseWithNoTLS(t *testing.T) {
	// A plain HTTP response has no TLS block, and a nil dereference there would
	// take down the stage for every unencrypted host.
	svc := toHTTPSvc(&httpclient.Response{URL: "http://example.com/", StatusCode: 200}, pipeNow)
	if svc.TLS != nil {
		t.Errorf("TLS = %+v, want nil", svc.TLS)
	}
	if svc.Observed != pipeNow {
		t.Errorf("Observed = %v, want the injected clock to fill in", svc.Observed)
	}
}

func TestReconcNamesAreDeduplicated(t *testing.T) {
	o := Observation{Assets: []recon.Asset{
		{Name: "a.example.com"}, {Name: "b.example.com"}, {Name: "a.example.com"},
	}}
	got := o.dnsNames()
	if len(got) != 2 {
		t.Errorf("dnsNames = %v, want 2 distinct names", got)
	}
}
