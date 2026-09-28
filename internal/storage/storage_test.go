package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bbtoolkit/bugbounty/pkg/models"
)

func memStore(t *testing.T) *Store {
	t.Helper()
	s, err := Memory(context.Background())
	if err != nil {
		t.Fatalf("Memory: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestMemoryReleasesItsHandleWhenOpeningFails exercises the path where Memory
// cannot get a usable database and must give the handle back rather than
// abandoning it. database/sql opens a real connection behind the pool, so an
// unreleased handle keeps a live SQLite connection for the life of the process.
//
// Note the limit of what this test can assert: the leak is the absence of a
// Close on an error path, and an abandoned *sql.DB is not observable from here.
// The test pins the error behaviour and the path being taken; the fix it guards
// is the db.Close() calls in Memory, and the symmetry with Open above it is the
// thing a reviewer should read.
func TestMemoryReleasesItsHandleWhenOpeningFails(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if s, err := Memory(ctx); err == nil {
		_ = s.Close()
		t.Fatal("Memory accepted a cancelled context")
	}
	// A usable store is still openable afterwards, so the failed attempt did
	// not leave global driver state broken.
	s := memStore(t)
	if s == nil || s.Path() != ":memory:" {
		t.Errorf("a store could not be opened after a failed one: %+v", s)
	}
}

func fileStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "engagement.db")
	s, err := Open(context.Background(), Options{Path: path})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func sampleFinding(t *testing.T) models.Finding {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	return models.Finding{
		Type:        "missing-security-header",
		Title:       "Missing HSTS",
		Severity:    models.SeverityMedium,
		Confidence:  models.ConfidenceHigh,
		Asset:       "https://example.com/",
		Endpoint:    "https://example.com/login",
		Description: "why it was flagged",
		Impact:      "possible impact",
		Remediation: "set the header",
		Status:      models.StatusNew,
		Source:      "test",
		Evidence: []models.Evidence{{
			Source: "http", Summary: "no strict-transport-security header",
			Data:       map[string]string{"host": "example.com"},
			ObservedAt: now,
		}},
		FirstSeen: now,
		LastSeen:  now,
	}
}

// --- opening and migration --------------------------------------------------

func TestOpenCreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "deeper", "engagement.db")
	s, err := Open(context.Background(), Options{Path: path})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the database file was not created: %v", err)
	}
}

func TestMigrationsAreIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "e.db")
	for i := 0; i < 3; i++ {
		s, err := Open(context.Background(), Options{Path: path})
		if err != nil {
			t.Fatalf("reopen %d: %v", i, err)
		}
		v, err := s.SchemaVersion(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if v != CurrentVersion() {
			t.Errorf("schema version = %d, want %d", v, CurrentVersion())
		}
		_ = s.Close()
	}
}

func TestReadOnlyOpenRejectsMissingFile(t *testing.T) {
	_, err := Open(context.Background(), Options{
		Path:     filepath.Join(t.TempDir(), "absent.db"),
		ReadOnly: true,
	})
	if err == nil {
		t.Error("SECURITY: a read-only open created a missing database")
	}
}

func TestPathHandlingIsSafe(t *testing.T) {
	// The database path is operator configuration, not attacker input, so the
	// requirement is not "no traversal" but "a nonsensical or device-like path
	// is refused rather than silently doing something surprising".
	base := t.TempDir()
	for _, name := range []string{
		"bad\x00name.db",
		"tab\tdir/db.db",
		"newline\n.db",
		".",
		"..",
	} {
		if _, err := Open(context.Background(), Options{Path: filepath.Join(base, name)}); err == nil {
			t.Errorf("a malformed database path was accepted: %q", name)
		}
	}
	// A normal relative name inside the chosen directory still works.
	s, err := Open(context.Background(), Options{Path: filepath.Join(base, "ok.db")})
	if err != nil {
		t.Fatalf("a valid path was rejected: %v", err)
	}
	defer s.Close()
	if got := s.Path(); got == "" {
		t.Error("the store did not record its path")
	}
}

// --- findings ---------------------------------------------------------------

func TestFindingRoundTrip(t *testing.T) {
	s := memStore(t)
	ctx := context.Background()
	in := sampleFinding(t)
	got, created, err := s.UpsertFinding(ctx, in)
	if err != nil {
		t.Fatalf("UpsertFinding: %v", err)
	}
	if !created {
		t.Error("the first insert should report a creation")
	}
	if got.ID == "" {
		t.Error("no id was assigned")
	}
	if got.Fingerprint == "" {
		t.Error("no fingerprint was computed")
	}
	if len(got.Evidence) != 1 {
		t.Errorf("evidence = %d, want 1", len(got.Evidence))
	}
	if got.Evidence[0].FindingID != got.ID {
		t.Error("evidence was not linked to the finding")
	}
}

func TestFindingFingerprintIsStableAndDeduplicates(t *testing.T) {
	s := memStore(t)
	ctx := context.Background()
	a := sampleFinding(t)
	first, _, err := s.UpsertFinding(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	// Same finding seen again, later, with a different description edit: it is
	// still the same finding and must merge rather than duplicate.
	b := a
	b.Description = "a slightly different description"
	b.LastSeen = a.LastSeen.Add(time.Hour)
	second, created, err := s.UpsertFinding(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Error("an identical finding was inserted twice")
	}
	if second.ID != first.ID {
		t.Errorf("ids differ: %s vs %s", first.ID, second.ID)
	}
	all, err := s.ListFindings(ctx, FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Errorf("%d findings stored, want 1", len(all))
	}
	if !all[0].LastSeen.After(first.LastSeen) {
		t.Error("last_seen was not advanced on re-observation")
	}
}

func TestFindingEvidenceAccumulates(t *testing.T) {
	s := memStore(t)
	ctx := context.Background()
	a := sampleFinding(t)
	got, _, err := s.UpsertFinding(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	b := a
	b.Evidence = []models.Evidence{{
		Source: "dns", Summary: "a different observation of the same problem",
		Data: map[string]string{"host": "example.com"}, ObservedAt: time.Now().UTC(),
	}}
	if _, _, err := s.UpsertFinding(ctx, b); err != nil {
		t.Fatal(err)
	}
	reloaded, err := s.GetFindingByFingerprint(ctx, got.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.Evidence) != 2 {
		t.Errorf("evidence = %d, want 2 distinct observations", len(reloaded.Evidence))
	}
}

func TestFindingFilter(t *testing.T) {
	s := memStore(t)
	ctx := context.Background()
	base := sampleFinding(t)
	mustInsert := func(mut func(*models.Finding)) models.Finding {
		f := base
		f.LastSeen = time.Now().UTC()
		f.FirstSeen = f.LastSeen
		if mut != nil {
			mut(&f)
		}
		if _, _, err := s.UpsertFinding(ctx, f); err != nil {
			t.Fatal(err)
		}
		return f
	}
	mustInsert(func(f *models.Finding) { f.Type = "a"; f.Severity = models.SeverityCritical })
	mustInsert(func(f *models.Finding) {
		f.Type = "b"
		f.Severity = models.SeverityLow
		f.Status = models.StatusTriaged
	})
	mustInsert(func(f *models.Finding) { f.Type = "c"; f.Severity = models.SeverityLow })

	cases := []struct {
		name   string
		filter FindingFilter
		want   int
	}{
		{"all", FindingFilter{}, 3},
		{"by severity", FindingFilter{Severities: []models.Severity{models.SeverityCritical}}, 1},
		{"by status", FindingFilter{Statuses: []models.Status{models.StatusTriaged}}, 1},
		{"by type", FindingFilter{Types: []string{"a", "c"}}, 2},
		{"by asset", FindingFilter{Asset: "https://example.com/"}, 3},
		{"by asset miss", FindingFilter{Asset: "https://other.test/"}, 0},
		{"limit", FindingFilter{Limit: 2}, 2},
		{"offset", FindingFilter{Offset: 2}, 1},
		{"severity and type", FindingFilter{Severities: []models.Severity{models.SeverityLow}, Types: []string{"b"}}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.ListFindings(ctx, tc.filter)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != tc.want {
				t.Errorf("got %d findings, want %d", len(got), tc.want)
			}
		})
	}
}

func TestListFindingsIsOrderedBySeverity(t *testing.T) {
	s := memStore(t)
	ctx := context.Background()
	for _, sev := range []models.Severity{
		models.SeverityInformational, models.SeverityCritical, models.SeverityLow, models.SeverityHigh,
	} {
		f := sampleFinding(t)
		f.Severity = sev
		f.Type = "type-" + string(sev)
		f.FirstSeen, f.LastSeen = time.Now().UTC(), time.Now().UTC()
		if _, _, err := s.UpsertFinding(ctx, f); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.ListFindings(ctx, FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	want := []models.Severity{
		models.SeverityCritical, models.SeverityHigh, models.SeverityLow, models.SeverityInformational,
	}
	for i, sev := range want {
		if got[i].Severity != sev {
			t.Fatalf("position %d is %s, want %s", i, got[i].Severity, sev)
		}
	}
}

func TestSetFindingStatus(t *testing.T) {
	s := memStore(t)
	ctx := context.Background()
	f, _, err := s.UpsertFinding(ctx, sampleFinding(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range []models.Status{models.StatusTriaged, models.StatusFalsePositive, models.StatusResolved} {
		if err := s.SetFindingStatus(ctx, f.ID, st); err != nil {
			t.Fatalf("SetFindingStatus(%s): %v", st, err)
		}
		got, err := s.GetFindingByFingerprint(ctx, f.Fingerprint)
		if err != nil {
			t.Fatal(err)
		}
		if got.Status != st {
			t.Errorf("status = %s, want %s", got.Status, st)
		}
	}
	if err := s.SetFindingStatus(ctx, "no-such-id", models.StatusTriaged); err == nil {
		t.Error("SECURITY: a status change silently succeeded for an unknown finding")
	}
}

func TestFindingStats(t *testing.T) {
	s := memStore(t)
	ctx := context.Background()
	f := sampleFinding(t)
	f.FirstSeen, f.LastSeen = time.Now().UTC(), time.Now().UTC()
	if _, _, err := s.UpsertFinding(ctx, f); err != nil {
		t.Fatal(err)
	}
	st, err := s.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Total != 1 {
		t.Errorf("total = %d", st.Total)
	}
	if st.BySeverity[string(models.SeverityMedium)] != 1 {
		t.Errorf("by_severity = %v", st.BySeverity)
	}
}

// --- redaction at rest ------------------------------------------------------

func TestSecretsAreRedactedAtRest(t *testing.T) {
	s := memStore(t)
	ctx := context.Background()
	secret := "AKIAIOSFODNN7EXAMPLE"
	f := sampleFinding(t)
	f.Evidence = []models.Evidence{{
		Source: "http",
		Summary: "response header set-cookie: session=supersecretvalue; " +
			"x-api-key: " + secret,
		Data: map[string]string{
			"authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
			"note":          "password=hunter2",
		},
		ObservedAt: time.Now().UTC(),
	}}
	stored, _, err := s.UpsertFinding(ctx, f)
	if err != nil {
		t.Fatal(err)
	}

	// Check the raw bytes on disk, not the in-memory copy, because a redaction
	// that only happens on read still leaves the secret in the file.
	raw := readAllRows(t, s, "SELECT summary, data FROM evidence WHERE finding = ?", stored.ID)
	joined := strings.ToLower(raw)
	for _, bad := range []string{
		strings.ToLower(secret), "supersecretvalue", "hunter2", "eyjhbGciOiJiuzI1nij9",
	} {
		if strings.Contains(joined, bad) {
			t.Errorf("SECURITY: %q was written to the database verbatim", bad)
		}
	}
	if !strings.Contains(raw, "[REDACTED]") && !strings.Contains(raw, "redacted") {
		t.Error("no redaction marker was recorded, so the value was dropped rather than marked")
	}
}

func TestRedactionIsAppliedToRunEvents(t *testing.T) {
	s := memStore(t)
	ctx := context.Background()
	run := ScanRun{ID: "run-1", Name: "n", Status: RunRunning, StartedAt: time.Now().UTC()}
	if err := s.StartRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordEvent(ctx, Event{
		Run: "run-1", Level: "info", Module: "http", Event: "response",
		Data: map[string]string{"authorization": "Bearer supersecretvalue"},
	}); err != nil {
		t.Fatal(err)
	}
	raw := readAllRows(t, s, "SELECT data FROM events WHERE run = ?", "run-1")
	if strings.Contains(strings.ToLower(raw), "supersecretvalue") {
		t.Errorf("SECURITY: a secret reached the events table: %s", raw)
	}
}

// --- runs -------------------------------------------------------------------

func TestRunLifecycle(t *testing.T) {
	s := memStore(t)
	ctx := context.Background()
	run := ScanRun{
		ID: "run-1", Name: "engagement", Profile: "default",
		ScopeFile: "scope.yaml", ScopeDigest: "abc", Status: RunRunning,
		StartedAt: time.Now().UTC(),
	}
	if err := s.StartRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetRun(ctx, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "engagement" || got.ScopeDigest != "abc" {
		t.Errorf("round trip lost data: %+v", got)
	}
	if err := s.FinishRun(ctx, "run-1", RunCompleted, map[string]any{"findings": 3}); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetRun(ctx, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != RunCompleted {
		t.Errorf("status = %s", got.Status)
	}
	if got.FinishedAt.IsZero() {
		t.Error("finished_at was not set")
	}
	if !strings.Contains(got.Stats, "findings") {
		t.Errorf("stats = %q", got.Stats)
	}
}

func TestStartRunRejectsDuplicateID(t *testing.T) {
	s := memStore(t)
	ctx := context.Background()
	run := ScanRun{ID: "dup", Status: RunRunning, StartedAt: time.Now().UTC()}
	if err := s.StartRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	if err := s.StartRun(ctx, run); err == nil {
		t.Error("a duplicate run id was accepted")
	}
}

func TestStartRunRequiresID(t *testing.T) {
	s := memStore(t)
	if err := s.StartRun(context.Background(), ScanRun{Status: RunRunning}); err == nil {
		t.Error("a run without an id was accepted")
	}
}

// TestResumableRun goes through the real sequence a scan performs: start the
// run, then finish it as resumable. Building the rows by hand instead would
// leave finished_at unset and would not notice that FinishRun always stamps it.
func TestResumableRun(t *testing.T) {
	s := memStore(t)
	ctx := context.Background()

	// A completed run must not be offered for resume.
	if err := s.StartRun(ctx, ScanRun{ID: "done", Status: RunRunning, StartedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishRun(ctx, "done", RunCompleted, nil); err != nil {
		t.Fatal(err)
	}

	// A run that ended with warnings is finished, yet still resumable. This is
	// the case the pipeline actually produces, and it is the one that matters.
	if err := s.StartRun(ctx, ScanRun{ID: "open", Status: RunRunning, StartedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishRun(ctx, "open", RunResumable, map[string]any{"warnings": 2}); err != nil {
		t.Fatal(err)
	}

	got, err := s.LatestResumableRun(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "open" {
		t.Errorf("LatestResumableRun = %s, want open", got.ID)
	}
	if got.Status != RunResumable {
		t.Errorf("status = %s, want %s", got.Status, RunResumable)
	}
	// It really was finished, which is the point: the query has to find a run
	// that is both finished and resumable.
	if got.FinishedAt.IsZero() {
		t.Error("the run was not stamped as finished, so this test is not exercising the real path")
	}

	// A run still in progress is resumable too, and is the newer of the two.
	if err := s.StartRun(ctx, ScanRun{ID: "running", Status: RunRunning, StartedAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	got, err = s.LatestResumableRun(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "running" {
		t.Errorf("LatestResumableRun = %s, want the newer run", got.ID)
	}

	// The most recent resumable run wins, not the first.
	if err := s.FinishRun(ctx, "running", RunResumable, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.StartRun(ctx, ScanRun{ID: "newest", Status: RunRunning, StartedAt: time.Now().UTC().Add(2 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	got, err = s.LatestResumableRun(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "newest" {
		t.Errorf("LatestResumableRun = %s, want newest", got.ID)
	}
}

// TestLatestResumableRunReportsWhenThereIsNone covers the empty case, which is
// what a caller sees the first time it is ever asked.
func TestLatestResumableRunReportsWhenThereIsNone(t *testing.T) {
	s := memStore(t)
	ctx := context.Background()
	if err := s.StartRun(ctx, ScanRun{ID: "done", Status: RunRunning}); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishRun(ctx, "done", RunCompleted, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LatestResumableRun(ctx); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound so a caller can tell 'none' from a failure", err)
	}
}

func TestStageState(t *testing.T) {
	s := memStore(t)
	ctx := context.Background()
	if err := s.StartRun(ctx, ScanRun{ID: "r", Status: RunRunning, StartedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	rec := StageStatusRecord{
		Run: "r", Name: "crawl", Seq: 1, Status: StageRunning, StartedAt: time.Now().UTC(),
	}
	if err := s.SetStageState(ctx, rec); err != nil {
		t.Fatal(err)
	}
	rec.Status = StageCompleted
	rec.FinishedAt = time.Now().UTC()
	rec.Stats = `{"pages":10}`
	if err := s.SetStageState(ctx, rec); err != nil {
		t.Fatal(err)
	}
	states, err := s.StageStates(ctx, "r")
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 {
		t.Fatalf("%d stage records, want 1", len(states))
	}
	if states[0].Status != StageCompleted {
		t.Errorf("status = %s", states[0].Status)
	}
	if !strings.Contains(states[0].Stats, "pages") {
		t.Errorf("stats = %q", states[0].Stats)
	}
}

func TestEventsAreBounded(t *testing.T) {
	s := memStore(t)
	ctx := context.Background()
	if err := s.StartRun(ctx, ScanRun{ID: "r", Status: RunRunning, StartedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		if err := s.RecordEvent(ctx, Event{Run: "r", Module: "m", Event: "e", Data: map[string]string{"i": fmt.Sprint(i)}}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.Events(ctx, "r", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 10 {
		t.Errorf("Events limit ignored: got %d", len(got))
	}
	// The newest must come first.
	if got[0].Data["i"] != "49" {
		t.Errorf("events are not newest-first: first = %v", got[0].Data)
	}
}

// --- assets -----------------------------------------------------------------

func TestAssetUpserts(t *testing.T) {
	s := memStore(t)
	ctx := context.Background()
	domID, err := s.UpsertDomain(ctx, "example.com", "seed", map[string]string{"registrar": "x"})
	if err != nil {
		t.Fatal(err)
	}
	// Re-upserting must update, not duplicate.
	domID2, err := s.UpsertDomain(ctx, "example.com", "seed", map[string]string{"registrar": "y"})
	if err != nil {
		t.Fatal(err)
	}
	if domID != domID2 {
		t.Errorf("domain duplicated: %d vs %d", domID, domID2)
	}
	subID, err := s.UpsertSubdomain(ctx, "www.example.com", "crt", true, domID)
	if err != nil {
		t.Fatal(err)
	}
	if subID == 0 {
		t.Error("subdomain id is zero")
	}
	if _, err := s.UpsertIP(ctx, "93.184.216.34", "example.com", nil); err != nil {
		t.Fatal(err)
	}
	sum, err := s.AssetSummary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Domains != 1 || sum.Subdomains != 1 || sum.IPs != 1 {
		t.Errorf("summary = %+v", sum)
	}
}

func TestServiceAndEndpointUpserts(t *testing.T) {
	s := memStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	svc := models.HTTPSvc{
		URL: "https://example.com/", Method: "GET",
		StatusCode: 200, Title: "Home", Server: "nginx/1.24.0", Observed: time.Now().UTC(),
		Technologies: []string{"nginx 1.24.0"},
		Security:     models.SecurityHeaderReport{Missing: []string{"Strict-Transport-Security"}},
	}
	svcID, err := s.UpsertService(ctx, svc)
	if err != nil {
		t.Fatal(err)
	}
	svcID2, err := s.UpsertService(ctx, svc)
	if err != nil {
		t.Fatal(err)
	}
	if svcID != svcID2 {
		t.Error("a repeated service created a second row")
	}
	if err := s.UpsertTechnology(ctx, svcID, "nginx", "1.24.0", "web-server", string(models.ConfidenceHigh)); err != nil {
		t.Fatal(err)
	}
	epID, err := s.UpsertEndpoint(ctx, models.Endpoint{URL: "https://example.com/login", Kind: models.EndpointForm, Depth: 1}, svcID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertParameter(ctx, models.Parameter{
		Name: "user", Kind: models.ParamForm, Interesting: true, Reason: "common auth name", Observed: now,
	}, epID); err != nil {
		t.Fatal(err)
	}
	sum, err := s.AssetSummary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Services != 1 || sum.Endpoints != 1 || sum.Parameters != 1 || sum.Interesting != 1 {
		t.Errorf("summary = %+v", sum)
	}
	if sum.Technologies != 1 {
		t.Errorf("technologies = %d", sum.Technologies)
	}
}

// --- DNS and graph ----------------------------------------------------------

func TestDNSRoundTrip(t *testing.T) {
	s := memStore(t)
	ctx := context.Background()
	res := models.DNSResult{
		Name: "www.example.com", Resolved: true, Observed: time.Now().UTC(),
		Records: []models.DNSRecord{{
			Name: "www.example.com", Type: models.RecordA, Value: "93.184.216.34",
			Observed: time.Now().UTC(),
		}},
	}
	if err := s.SaveDNSResult(ctx, res); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.LoadDNSResult(ctx, "www.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("the stored result was not found")
	}
	if len(got.Records) != 1 || got.Records[0].Value != "93.184.216.34" {
		t.Errorf("round trip lost records: %+v", got.Records)
	}
}

func TestGraphRoundTrip(t *testing.T) {
	s := memStore(t)
	ctx := context.Background()
	g := models.NewGraph()
	now := time.Now().UTC()
	g.AddNode(models.Node{Kind: models.NodeDomain, Key: "example.com", Label: "example.com", First: now, Last: now})
	g.AddNode(models.Node{Kind: models.NodeIP, Key: "93.184.216.34", Label: "93.184.216.34", First: now, Last: now})
	g.AddEdge(models.Edge{
		From: models.NodeDomain, FromK: "example.com",
		Rel:   models.RelServesPort,
		To:    models.NodeIP,
		ToK:   "93.184.216.34",
		Attrs: "note",
	})
	if err := s.SaveGraph(ctx, g); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadGraph(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Nodes(models.NodeDomain)) != 1 || len(got.Nodes(models.NodeIP)) != 1 {
		t.Fatalf("graph = %v", got.Stats())
	}
	if len(got.Edges()) != 1 {
		t.Errorf("edges = %d, want 1", len(got.Edges()))
	}
}

// --- concurrency and lifecycle ---------------------------------------------

func TestConcurrentWritesAreSafe(t *testing.T) {
	s := memStore(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			f := sampleFinding(t)
			f.Type = fmt.Sprintf("type-%d", i)
			f.FirstSeen, f.LastSeen = time.Now().UTC(), time.Now().UTC()
			if _, _, err := s.UpsertFinding(ctx, f); err != nil {
				t.Errorf("concurrent insert %d: %v", i, err)
			}
			_, _ = s.ListFindings(ctx, FindingFilter{})
			_, _ = s.Stats(ctx)
		}(i)
	}
	wg.Wait()
	got, err := s.ListFindings(ctx, FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 16 {
		t.Errorf("%d findings, want 16", len(got))
	}
}

func TestHostileInputIsStoredSafely(t *testing.T) {
	s := memStore(t)
	ctx := context.Background()
	f := sampleFinding(t)
	f.Title = strings.Repeat("A", 100000)
	f.Description = "\x00\x01 control characters and \"quotes\" and 'quotes'"
	f.Evidence = []models.Evidence{{
		Source: "x", Summary: strings.Repeat("B", 100000),
		Data: map[string]string{"k": strings.Repeat("C", 50000)}, ObservedAt: time.Now().UTC(),
	}}
	if _, _, err := s.UpsertFinding(ctx, f); err != nil {
		t.Fatalf("hostile content was rejected instead of stored safely: %v", err)
	}
	got, err := s.ListFindings(ctx, FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("%d findings", len(got))
	}
	// The point is not that it round-trips byte for byte, but that nothing
	// panics, nothing is lost silently and the record is still retrievable.
	if got[0].Fingerprint == "" {
		t.Error("the fingerprint was lost")
	}
}

func TestVacuum(t *testing.T) {
	s := fileStore(t)
	if err := s.Vacuum(context.Background()); err != nil {
		t.Errorf("Vacuum: %v", err)
	}
}

func TestClosedStoreFailsCleanly(t *testing.T) {
	s, err := Memory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err == nil {
		t.Log("a second Close returned nil")
	}
	if _, _, err := s.UpsertFinding(context.Background(), sampleFinding(t)); err == nil {
		t.Error("SECURITY: a write to a closed store silently succeeded")
	}
}

// readAllRows runs a query and concatenates every scanned value, so a test can
// search the raw stored bytes for a secret.
func readAllRows(t *testing.T, s *Store, query string, args ...any) string {
	t.Helper()
	rows, err := s.DB().Query(query, args...)
	if err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		for _, v := range vals {
			switch tv := v.(type) {
			case string:
				out.WriteString(tv)
			case []byte:
				out.Write(tv)
			case int64:
				out.WriteString(fmt.Sprint(tv))
			}
			out.WriteString("\x00")
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out.String()
}
