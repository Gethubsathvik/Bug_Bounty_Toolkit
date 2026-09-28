package storage

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/bbtoolkit/bugbounty/internal/findings"
	"github.com/bbtoolkit/bugbounty/pkg/models"
)

// TestEngineOutputPersists is the seam between the finding engine and the
// store. A finding the engine produces is not worth much if the schema rejects
// it, and that mismatch only shows up here.
func TestEngineOutputPersists(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	engine := findings.DefaultEngine()

	produced, errs := engine.Evaluate(context.Background(), findings.Input{
		Asset: "example.com",
		Now:   now,
		HTTP: []models.HTTPSvc{{
			URL:         "https://example.com/login",
			StatusCode:  200,
			ContentType: "text/html",
			Server:      "nginx/1.14.0",
			Security:    models.SecurityHeaderReport{Present: map[string]string{}},
			TLS:         &models.TLSInfo{Version: "TLS 1.0", NotAfter: now.AddDate(1, 0, 0)},
		}},
		Posture:   []models.SecurityPosture{{HasMX: true}},
		Endpoints: []models.Endpoint{{URL: "https://example.com/admin", Kind: models.EndpointLink, StatusCode: 200}},
	})
	if len(errs) != 0 {
		t.Fatalf("engine errors: %v", errs)
	}
	if len(produced) < 4 {
		t.Fatalf("the engine produced only %d findings from a deliberately weak host", len(produced))
	}

	store := memStore(t)
	for _, f := range produced {
		if _, _, err := store.UpsertFinding(context.Background(), f); err != nil {
			t.Fatalf("UpsertFinding(%s): %v", f.Type, err)
		}
	}

	got, err := store.ListFindings(context.Background(), FindingFilter{})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if len(got) != len(produced) {
		t.Fatalf("stored %d findings, engine produced %d", len(got), len(produced))
	}
	for _, f := range got {
		if f.Asset != "example.com" {
			t.Errorf("finding %s has asset %q", f.Type, f.Asset)
		}
		if f.Fingerprint == "" {
			t.Errorf("finding %s lost its fingerprint in storage", f.Type)
		}
		if len(f.Evidence) == 0 {
			t.Errorf("finding %s lost its evidence in storage", f.Type)
		}
	}
}

// TestEngineOutputDeduplicatesAcrossRuns checks that a second run over the
// same host updates rather than duplicates, which is what makes re-running a
// profile useful instead of inflating the report.
func TestEngineOutputDeduplicatesAcrossRuns(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	engine := findings.DefaultEngine()
	store := memStore(t)

	for run := range 2 {
		produced, errs := engine.Evaluate(context.Background(), findings.Input{
			Asset: "example.com",
			Now:   now.Add(time.Duration(run) * 24 * time.Hour),
			HTTP: []models.HTTPSvc{{
				URL:        "https://example.com/",
				StatusCode: 200,
				Security:   models.SecurityHeaderReport{Present: map[string]string{}},
			}},
		})
		if len(errs) != 0 {
			t.Fatalf("engine errors: %v", errs)
		}
		for _, f := range produced {
			if _, _, err := store.UpsertFinding(context.Background(), f); err != nil {
				t.Fatalf("UpsertFinding: %v", err)
			}
		}
	}

	got, err := store.ListFindings(context.Background(), FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	// The second run must not have created a second copy of anything.
	if len(got) == 0 {
		t.Fatal("nothing was stored at all")
	}
	seen := map[string]int{}
	for _, f := range got {
		seen[f.Type]++
	}
	for typ, n := range seen {
		if n > 1 {
			t.Errorf("type %s was stored %d times across two identical runs", typ, n)
		}
	}
}

// TestFindingsAreScopedToTheirRun checks that a report can be limited to one
// engagement. Without the run association, every report would be the union of
// every assessment ever run from the same database, which is the wrong answer
// for a client and a confidentiality problem across clients.
func TestFindingsAreScopedToTheirRun(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	store := memStore(t)

	mk := func(id, runID, typ, asset string) models.Finding {
		f := models.Finding{
			ID: id, Fingerprint: "fp-" + id, Type: typ, Title: typ,
			Severity: models.SeverityMedium, Confidence: models.ConfidenceHigh,
			Asset: asset, Status: models.StatusNew, RunID: runID,
			FirstSeen: now, LastSeen: now,
		}
		if _, _, err := store.UpsertFinding(ctx, f); err != nil {
			t.Fatalf("UpsertFinding(%s): %v", id, err)
		}
		return f
	}
	mk("a1", "run-alpha", "http-missing-hsts", "alpha.example")
	mk("a2", "run-alpha", "tls-old-protocol", "alpha.example")
	mk("b1", "run-beta", "http-missing-csp", "beta.example")

	all, err := store.ListFindings(ctx, FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("stored %d findings, want 3", len(all))
	}

	alpha, err := store.ListFindings(ctx, FindingFilter{RunID: "run-alpha"})
	if err != nil {
		t.Fatal(err)
	}
	if len(alpha) != 2 {
		t.Fatalf("run-alpha returned %d findings, want 2", len(alpha))
	}
	for _, f := range alpha {
		if f.RunID != "run-alpha" {
			t.Errorf("the run filter let through %s from %q", f.Fingerprint, f.RunID)
		}
	}

	// A run nobody has findings for yields nothing rather than everything.
	none, err := store.ListFindings(ctx, FindingFilter{RunID: "run-gamma"})
	if err != nil {
		t.Fatal(err)
	}
	if len(none) != 0 {
		t.Errorf("an unknown run matched %d findings", len(none))
	}

	// The association must survive a reload, not merely be readable in the
	// row the insert just wrote.
	one, err := store.GetFindingByFingerprint(ctx, "fp-a1")
	if err != nil {
		t.Fatal(err)
	}
	if one.RunID != "run-alpha" {
		t.Errorf("reloaded finding has run %q, want run-alpha", one.RunID)
	}

	// Combining the run with a severity narrows further rather than widening.
	narrow, err := store.ListFindings(ctx, FindingFilter{
		RunID: "run-alpha", Severities: []models.Severity{models.SeverityMedium},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(narrow) != 2 {
		t.Errorf("the combined filter returned %d findings, want 2", len(narrow))
	}
}

// TestPersistedEvidenceIsRedacted confirms the redaction the engine performs
// survives a database round trip, so a credential reflected by the target
// cannot be recovered from the file on disk.
func TestPersistedEvidenceIsRedacted(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	rule := findings.Rule{
		ID: "reflects-secret", Title: "t",
		Severity: models.SeverityMedium, Confidence: models.ConfidenceHigh,
		Description: "d", Impact: "i",
		Check: func(context.Context, findings.Input) []findings.Result {
			return []findings.Result{{
				Summary: "target replied: api_key=AKIAIOSFODNN7EXAMPLE",
				Data:    map[string]string{"password": "hunter2"},
			}}
		},
	}
	engine, err := findings.NewEngine(rule)
	if err != nil {
		t.Fatal(err)
	}
	produced, errs := engine.Evaluate(context.Background(), findings.Input{Asset: "example.com", Now: now})
	if len(errs) != 0 {
		t.Fatalf("engine errors: %v", errs)
	}

	store := memStore(t)
	for _, f := range produced {
		if _, _, err := store.UpsertFinding(context.Background(), f); err != nil {
			t.Fatalf("UpsertFinding: %v", err)
		}
	}

	got, err := store.ListFindings(context.Background(), FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("stored %d findings, want 1", len(got))
	}
	blob := strings.Join(evidenceText(got[0]), " ")
	for _, secret := range []string{"AKIAIOSFODNN7EXAMPLE", "hunter2"} {
		if strings.Contains(blob, secret) {
			t.Errorf("SECURITY: %q survived into the database: %s", secret, blob)
		}
	}
}

func evidenceText(f models.Finding) []string {
	var out []string
	for _, ev := range f.Evidence {
		out = append(out, ev.Summary)
		for _, v := range ev.Data {
			out = append(out, v)
		}
	}
	return out
}
