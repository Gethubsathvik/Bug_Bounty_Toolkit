package findings

import (
	"strings"
	"testing"
	"time"

	"github.com/bbtoolkit/bugbounty/pkg/models"
)

func mkFinding(typ, asset, endpoint string, sev models.Severity, conf models.Confidence, at time.Time, sources ...string) models.Finding {
	f := models.Finding{
		Type:               typ,
		Title:              typ,
		Severity:           sev,
		Confidence:         conf,
		Asset:              asset,
		Endpoint:           endpoint,
		Description:        "d",
		Impact:             "i",
		Status:             models.StatusNew,
		Source:             typ,
		FirstSeen:          at,
		LastSeen:           at,
		ManualVerification: []string{"check it"},
	}
	for _, s := range sources {
		f.Evidence = append(f.Evidence, models.Evidence{
			Source:     s,
			Summary:    s + " observed this",
			ObservedAt: at,
		})
	}
	f.Fingerprint = f.ComputeFingerprint()
	f.ID = "F-" + shortID(f.Fingerprint)
	return f
}

func TestCorrelateDropsInvalidFindingsAndReportsThem(t *testing.T) {
	bad := mkFinding("t", "example.com", "", models.SeverityLow, models.ConfidenceLow, testNow, "http")
	bad.FirstSeen = time.Time{} // no timestamp: cannot be persisted

	out, errs := Correlate([]models.Finding{bad})
	if len(out) != 0 {
		t.Errorf("an invalid finding survived: %+v", out)
	}
	if len(errs) != 1 {
		t.Fatalf("errs = %v, want the drop to be reported", errs)
	}
	if !strings.Contains(errs[0].Error(), "dropping invalid finding") {
		t.Errorf("error = %v", errs[0])
	}
}

func TestCorrelateMergesDuplicates(t *testing.T) {
	low := mkFinding(RuleMissingHSTS, "example.com", "https://example.com/", models.SeverityLow, models.ConfidenceLow, testNow, "http")
	high := mkFinding(RuleMissingHSTS, "EXAMPLE.com", "https://example.com/", models.SeverityHigh, models.ConfidenceHigh, testNow.Add(time.Hour), "header-analysis")

	out, errs := Correlate([]models.Finding{low, high})
	if len(errs) != 0 {
		t.Fatalf("errs = %v", errs)
	}
	if len(out) != 1 {
		t.Fatalf("got %d findings, want the duplicates merged into 1", len(out))
	}
	f := out[0]
	if f.Severity != models.SeverityHigh || f.Confidence != models.ConfidenceHigh {
		t.Errorf("merged as %q/%q, want the most severe and most confident reading", f.Severity, f.Confidence)
	}
	if len(f.Evidence) != 2 {
		t.Errorf("evidence count = %d, want both observations kept", len(f.Evidence))
	}
	if !f.FirstSeen.Equal(testNow) {
		t.Errorf("FirstSeen = %v, want the earliest observation", f.FirstSeen)
	}
	if !f.LastSeen.Equal(testNow.Add(time.Hour)) {
		t.Errorf("LastSeen = %v, want the latest observation", f.LastSeen)
	}
}

func TestCorrelateKeepsDistinctFindingsApart(t *testing.T) {
	a := mkFinding("missing-header", "example.com", "", models.SeverityLow, models.ConfidenceLow, testNow, "http")
	a.Tags = []string{"header:csp"}
	b := mkFinding("missing-header", "example.com", "", models.SeverityLow, models.ConfidenceLow, testNow, "http")
	b.Tags = []string{"header:hsts"}

	out, _ := Correlate([]models.Finding{a, b})
	if len(out) != 2 {
		t.Fatalf("got %d findings, want 2: the tag discriminator was ignored", len(out))
	}
}

func TestCorrelateRaisesConfidenceForCorroboration(t *testing.T) {
	one := mkFinding("t", "example.com", "", models.SeverityLow, models.ConfidenceLow, testNow, "crawler")
	two := mkFinding("t", "example.com", "", models.SeverityLow, models.ConfidenceLow, testNow, "fingerprint")

	out, _ := Correlate([]models.Finding{one, two})
	if len(out) != 1 {
		t.Fatalf("got %d findings", len(out))
	}
	// Two independent modules agree, so confidence rises one step, not to the
	// top: one signal usually derives from the other.
	if out[0].Confidence != models.ConfidenceMedium {
		t.Errorf("Confidence = %q, want medium", out[0].Confidence)
	}
}

func TestCorrelateConfidenceIsCappedAtHigh(t *testing.T) {
	one := mkFinding("t", "example.com", "", models.SeverityHigh, models.ConfidenceHigh, testNow, "a", "b", "c")
	out, _ := Correlate([]models.Finding{one})
	if out[0].Confidence != models.ConfidenceHigh {
		t.Errorf("Confidence = %q, want it capped at high", out[0].Confidence)
	}
}

func TestCorrelateLowersConfidenceWithoutEvidence(t *testing.T) {
	f := mkFinding("t", "example.com", "", models.SeverityHigh, models.ConfidenceHigh, testNow)
	out, _ := Correlate([]models.Finding{f})
	if out[0].Confidence != models.ConfidenceLow {
		t.Errorf("Confidence = %q; a finding with nothing behind it must not read as certain", out[0].Confidence)
	}
}

func TestCorrelateNeverTouchesSeverity(t *testing.T) {
	// Severity is a judgement made in a rule, not arithmetic over signals.
	// An engine that raised it would turn "we saw it three ways" into "it is
	// worse", which is not a valid inference.
	one := mkFinding("t", "example.com", "", models.SeverityLow, models.ConfidenceLow, testNow, "a", "b", "c")
	out, _ := Correlate([]models.Finding{one})
	if out[0].Severity != models.SeverityLow {
		t.Errorf("Severity = %q, want it untouched at low", out[0].Severity)
	}
}

func TestCorrelateMarksManualVerificationWork(t *testing.T) {
	f := mkFinding("t", "example.com", "", models.SeverityLow, models.ConfidenceLow, testNow, "http")
	f.ManualVerificationRequired = true
	out, _ := Correlate([]models.Finding{f})
	if out[0].Status != models.StatusNeedsManual {
		t.Errorf("Status = %q, want it queued for manual verification", out[0].Status)
	}
}

func TestCorrelateBoundsEvidenceAndKeepsTheMostRecent(t *testing.T) {
	base := testNow
	f := mkFinding("t", "example.com", "", models.SeverityLow, models.ConfidenceLow, base)
	f.Evidence = nil
	for i := 0; i < MaxEvidencePerFinding*3; i++ {
		f.Evidence = append(f.Evidence, models.Evidence{
			Source:     "src",
			Summary:    "observation",
			ObservedAt: base.Add(time.Duration(i) * time.Minute),
		})
	}
	out, _ := Correlate([]models.Finding{f})
	if len(out[0].Evidence) != MaxEvidencePerFinding {
		t.Fatalf("evidence count = %d, want it bounded to %d", len(out[0].Evidence), MaxEvidencePerFinding)
	}
	latest := out[0].Evidence[len(out[0].Evidence)-1].ObservedAt
	if !latest.Equal(base.Add(time.Duration(MaxEvidencePerFinding*3-1) * time.Minute)) {
		t.Errorf("the newest evidence was dropped; last kept = %v", latest)
	}
	// Kept evidence must be in a stable order for report diffing.
	for i := 1; i < len(out[0].Evidence); i++ {
		if out[0].Evidence[i].ObservedAt.Before(out[0].Evidence[i-1].ObservedAt) {
			t.Error("kept evidence is not in chronological order")
		}
	}
}

func TestCorrelateOutputIsSortedAndDeterministic(t *testing.T) {
	in := []models.Finding{
		mkFinding("a", "b.example.com", "", models.SeverityLow, models.ConfidenceHigh, testNow, "s"),
		mkFinding("b", "a.example.com", "", models.SeverityHigh, models.ConfidenceLow, testNow, "s"),
		mkFinding("c", "c.example.com", "", models.SeverityHigh, models.ConfidenceHigh, testNow, "s"),
	}
	first, _ := Correlate(in)
	for i := 0; i < 5; i++ {
		again, _ := Correlate(in)
		if len(again) != len(first) {
			t.Fatalf("run %d produced %d findings, first produced %d", i, len(again), len(first))
		}
		for j := range first {
			if again[j].Fingerprint != first[j].Fingerprint {
				t.Fatalf("run %d differs at index %d: %s vs %s", i, j, again[j].Fingerprint, first[j].Fingerprint)
			}
		}
	}
	if first[0].Severity != models.SeverityHigh {
		t.Errorf("the highest severity finding should sort first, got %q", first[0].Severity)
	}
}

func TestCorrelateIsIdempotent(t *testing.T) {
	in := []models.Finding{
		mkFinding("a", "example.com", "", models.SeverityLow, models.ConfidenceLow, testNow, "s1"),
		mkFinding("a", "example.com", "", models.SeverityLow, models.ConfidenceLow, testNow, "s2"),
	}
	once, _ := Correlate(in)
	twice, _ := Correlate(once)
	if len(twice) != len(once) {
		t.Fatalf("correlating twice changed the count: %d then %d", len(once), len(twice))
	}
	for i := range once {
		if once[i].Fingerprint != twice[i].Fingerprint {
			t.Errorf("finding %d changed identity on a second pass", i)
		}
		if len(once[i].Evidence) != len(twice[i].Evidence) {
			t.Errorf("finding %d duplicated its evidence on a second pass: %d then %d", i, len(once[i].Evidence), len(twice[i].Evidence))
		}
	}
}

func TestCorrelateToleratesEmptyInput(t *testing.T) {
	out, errs := Correlate(nil)
	if len(out) != 0 || len(errs) != 0 {
		t.Errorf("Correlate(nil) = %v, %v", out, errs)
	}
}

func TestStampFillsMissingTimestamps(t *testing.T) {
	f := mkFinding("t", "example.com", "", models.SeverityLow, models.ConfidenceLow, time.Time{})
	stamped := Stamp([]models.Finding{f}, testNow)
	if !stamped[0].FirstSeen.Equal(testNow) || !stamped[0].LastSeen.Equal(testNow) {
		t.Errorf("timestamps = %v/%v", stamped[0].FirstSeen, stamped[0].LastSeen)
	}
}

func TestEngineOutputSurvivesCorrelation(t *testing.T) {
	// An end-to-end check that what the engine produces is actually storable,
	// since a finding that fails validation at persistence time is lost work.
	e := DefaultEngine()
	out, errs := e.Evaluate(t.Context(), Input{
		Asset: "example.com",
		Now:   testNow,
		HTTP: []models.HTTPSvc{{
			URL:         "https://example.com/login",
			StatusCode:  200,
			ContentType: "text/html",
			Server:      "nginx/1.14.0",
			Security:    models.SecurityHeaderReport{Present: map[string]string{}},
			TLS:         &models.TLSInfo{Version: "TLS 1.0", Expired: true, NotAfter: testNow.AddDate(0, -2, 0)},
		}},
		Posture: []models.SecurityPosture{{HasMX: true}},
		Endpoints: []models.Endpoint{
			{URL: "https://example.com/admin", Kind: models.EndpointLink, StatusCode: 200},
		},
	})
	if len(errs) != 0 {
		t.Fatalf("errs = %v", errs)
	}
	if len(out) < 5 {
		t.Fatalf("only %d findings from a deliberately bad host: %+v", len(out), out)
	}
	for _, f := range out {
		if err := f.Validate(); err != nil {
			t.Errorf("the engine produced a finding that will not persist (%s): %v", f.Type, err)
		}
		if f.Fingerprint == "" || f.ID == "" {
			t.Errorf("finding %s has no identity", f.Type)
		}
	}
}
