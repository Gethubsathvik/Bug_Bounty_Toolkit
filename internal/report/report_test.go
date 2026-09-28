package report

import (
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bbtoolkit/bugbounty/pkg/models"
)

var reportNow = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func sampleReport() Report {
	base := func(typ, title string, sev models.Severity, conf models.Confidence, manual bool) models.Finding {
		f := models.Finding{
			Type:        typ,
			Source:      typ,
			Title:       title,
			Severity:    sev,
			Confidence:  conf,
			Asset:       "example.com",
			Endpoint:    "https://example.com/login",
			Description: "Why it was flagged.",
			Impact:      "Possible impact.",
			Remediation: "Fix it.",
			Status:      models.StatusNew,
			Tags:        []string{"headers"},
			References:  []string{"https://example.com/ref"},
			FirstSeen:   reportNow,
			LastSeen:    reportNow,
			Evidence: []models.Evidence{{
				Source: "http", Summary: "observed", ObservedAt: reportNow,
			}},
		}
		if manual {
			f.ManualVerificationRequired = true
			f.Status = models.StatusNeedsManual
			f.ManualVerification = []string{"Open the page and confirm."}
		}
		f.Fingerprint = f.ComputeFingerprint()
		f.ID = "F-test"
		return f
	}

	return Report{
		GeneratedAt: reportNow,
		Metadata: Metadata{
			Engagement:     "Acme assessment",
			RunID:          "run-1",
			Seed:           "example.com",
			Scope:          []string{"example.com", "*.example.com"},
			Exclusions:     []string{"internal.example.com"},
			StartedAt:      reportNow.Add(-time.Hour),
			FinishedAt:     reportNow,
			PassiveOnly:    true,
			ToolkitVersion: "1.0.0",
			Warnings:       []string{"the crawler stage did not complete"},
		},
		Findings: []models.Finding{
			base("tls-certificate-expired", "Certificate expired", models.SeverityCritical, models.ConfidenceHigh, false),
			base("http-admin-surface-exposed", "Admin surface", models.SeverityInformational, models.ConfidenceLow, true),
			base("http-missing-hsts", "HSTS absent", models.SeverityLow, models.ConfidenceHigh, false),
		},
	}
}

func renderAll(t *testing.T, r Report) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, format := range Formats() {
		rd, err := New(format)
		if err != nil {
			t.Fatalf("New(%q): %v", format, err)
		}
		b, err := rd.Render(r)
		if err != nil {
			t.Fatalf("%s render: %v", format, err)
		}
		out[format] = string(b)
	}
	return out
}

func TestEveryFormatRenders(t *testing.T) {
	all := renderAll(t, sampleReport())
	for format, body := range all {
		if strings.TrimSpace(body) == "" {
			t.Errorf("%s produced an empty report", format)
		}
	}
}

func TestUnknownFormatIsRejected(t *testing.T) {
	if _, err := New("postscript"); err == nil {
		t.Fatal("an unknown format was accepted")
	} else if !strings.Contains(err.Error(), "json") {
		t.Errorf("the error should list the known formats: %v", err)
	}
}

func TestEmptyReportRendersInEveryFormat(t *testing.T) {
	// A run that found nothing must still produce a usable report, and it must
	// say plainly that an empty result is not a clean bill of health.
	all := renderAll(t, Report{Metadata: Metadata{Seed: "example.com"}, GeneratedAt: reportNow})
	for format := FormatText; format != ""; format = "" {
		break
	}
	for _, f := range []string{FormatText, FormatMarkdown, FormatHTML, FormatJSON, FormatSARIF, FormatCSV} {
		if strings.TrimSpace(all[f]) == "" {
			t.Errorf("%s produced nothing for an empty result", f)
		}
	}
	if !strings.Contains(all[FormatText], "not a clean bill of health") {
		t.Error("the text report does not explain what an empty result means")
	}
	if !strings.Contains(all[FormatMarkdown], "not a clean bill of health") {
		t.Error("the markdown report does not explain what an empty result means")
	}
}

func TestFormatMetadata(t *testing.T) {
	for _, format := range Formats() {
		rd, err := New(format)
		if err != nil {
			t.Fatal(err)
		}
		if rd.Format() != format {
			t.Errorf("%s: Format() = %q", format, rd.Format())
		}
		if !strings.HasPrefix(rd.Extension(), ".") {
			t.Errorf("%s: Extension() = %q", format, rd.Extension())
		}
		if ContentType(format) == "application/octet-stream" {
			t.Errorf("%s has no media type", format)
		}
	}
}

// --- JSON --------------------------------------------------------------------

func TestJSONIsValidAndComplete(t *testing.T) {
	body, err := JSON{}.Render(sampleReport())
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Metadata struct {
			Scope       []string `json:"scope"`
			PassiveOnly bool     `json:"passive_only"`
			Warnings    []string `json:"warnings"`
		} `json:"metadata"`
		Summary struct {
			Total       int            `json:"total"`
			NeedsManual int            `json:"needs_manual_verification"`
			BySeverity  map[string]int `json:"by_severity"`
		} `json:"summary"`
		Findings []struct {
			Type           string `json:"type"`
			Severity       string `json:"severity"`
			ManualRequired bool   `json:"manual_verification_required"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("the JSON report does not parse: %v\n%s", err, body)
	}
	if doc.Metadata.PassiveOnly != true {
		t.Error("passive_only was not recorded")
	}
	if len(doc.Metadata.Scope) != 2 {
		t.Errorf("scope = %v", doc.Metadata.Scope)
	}
	if doc.Summary.Total != 3 {
		t.Errorf("summary total = %d, want 3", doc.Summary.Total)
	}
	if doc.Summary.NeedsManual != 1 {
		t.Errorf("needs_manual = %d, want 1", doc.Summary.NeedsManual)
	}
	if doc.Summary.BySeverity["critical"] != 1 {
		t.Errorf("by_severity = %v", doc.Summary.BySeverity)
	}
	// Worst first: a reviewer opens the report and should meet the worst
	// finding immediately.
	if doc.Findings[0].Severity != "critical" {
		t.Errorf("first finding is %q, want the most severe first", doc.Findings[0].Severity)
	}
}

// --- SARIF -------------------------------------------------------------------

func TestSARIFIsWellFormed(t *testing.T) {
	body, err := SARIF{}.Render(sampleReport())
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID         string `json:"id"`
						Properties struct {
							Severity string `json:"problem.severity"`
						} `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID  string `json:"ruleId"`
				Level   string `json:"level"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
			Invocations []struct {
				ExecutionSuccessful bool `json:"executionSuccessful"`
				Properties          struct {
					PassiveOnly bool     `json:"passiveOnly"`
					Scope       []string `json:"scope"`
				} `json:"properties"`
			} `json:"invocations"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("the SARIF log does not parse: %v", err)
	}
	if doc.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", doc.Version)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(doc.Runs))
	}
	run := doc.Runs[0]
	if len(run.Results) != 3 {
		t.Fatalf("results = %d, want 3", len(run.Results))
	}
	// Every result must name a rule that is declared, or a consumer rejects
	// the log.
	declared := map[string]struct{}{}
	for _, r := range run.Tool.Driver.Rules {
		declared[r.ID] = struct{}{}
	}
	for _, res := range run.Results {
		if _, ok := declared[res.RuleID]; !ok {
			t.Errorf("result references undeclared rule %q", res.RuleID)
		}
		if res.Locations[0].PhysicalLocation.ArtifactLocation.URI == "" {
			t.Errorf("result %s has no location", res.RuleID)
		}
	}
	if run.Results[0].Level != "error" {
		t.Errorf("a critical finding mapped to level %q, want error", run.Results[0].Level)
	}
	if run.Invocations[0].Properties.PassiveOnly != true {
		t.Error("the SARIF invocation does not record that the run was passive")
	}
	// The run had a warning, so it did not complete cleanly.
	if run.Invocations[0].ExecutionSuccessful {
		t.Error("a run with warnings was marked fully successful")
	}
}

func TestSARIFLevelMapping(t *testing.T) {
	cases := map[models.Severity]string{
		models.SeverityCritical:      "error",
		models.SeverityHigh:          "error",
		models.SeverityMedium:        "warning",
		models.SeverityLow:           "note",
		models.SeverityInformational: "none",
	}
	for sev, want := range cases {
		if got := sarifLevel(sev); got != want {
			t.Errorf("sarifLevel(%q) = %q, want %q", sev, got, want)
		}
	}
}

func TestSARIFDeclaresAnUnknownRule(t *testing.T) {
	// A finding from a custom or plugin rule still has to be declared, or the
	// log is invalid.
	r := sampleReport()
	r.Findings[0].Source = "custom-plugin-check"
	r.Findings[0].Type = "custom-plugin-check"
	body, err := SARIF{}.Render(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "custom-plugin-check") {
		t.Error("the custom rule was not declared in the log")
	}
}

// --- Markdown and text -------------------------------------------------------

func TestMarkdownShowsAuthorisationBeforeFindings(t *testing.T) {
	body, err := Markdown{}.Render(sampleReport())
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)
	authIdx := strings.Index(s, "## Authorisation")
	firstFinding := strings.Index(s, "## CRITICAL")
	if authIdx < 0 || firstFinding < 0 {
		t.Fatalf("expected both sections:\n%s", s)
	}
	if authIdx > firstFinding {
		t.Error("findings appear before the authorisation section; a reader would see results before knowing what was permitted")
	}
	if !strings.Contains(s, "passive-only") {
		t.Error("the passive-only status is not stated")
	}
	if !strings.Contains(s, "not a confirmed issue") {
		t.Error("the report does not distinguish leads from confirmed issues")
	}
	if !strings.Contains(s, "internal.example.com") {
		t.Error("the exclusions are missing from the report")
	}
}

func TestMarkdownMarksManualVerification(t *testing.T) {
	body, _ := Markdown{}.Render(sampleReport())
	s := string(body)
	if !strings.Contains(s, "needs manual verification") {
		t.Error("a finding requiring manual verification is not marked as such")
	}
	if !strings.Contains(s, "To verify manually") {
		t.Error("the manual verification steps are missing")
	}
}

func TestTextSummary(t *testing.T) {
	body, err := Text{}.Render(sampleReport())
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)
	if !strings.Contains(s, "PASSIVE-ONLY ENGAGEMENT") {
		t.Error("the passive-only status is not stated")
	}
	if !strings.Contains(s, "[NEEDS MANUAL VERIFICATION]") {
		t.Error("a finding requiring manual verification is not marked")
	}
	if !strings.Contains(s, "WARNING:") {
		t.Error("the run warning is not surfaced")
	}
}

// --- CSV ---------------------------------------------------------------------

func TestCSVParsesAndHasAHeader(t *testing.T) {
	body, err := CSV{}.Render(sampleReport())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(string(body))).ReadAll()
	if err != nil {
		t.Fatalf("the CSV does not parse: %v", err)
	}
	if len(rows) != 4 {
		t.Fatalf("rows = %d, want a header plus 3 findings", len(rows))
	}
	if rows[0][0] != "id" || rows[0][1] != "severity" {
		t.Errorf("header = %v", rows[0])
	}
}

func TestCSVNeutralisesSpreadsheetFormulas(t *testing.T) {
	// Report text is attacker-influenced. A cell starting with = is a formula,
	// and it executes when the report is opened in a spreadsheet.
	r := Report{
		GeneratedAt: reportNow,
		Metadata:    Metadata{Seed: "example.com"},
		Findings: []models.Finding{{
			Type: "t", Source: "t", Title: `=cmd|'/c calc'!A1`,
			Severity: models.SeverityLow, Confidence: models.ConfidenceLow,
			Asset: "example.com", Status: models.StatusNew,
			FirstSeen: reportNow, LastSeen: reportNow,
		}},
	}
	body, err := CSV{}.Render(r)
	if err != nil {
		t.Fatal(err)
	}
	rows, _ := csv.NewReader(strings.NewReader(string(body))).ReadAll()
	title := rows[1][7]
	if !strings.HasPrefix(title, "'") {
		t.Errorf("SECURITY: a formula was left live in the CSV: %q", title)
	}
}

func TestCSVSafeLeavesOrdinaryTextAlone(t *testing.T) {
	if got := csvSafe("a normal title"); got != "a normal title" {
		t.Errorf("csvSafe altered ordinary text: %q", got)
	}
	if got := csvSafe("50% of hosts"); got != "50% of hosts" {
		t.Errorf("csvSafe altered ordinary text: %q", got)
	}
	if got := csvSafe(""); got != "" {
		t.Errorf("csvSafe altered empty text: %q", got)
	}
	// A leading hyphen is ambiguous: a spreadsheet may read it as a formula or
	// as a negative number. Erring toward escaping costs one stray apostrophe;
	// getting it wrong executes code in the reviewer's spreadsheet.
	for _, s := range []string{"=1+1", "+1", "-1", "@SUM(A1)", "\tX"} {
		if got := csvSafe(s); !strings.HasPrefix(got, "'") {
			t.Errorf("csvSafe(%q) = %q, want it neutralised", s, got)
		}
	}
}

// --- injection resistance ----------------------------------------------------

// hostileFinding returns a finding whose every text field is attacker-chosen.
func hostileFinding(payload string) models.Finding {
	f := models.Finding{
		Type: "t", Source: "t",
		Title:      payload,
		Severity:   models.SeverityLow,
		Confidence: models.ConfidenceLow,
		Asset:      payload,
		Endpoint:   "https://example.com/?token=" + payload,
		// An API key reflected back by the target.
		Description: "server said api_key=AKIAIOSFODNN7EXAMPLE " + payload,
		Impact:      payload,
		Remediation: payload,
		References:  []string{payload},
		Tags:        []string{payload},
		Status:      models.StatusNew,
		FirstSeen:   reportNow,
		LastSeen:    reportNow,
		Evidence: []models.Evidence{{
			Source: payload, Summary: "token=ghp_0123456789abcdefghijklmnop " + payload,
			Data: map[string]string{"password": payload}, ObservedAt: reportNow,
		}},
	}
	f.Fingerprint = f.ComputeFingerprint()
	f.ID = "F-hostile"
	return f
}

func TestNoFormatLeaksAReflectedCredential(t *testing.T) {
	payloads := []string{
		"AKIAIOSFODNN7EXAMPLE",
		"ghp_0123456789abcdefghijklmnopqrstuvwx",
		"password=hunter2",
		"token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop",
	}
	for _, payload := range payloads {
		r := Report{
			GeneratedAt: reportNow,
			Metadata:    Metadata{Seed: "example.com", Scope: []string{"example.com"}},
			Findings:    []models.Finding{hostileFinding(payload)},
		}
		for format, body := range renderAll(t, r) {
			if strings.Contains(body, payload) {
				t.Errorf("SECURITY: %s leaked the reflected value %q\n%s", format, payload, body)
			}
		}
	}
}

func TestMarkdownEscapesFormattingCharacters(t *testing.T) {
	// A target that reflects text into a title must not be able to rewrite
	// the structure of the report.
	payload := "# Injected heading\n\n- fake finding\n[link](https://evil.example)\n`code`"
	r := Report{
		GeneratedAt: reportNow,
		Metadata:    Metadata{Seed: "example.com"},
		Findings:    []models.Finding{hostileFinding(payload)},
	}
	body, err := Markdown{}.Render(r)
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)
	// A real heading from the template is there; the injected one is not.
	if strings.Count(s, "\n# ") > 1 {
		t.Errorf("the report gained a top-level heading from reflected text:\n%s", s)
	}
	if strings.Contains(s, "[link](https://evil.example)") {
		t.Errorf("an unescaped Markdown link survived:\n%s", s)
	}
}

func TestHTMLIsSelfContainedAndEscaped(t *testing.T) {
	r := Report{
		GeneratedAt: reportNow,
		Metadata:    Metadata{Seed: "example.com"},
		Findings:    []models.Finding{hostileFinding(`<script>alert(1)</script>`)},
	}
	body, err := HTML{}.Render(r)
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)
	if strings.Contains(s, "<script>alert(1)</script>") {
		t.Errorf("SECURITY: unescaped script survived into the HTML report:\n%s", s)
	}
	if !strings.Contains(s, "&lt;script&gt;") {
		t.Error("the script was not escaped at all")
	}
	// A security report gets emailed around; it must not carry anything that
	// executes or phones home.
	if strings.Contains(s, "<script") && !strings.Contains(s, "no script") {
		t.Error("the report contains a script element")
	}
	if strings.Contains(s, "http://") || strings.Contains(s, "https://cdn") {
		t.Error("the report references an external resource")
	}
	if !strings.Contains(s, `content="no-referrer"`) {
		t.Error("the report does not suppress referrer leakage")
	}
}

func TestHTMLContainsNoExternalResource(t *testing.T) {
	body, err := HTML{}.Render(sampleReport())
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)
	for _, bad := range []string{"<script", "<iframe", "src=\"http", "href=\"http", "@import", "onload="} {
		if strings.Contains(s, bad) {
			t.Errorf("the HTML report contains %q", bad)
		}
	}
}

// --- determinism and bounds --------------------------------------------------

func TestRenderingIsDeterministic(t *testing.T) {
	r := sampleReport()
	first, err := JSON{}.Render(r)
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		again, err := JSON{}.Render(r)
		if err != nil {
			t.Fatal(err)
		}
		if string(again) != string(first) {
			t.Fatal("two renders of the same report differ")
		}
	}
}

func TestSummaryCountsCannotDisagreeWithTheFindings(t *testing.T) {
	r := Report{Findings: sampleReport().Findings}
	s := r.Summary()
	if s.Total != len(r.Findings) {
		t.Errorf("Summary reports %d findings but the report carries %d", s.Total, len(r.Findings))
	}
	counted := 0
	for _, n := range s.BySeverity {
		counted += n
	}
	if counted != s.Total {
		t.Errorf("severity counts sum to %d, want %d", counted, s.Total)
	}
}

func TestCSVHandlesAFieldContainingNewlines(t *testing.T) {
	r := Report{
		GeneratedAt: reportNow,
		Findings:    []models.Finding{hostileFinding("line one\nline two")},
	}
	body, err := CSV{}.Render(r)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(string(body))).ReadAll()
	if err != nil {
		t.Fatalf("a quoted newline broke the CSV: %v", err)
	}
	if len(rows) != 2 {
		t.Errorf("rows = %d, want a header and one finding", len(rows))
	}
}
