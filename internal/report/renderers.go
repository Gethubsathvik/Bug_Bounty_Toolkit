package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bbtoolkit/bugbounty/pkg/models"
)

// --- JSON --------------------------------------------------------------------

// jsonReport is the stable machine-readable shape. It is a declared struct
// rather than the models directly so that adding a field to a model does not
// silently change the report contract.
type jsonReport struct {
	Tool     string        `json:"tool"`
	Version  string        `json:"version,omitempty"`
	Metadata jsonMetadata  `json:"metadata"`
	Summary  jsonSummary   `json:"summary"`
	Findings []jsonFinding `json:"findings"`
}

type jsonMetadata struct {
	Engagement  string     `json:"engagement,omitempty"`
	RunID       string     `json:"run_id,omitempty"`
	Seed        string     `json:"seed,omitempty"`
	Scope       []string   `json:"scope"`
	Exclusions  []string   `json:"exclusions"`
	PassiveOnly bool       `json:"passive_only"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
	Duration    string     `json:"duration,omitempty"`
	Warnings    []string   `json:"warnings"`
	GeneratedAt time.Time  `json:"generated_at"`
}

type jsonSummary struct {
	Total       int            `json:"total"`
	NeedsManual int            `json:"needs_manual_verification"`
	BySeverity  map[string]int `json:"by_severity"`
	ByStatus    map[string]int `json:"by_status"`
}

type jsonFinding struct {
	ID                 string         `json:"id"`
	Fingerprint        string         `json:"fingerprint"`
	Type               string         `json:"type"`
	Title              string         `json:"title"`
	Severity           string         `json:"severity"`
	Confidence         string         `json:"confidence"`
	Asset              string         `json:"asset"`
	Endpoint           string         `json:"endpoint,omitempty"`
	Description        string         `json:"description"`
	Impact             string         `json:"possible_impact"`
	Remediation        string         `json:"remediation,omitempty"`
	References         []string       `json:"references,omitempty"`
	ManualVerification []string       `json:"manual_verification_steps,omitempty"`
	ManualRequired     bool           `json:"manual_verification_required"`
	Status             string         `json:"status"`
	Tags               []string       `json:"tags,omitempty"`
	Source             string         `json:"source"`
	FirstSeen          time.Time      `json:"first_seen"`
	LastSeen           time.Time      `json:"last_seen"`
	Evidence           []jsonEvidence `json:"evidence,omitempty"`
}

type jsonEvidence struct {
	Source     string            `json:"source"`
	Summary    string            `json:"summary"`
	Data       map[string]string `json:"data,omitempty"`
	Redacted   bool              `json:"redacted,omitempty"`
	ObservedAt time.Time         `json:"observed_at"`
}

// JSON renders the machine-readable report.
type JSON struct{}

func (JSON) Format() string    { return FormatJSON }
func (JSON) Extension() string { return ".json" }

func (JSON) Render(r Report) ([]byte, error) {
	s := r.Summary()
	out := jsonReport{
		Tool:    "bugbounty-toolkit",
		Version: r.Metadata.ToolkitVersion,
		Metadata: jsonMetadata{
			Engagement:  safe(r.Metadata.Engagement),
			RunID:       safe(r.Metadata.RunID),
			Seed:        safe(r.Metadata.Seed),
			Scope:       dedupeSorted(r.Metadata.Scope),
			Exclusions:  dedupeSorted(r.Metadata.Exclusions),
			PassiveOnly: r.Metadata.PassiveOnly,
			StartedAt:   optTime(r.Metadata.StartedAt),
			FinishedAt:  optTime(r.Metadata.FinishedAt),
			Duration:    formatDuration(r.Metadata.FinishedAt.Sub(r.Metadata.StartedAt)),
			Warnings:    redactStringSlice(r.Metadata.Warnings),
			GeneratedAt: generatedAt(r),
		},
		Summary: jsonSummary{
			Total:       s.Total,
			NeedsManual: s.NeedsManual,
			BySeverity:  severityCounts(s),
			ByStatus:    statusCounts(s),
		},
		Findings: []jsonFinding{},
	}
	for _, f := range sortFindings(r.Findings) {
		out.Findings = append(out.Findings, toJSONFinding(f))
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return nil, fmt.Errorf("report: encoding json: %w", err)
	}
	return buf.Bytes(), nil
}

func toJSONFinding(f models.Finding) jsonFinding {
	out := jsonFinding{
		ID:                 safe(f.ID),
		Fingerprint:        safe(f.Fingerprint),
		Type:               safe(f.Type),
		Title:              safe(f.Title),
		Severity:           string(f.Severity),
		Confidence:         string(f.Confidence),
		Asset:              safe(f.Asset),
		Endpoint:           safe(f.Endpoint),
		Description:        safe(f.Description),
		Impact:             safe(f.Impact),
		Remediation:        safe(f.Remediation),
		References:         redactStringSlice(f.References),
		ManualVerification: redactStringSlice(f.ManualVerification),
		ManualRequired:     f.ManualVerificationRequired,
		Status:             string(f.Status),
		Tags:               redactStringSlice(f.Tags),
		Source:             safe(f.Source),
		FirstSeen:          f.FirstSeen,
		LastSeen:           f.LastSeen,
		Evidence:           []jsonEvidence{},
	}
	for _, ev := range f.Evidence {
		out.Evidence = append(out.Evidence, jsonEvidence{
			Source:     safe(ev.Source),
			Summary:    safe(ev.Summary),
			Data:       redactMap(ev.Data),
			Redacted:   ev.Redacted,
			ObservedAt: ev.ObservedAt,
		})
	}
	return out
}

// --- Markdown ----------------------------------------------------------------

// Markdown renders the report a person actually reads.
type Markdown struct{}

func (Markdown) Format() string    { return FormatMarkdown }
func (Markdown) Extension() string { return ".md" }

// mdsafe is the only way attacker-influenced text may enter the Markdown
// renderer.
//
// redactor.Text strips control characters and credential patterns, but it does
// not neutralise Markdown. Every field here is derived from a target's
// response body, header or parameter name, so a target that reflects text into
// a page title could otherwise inject its own headings, links and list items
// into a report a client reads as the assessor's own conclusions.
func mdsafe(s string) string { return mdEscape(safe(s)) }

func (Markdown) Render(r Report) ([]byte, error) {
	findings := sortFindings(r.Findings)
	s := r.Summary()

	var b strings.Builder
	title := "Security assessment report"
	if r.Metadata.Engagement != "" {
		title += ": " + mdsafe(r.Metadata.Engagement)
	}
	b.WriteString("# " + mdEscape(title) + "\n\n")

	// Scope and authorisation come first, before any finding. A reader who
	// sees the findings first has already formed the wrong impression about
	// what was tested.
	b.WriteString("## Authorisation\n\n")
	if r.Metadata.PassiveOnly {
		b.WriteString("This engagement ran in **passive-only** mode. No request was sent to any target system.\n\n")
	}
	if len(r.Metadata.Scope) > 0 {
		b.WriteString("**In scope**\n\n")
		for _, s := range dedupeSorted(r.Metadata.Scope) {
			b.WriteString("- `" + mdsafe(s) + "`\n")
		}
		b.WriteString("\n")
	}
	if ex := dedupeSorted(r.Metadata.Exclusions); len(ex) > 0 {
		b.WriteString("**Explicitly excluded**\n\n")
		for _, e := range ex {
			b.WriteString("- `" + mdsafe(e) + "`\n")
		}
		b.WriteString("\n")
	}
	if len(r.Metadata.Warnings) > 0 {
		b.WriteString("**Warnings**\n\n")
		for _, w := range r.Metadata.Warnings {
			b.WriteString("- " + mdsafe(w) + "\n")
		}
		b.WriteString("\n")
	}

	b.WriteString("## Summary\n\n")
	b.WriteString(fmt.Sprintf("%d finding(s) across %d asset(s). %d require manual verification before they can be treated as results.\n\n",
		s.Total, countAssets(findings), s.NeedsManual))

	b.WriteString("| Severity | Count |\n|---|---|\n")
	for _, sev := range severitiesInOrder {
		if n := s.BySeverity[sev]; n > 0 {
			b.WriteString("| " + strings.ToUpper(string(sev)) + " | " + strconv.Itoa(n) + " |\n")
		}
	}
	b.WriteString("\n")

	if s.NeedsManual > 0 {
		b.WriteString("> Every item marked *needs manual verification* is a lead produced by observation, not a confirmed issue. ")
		b.WriteString("The toolkit does not test exploitability and does not claim to have.\n\n")
	}

	if len(findings) == 0 {
		b.WriteString("No findings were produced by this run. An empty result is not a clean bill of health: ")
		b.WriteString("it means the checks that ran found nothing, and the stages that were skipped or failed are listed in the warnings above.\n")
		return []byte(b.String()), nil
	}

	for _, sev := range severitiesInOrder {
		group := filterSeverity(findings, sev)
		if len(group) == 0 {
			continue
		}
		b.WriteString("## " + strings.ToUpper(string(sev)) + "\n\n")
		for _, f := range group {
			writeMarkdownFinding(&b, f)
		}
	}

	b.WriteString("---\n\n_Generated by bugbounty-toolkit")
	if r.Metadata.ToolkitVersion != "" {
		b.WriteString(" " + mdEscape(r.Metadata.ToolkitVersion))
	}
	b.WriteString(" at " + generatedAt(r).UTC().Format(time.RFC3339) + "._\n")
	return []byte(b.String()), nil
}

func writeMarkdownFinding(b *strings.Builder, f models.Finding) {
	title := mdsafe(f.Title)
	if f.ManualVerificationRequired {
		title += " _(needs manual verification)_"
	}
	b.WriteString("### " + mdEscape(title) + "\n\n")

	b.WriteString("- **Asset:** `" + mdsafe(assetLabel(f.Asset)) + "`\n")
	if f.Endpoint != "" {
		b.WriteString("- **Endpoint:** `" + mdsafe(f.Endpoint) + "`\n")
	}
	b.WriteString("- **Severity:** " + strings.ToUpper(string(f.Severity)) +
		"  \n- **Confidence:** " + string(f.Confidence) + "  \n")
	b.WriteString("- **Status:** " + string(f.Status) + "  \n")
	if f.Source != "" {
		b.WriteString("- **Rule:** `" + mdsafe(f.Source) + "`  \n")
	}
	b.WriteString("\n")

	if f.Description != "" {
		b.WriteString("**Why it was flagged**\n\n" + mdsafe(f.Description) + "\n\n")
	}
	if f.Impact != "" {
		b.WriteString("**Possible impact**\n\n" + mdsafe(f.Impact) + "\n\n")
	}
	if f.Remediation != "" {
		b.WriteString("**Remediation**\n\n" + mdsafe(f.Remediation) + "\n\n")
	}
	if len(f.ManualVerification) > 0 {
		b.WriteString("**To verify manually**\n\n")
		for _, step := range f.ManualVerification {
			b.WriteString("- " + mdsafe(step) + "\n")
		}
		b.WriteString("\n")
	}
	if len(f.Evidence) > 0 {
		b.WriteString("**Evidence**\n\n")
		for _, ev := range f.Evidence {
			line := "- `" + mdsafe(ev.Source) + "`: " + mdsafe(ev.Summary)
			if ev.Redacted {
				line += " _(redacted)_"
			}
			b.WriteString(line + "\n")
		}
		b.WriteString("\n")
	}
	if len(f.References) > 0 {
		b.WriteString("**References**\n\n")
		for _, ref := range f.References {
			b.WriteString("- " + mdsafe(ref) + "\n")
		}
		b.WriteString("\n")
	}
}

// mdEscape neutralises Markdown control characters. Report text is
// attacker-influenced, and an unescaped heading or link in a report is a way
// for a target to rewrite the reviewer's view of the report.
func mdEscape(s string) string {
	r := strings.NewReplacer(
		"\\", "\\\\",
		"`", "\\`",
		"*", "\\*",
		"_", "\\_",
		"[", "\\[",
		"]", "\\]",
		"<", "&lt;",
		">", "&gt;",
		"|", "\\|",
		"\r", "",
		"\n", " ",
		"\x00", "",
	)
	out := r.Replace(s)
	// Newlines are collapsed above, so an escaped value can no longer contain
	// a line of its own. The only structural characters left that matter are at
	// the start of the value, where a heading, list item, blockquote or setext
	// underline would be read as structure rather than as text. Escaping a
	// leading "#" or "-<space>" costs nothing visually and removes the last
	// way reflected text can add structure to the report.
	trimmed := strings.TrimLeft(out, " \t")
	if trimmed != out {
		out = strings.Repeat(" ", len(out)-len(trimmed)) + trimmed
	}
	for _, prefix := range []string{"#", "> "} {
		if strings.HasPrefix(out, prefix) {
			out = "\\" + out
			break
		}
	}
	for _, prefix := range []string{"- ", "* ", "+ ", "=", "=="} {
		if strings.HasPrefix(out, prefix) {
			out = "\\" + out
			break
		}
	}
	return out
}

// --- HTML --------------------------------------------------------------------

// HTML renders a self-contained page. There is no external asset and no script:
// a security report is exactly the kind of file that gets emailed around, and
// it should not execute anything in the reviewer's browser.
type HTML struct{}

func (HTML) Format() string    { return FormatHTML }
func (HTML) Extension() string { return ".html" }

var htmlTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"severityClass": func(s models.Severity) string { return "sev-" + string(s) },
}).Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{{ .Title }}</title>
<style>
:root { color-scheme: light dark; }
body { font: 16px/1.5 system-ui, sans-serif; margin: 0 auto; max-width: 60rem; padding: 2rem 1rem; }
h1 { border-bottom: 2px solid currentColor; padding-bottom: .3rem; }
h2 { margin-top: 2.5rem; }
h3 { margin-bottom: .25rem; }
.badge { display: inline-block; padding: .1rem .5rem; border-radius: .25rem; font-size: .8rem; font-weight: 600; color: #fff; }
.sev-critical { background: #7f1d1d; } .sev-high { background: #b91c1c; }
.sev-medium { background: #b45309; } .sev-low { background: #0f766e; }
.sev-informational { background: #334155; }
dl { display: grid; grid-template-columns: max-content 1fr; gap: .2rem .8rem; margin: .5rem 0; }
dt { font-weight: 600; } dd { margin: 0; }
code { background: rgba(127,127,127,.15); padding: .1rem .3rem; border-radius: .2rem; word-break: break-all; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
th, td { text-align: left; padding: .4rem .6rem; border-bottom: 1px solid rgba(127,127,127,.3); }
.finding { border: 1px solid rgba(127,127,127,.3); border-radius: .4rem; padding: 1rem; margin: 1rem 0; }
.warn { border-left: .3rem solid #b45309; padding: .5rem 1rem; background: rgba(180,83,9,.1); }
.scope { border-left: .3rem solid #0f766e; padding: .5rem 1rem; background: rgba(15,118,110,.1); }
ul { padding-left: 1.2rem; }
.foot { margin-top: 3rem; font-size: .85rem; opacity: .8; }
</style>
</head>
<body>
<h1>{{ .Title }}</h1>

<div class="scope">
{{- if .Metadata.PassiveOnly }}
<p><strong>Passive-only engagement.</strong> No request was sent to any target system.</p>
{{- end }}
{{- if .Metadata.Scope }}
<p><strong>In scope:</strong> {{ range .Metadata.Scope }}<code>{{ . }}</code> {{ end }}</p>
{{- end }}
{{- if .Metadata.Exclusions }}
<p><strong>Excluded:</strong> {{ range .Metadata.Exclusions }}<code>{{ . }}</code> {{ end }}</p>
{{- end }}
</div>

{{- if .Metadata.Warnings }}
<div class="warn">
<strong>Warnings</strong>
<ul>{{ range .Metadata.Warnings }}<li>{{ . }}</li>{{ end }}</ul>
</div>
{{- end }}

<h2>Summary</h2>
<p>{{ .Summary.Total }} finding(s) across {{ .AssetCount }} asset(s).
{{ .Summary.NeedsManual }} require manual verification before they can be treated as results.</p>
<table>
<tr><th>Severity</th><th>Count</th></tr>
{{- range .Severities }}{{ if .Count }}
<tr><td><span class="badge {{ .Class }}">{{ .Name }}</span></td><td>{{ .Count }}</td></tr>
{{- end }}{{ end }}
</table>

{{- if .Summary.NeedsManual }}
<div class="warn">
Every item marked <em>needs manual verification</em> is a lead produced by observation, not a
confirmed issue. The toolkit does not test exploitability and does not claim to have.
</div>
{{- end }}

{{- if not .Findings }}
<p>No findings were produced by this run. An empty result is not a clean bill of health: it means
the checks that ran found nothing, and any stage that was skipped or failed is listed in the warnings above.</p>
{{- end }}

{{- range .Groups }}
<h2>{{ .Name }}</h2>
{{- range .Findings }}
<div class="finding">
<h3>{{ .Title }}{{ if .ManualRequired }} <span class="badge sev-informational">needs manual verification</span>{{ end }}</h3>
<dl>
<dt>Asset</dt><dd><code>{{ .Asset }}</code></dd>
{{- if .Endpoint }}<dt>Endpoint</dt><dd><code>{{ .Endpoint }}</code></dd>{{ end }}
<dt>Severity</dt><dd><span class="badge {{ .Class }}">{{ .Severity }}</span></dd>
<dt>Confidence</dt><dd>{{ .Confidence }}</dd>
<dt>Status</dt><dd>{{ .Status }}</dd>
{{- if .Rule }}<dt>Rule</dt><dd><code>{{ .Rule }}</code></dd>{{ end }}
</dl>
{{- if .Description }}<p><strong>Why it was flagged.</strong> {{ .Description }}</p>{{ end }}
{{- if .Impact }}<p><strong>Possible impact.</strong> {{ .Impact }}</p>{{ end }}
{{- if .Remediation }}<p><strong>Remediation.</strong> {{ .Remediation }}</p>{{ end }}
{{- if .Verification }}
<p><strong>To verify manually</strong></p>
<ul>{{ range .Verification }}<li>{{ . }}</li>{{ end }}</ul>
{{- end }}
{{- if .Evidence }}
<p><strong>Evidence</strong></p>
<ul>{{ range .Evidence }}<li><code>{{ .Source }}</code>: {{ .Summary }}{{ if .Redacted }} <em>(redacted)</em>{{ end }}</li>{{ end }}</ul>
{{- end }}
{{- if .References }}
<p><strong>References</strong></p>
<ul>{{ range .References }}<li>{{ . }}</li>{{ end }}</ul>
{{- end }}
</div>
{{- end }}
{{- end }}

<p class="foot">Generated by bugbounty-toolkit{{ if .Metadata.ToolkitVersion }} {{ .Metadata.ToolkitVersion }}{{ end }} at {{ .GeneratedAt }}.</p>
</body>
</html>
`))

type tmplMetadata struct {
	Engagement     string
	RunID          string
	Seed           string
	Scope          []string
	Exclusions     []string
	PassiveOnly    bool
	Warnings       []string
	ToolkitVersion string
}

type tmplData struct {
	Title      string
	Metadata   tmplMetadata
	Summary    Summary
	AssetCount int
	Severities []tmplSeverity
	Groups     []tmplGroup
	// Findings is the flat list the template checks for emptiness, so an empty
	// run renders an explanation rather than a blank page.
	Findings    []tmplFinding
	GeneratedAt string
}

type tmplSeverity struct {
	Name  string
	Class string
	Count int
}

type tmplFinding struct {
	Title          string
	Asset          string
	Endpoint       string
	Severity       string
	Class          string
	Confidence     string
	Status         string
	Rule           string
	Description    string
	Impact         string
	Remediation    string
	Verification   []string
	Evidence       []models.Evidence
	References     []string
	ManualRequired bool
}

type tmplGroup struct {
	Name     string
	Findings []tmplFinding
}

func (HTML) Render(r Report) ([]byte, error) {
	s := r.Summary()
	ordered := sortFindings(r.Findings)

	data := tmplData{
		Title:       htmlReportTitle(r),
		Metadata:    toHTMLMetadata(r.Metadata),
		Summary:     s,
		AssetCount:  countAssets(ordered),
		GeneratedAt: generatedAt(r).UTC().Format(time.RFC3339),
	}
	for _, sev := range severitiesInOrder {
		if n := s.BySeverity[sev]; n > 0 {
			data.Severities = append(data.Severities, tmplSeverity{
				Name:  strings.ToUpper(string(sev)),
				Class: "sev-" + string(sev),
				Count: n,
			})
		}
	}
	for _, sev := range severitiesInOrder {
		var group tmplGroup
		group.Name = strings.ToUpper(string(sev))
		for _, f := range ordered {
			if f.Severity != sev {
				continue
			}
			group.Findings = append(group.Findings, toHTMLFinding(f))
		}
		if len(group.Findings) > 0 {
			data.Groups = append(data.Groups, group)
		}
	}
	data.Findings = make([]tmplFinding, 0, len(ordered))
	for _, f := range ordered {
		data.Findings = append(data.Findings, toHTMLFinding(f))
	}

	var buf bytes.Buffer
	if err := htmlTemplate.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("report: rendering html: %w", err)
	}
	return buf.Bytes(), nil
}

func toHTMLMetadata(m Metadata) tmplMetadata {
	return tmplMetadata{
		Engagement:     safe(m.Engagement),
		RunID:          safe(m.RunID),
		Seed:           safe(m.Seed),
		Scope:          dedupeSorted(m.Scope),
		Exclusions:     dedupeSorted(m.Exclusions),
		PassiveOnly:    m.PassiveOnly,
		Warnings:       redactStringSlice(m.Warnings),
		ToolkitVersion: safe(m.ToolkitVersion),
	}
}

func toHTMLFinding(f models.Finding) tmplFinding {
	return tmplFinding{
		Title:          safe(f.Title),
		Asset:          assetLabel(f.Asset),
		Endpoint:       safe(f.Endpoint),
		Severity:       strings.ToUpper(string(f.Severity)),
		Class:          "sev-" + string(f.Severity),
		Confidence:     string(f.Confidence),
		Status:         string(f.Status),
		Rule:           safe(f.Source),
		Description:    safe(f.Description),
		Impact:         safe(f.Impact),
		Remediation:    safe(f.Remediation),
		Verification:   redactStringSlice(f.ManualVerification),
		Evidence:       redactedEvidence(f.Evidence),
		References:     redactStringSlice(f.References),
		ManualRequired: f.ManualVerificationRequired,
	}
}

// redactedEvidence copies evidence with every free-text field passed through
// the redactor. Evidence is built from response bodies, header values and
// parameter names, so handing it to a renderer unredacted is how a credential
// the target reflected ends up in a file the client emails to a colleague.
func redactedEvidence(in []models.Evidence) []models.Evidence {
	if in == nil {
		return nil
	}
	out := make([]models.Evidence, 0, len(in))
	for _, ev := range in {
		ev.Source = safe(ev.Source)
		ev.Summary = safe(ev.Summary)
		ev.Data = redactMap(ev.Data)
		ev.FindingID = safe(ev.FindingID)
		out = append(out, ev)
	}
	return out
}

func htmlReportTitle(r Report) string {
	t := "Security assessment report"
	if r.Metadata.Engagement != "" {
		t += ": " + safe(r.Metadata.Engagement)
	}
	return t
}

// --- SARIF -------------------------------------------------------------------

// SARIF version emitted. 2.1.0 is what current tooling consumes.
const sarifVersion = "2.1.0"
const sarifSchema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
	// Invocations records what the run was allowed to do. A consumer that
	// reads only results would otherwise not know the assessment was passive.
	Invocations []sarifInvocation `json:"invocations,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name,omitempty"`
	ShortDescription sarifText           `json:"shortDescription"`
	FullDescription  sarifText           `json:"fullDescription"`
	Help             sarifText           `json:"help"`
	HelpURI          string              `json:"helpUri,omitempty"`
	Properties       sarifRuleProperties `json:"properties"`
	// DefaultConfiguration lets a consumer render the rule before it has
	// seen a result from it.
	DefaultConfiguration sarifRuleConfig `json:"defaultConfiguration"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifRuleProperties struct {
	Tags     []string `json:"tags,omitempty"`
	Severity string   `json:"problem.severity,omitempty"`
	// RequiresManualVerification propagates the toolkit's core promise into
	// the machine-readable form: a consumer must not treat these results as
	// confirmed issues without a human closing them.
	RequiresManualVerification bool `json:"requiresManualVerification,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string                `json:"ruleId"`
	Level               string                `json:"level"`
	Message             sarifText             `json:"message"`
	Locations           []sarifLocation       `json:"locations"`
	PartialFingerprints map[string]string     `json:"partialFingerprints,omitempty"`
	Properties          sarifResultProperties `json:"properties,omitempty"`
}

type sarifResultProperties struct {
	Asset              string    `json:"asset,omitempty"`
	Confidence         string    `json:"confidence,omitempty"`
	Status             string    `json:"status,omitempty"`
	FirstSeen          time.Time `json:"firstSeen,omitempty"`
	LastSeen           time.Time `json:"lastSeen,omitempty"`
	ManualVerification []string  `json:"manualVerificationSteps,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool                      `json:"executionSuccessful"`
	StartTimeUtc        string                    `json:"startTimeUtc,omitempty"`
	EndTimeUtc          string                    `json:"endTimeUtc,omitempty"`
	Properties          sarifInvocationProperties `json:"properties"`
}

type sarifInvocationProperties struct {
	PassiveOnly bool     `json:"passiveOnly"`
	Scope       []string `json:"scope,omitempty"`
	Exclusions  []string `json:"exclusions,omitempty"`
	Warnings    []string `json:"warnings,omitempty"`
}

// SARIF renders the report for static analysis tooling.
type SARIF struct{}

func (SARIF) Format() string    { return FormatSARIF }
func (SARIF) Extension() string { return ".sarif" }

func (SARIF) Render(r Report) ([]byte, error) {
	meta := ruleMetadata()
	ordered := sortFindings(r.Findings)

	rules := make([]sarifRule, 0, len(meta))
	ids := make([]string, 0, len(meta))
	for id := range meta {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		m := meta[id]
		rule := sarifRule{
			ID:               id,
			Name:             safe(m.Title),
			ShortDescription: sarifText{Text: safe(m.Title)},
			FullDescription:  sarifText{Text: safe(m.Description)},
			Help:             sarifText{Text: safe(m.Description)},
			Properties: sarifRuleProperties{
				Severity: string(m.Severity),
			},
			DefaultConfiguration: sarifRuleConfig{Level: sarifLevel(m.Severity)},
		}
		if len(rule.Properties.Tags) == 0 {
			rule.Properties.Tags = []string{"security"}
		}
		rules = append(rules, rule)
	}

	// A finding whose rule is not in the built-in set still needs a declared
	// rule, or a consumer rejects the log.
	known := map[string]struct{}{}
	for _, id := range ids {
		known[id] = struct{}{}
	}
	results := make([]sarifResult, 0, len(ordered))
	for _, f := range ordered {
		ruleID := safe(f.Source)
		if ruleID == "" {
			ruleID = safe(f.Type)
		}
		if _, ok := known[ruleID]; !ok {
			known[ruleID] = struct{}{}
			rules = append(rules, sarifRule{
				ID:                   ruleID,
				ShortDescription:     sarifText{Text: safe(f.Title)},
				FullDescription:      sarifText{Text: safe(f.Description)},
				Help:                 sarifText{Text: safe(f.Remediation)},
				Properties:           sarifRuleProperties{Severity: string(f.Severity)},
				DefaultConfiguration: sarifRuleConfig{Level: sarifLevel(f.Severity)},
			})
		}
		results = append(results, sarifResult{
			RuleID:  ruleID,
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: safe(f.Title) + ": " + safe(f.Description)},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: sarifURI(f)},
				},
			}},
			PartialFingerprints: map[string]string{"bugbountyFingerprint/v1": safe(f.Fingerprint)},
			Properties: sarifResultProperties{
				Asset:              safe(f.Asset),
				Confidence:         string(f.Confidence),
				Status:             string(f.Status),
				FirstSeen:          f.FirstSeen,
				LastSeen:           f.LastSeen,
				ManualVerification: redactStringSlice(f.ManualVerification),
			},
		})
	}

	inv := sarifInvocation{
		ExecutionSuccessful: len(r.Metadata.Warnings) == 0,
		Properties: sarifInvocationProperties{
			PassiveOnly: r.Metadata.PassiveOnly,
			Scope:       dedupeSorted(r.Metadata.Scope),
			Exclusions:  dedupeSorted(r.Metadata.Exclusions),
			Warnings:    redactStringSlice(r.Metadata.Warnings),
		},
	}
	if !r.Metadata.StartedAt.IsZero() {
		inv.StartTimeUtc = r.Metadata.StartedAt.UTC().Format(time.RFC3339)
	}
	if !r.Metadata.FinishedAt.IsZero() {
		inv.EndTimeUtc = r.Metadata.FinishedAt.UTC().Format(time.RFC3339)
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "bugbounty-toolkit",
				Version:        safe(r.Metadata.ToolkitVersion),
				InformationURI: "https://github.com/bbtoolkit/bugbounty",
				Rules:          rules,
			}},
			Results:     results,
			Invocations: []sarifInvocation{inv},
		}},
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(log); err != nil {
		return nil, fmt.Errorf("report: encoding sarif: %w", err)
	}
	return buf.Bytes(), nil
}

// sarifLevel maps a severity onto SARIF's four-level scale.
func sarifLevel(s models.Severity) string {
	switch s {
	case models.SeverityCritical, models.SeverityHigh:
		return "error"
	case models.SeverityMedium:
		return "warning"
	case models.SeverityLow:
		return "note"
	default:
		return "none"
	}
}

// sarifURI prefers the endpoint, which is the most specific location, and falls
// back to the asset.
func sarifURI(f models.Finding) string {
	if f.Endpoint != "" {
		return safe(f.Endpoint)
	}
	if f.Asset != "" {
		return safe(f.Asset)
	}
	return "unknown"
}

// --- CSV ---------------------------------------------------------------------

// CSV renders one row per finding for triage in a spreadsheet.
type CSV struct{}

func (CSV) Format() string    { return FormatCSV }
func (CSV) Extension() string { return ".csv" }

func (CSV) Render(r Report) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)

	header := []string{
		"id", "severity", "confidence", "status", "asset", "endpoint",
		"rule", "title", "needs_manual_verification", "description",
		"possible_impact", "remediation", "tags", "references",
		"manual_verification_steps", "first_seen", "last_seen", "fingerprint",
	}
	if err := w.Write(header); err != nil {
		return nil, fmt.Errorf("report: writing csv header: %w", err)
	}

	for _, f := range sortFindings(r.Findings) {
		row := []string{
			safe(f.ID),
			string(f.Severity),
			string(f.Confidence),
			string(f.Status),
			safe(f.Asset),
			safe(f.Endpoint),
			safe(f.Source),
			// csv.Writer quotes embedded newlines, so multi-line text is safe
			// to emit without stripping it. A spreadsheet injection is a
			// different risk and is handled below.
			csvSafe(safe(f.Title)),
			strconv.FormatBool(f.ManualVerificationRequired),
			csvSafe(safe(f.Description)),
			csvSafe(safe(f.Impact)),
			csvSafe(safe(f.Remediation)),
			strings.Join(redactStringSlice(f.Tags), " "),
			strings.Join(redactStringSlice(f.References), " "),
			strings.Join(redactStringSlice(f.ManualVerification), " | "),
			f.FirstSeen.UTC().Format(time.RFC3339),
			f.LastSeen.UTC().Format(time.RFC3339),
			safe(f.Fingerprint),
		}
		if err := w.Write(row); err != nil {
			return nil, fmt.Errorf("report: writing csv row: %w", err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, fmt.Errorf("report: flushing csv: %w", err)
	}
	return buf.Bytes(), nil
}

// csvFormulaPrefixes are the characters a spreadsheet treats as the start of a
// formula. A finding's text is attacker-influenced, so a cell beginning with
// one of these executes when the report is opened.
var csvFormulaPrefixes = []string{"=", "+", "-", "@"}

// csvSafe prefixes a leading formula character with a single quote, which
// spreadsheets render as a literal character.
//
// A tab or carriage return ahead of the formula is part of the vector, not
// incidental whitespace: it is how the leading character gets past a filter
// that only looks at the first byte. So the check runs on the untrimmed value
// and the trim exists only to find a formula hidden behind ordinary spaces.
func csvSafe(s string) string {
	if s == "" {
		return s
	}
	if strings.HasPrefix(s, "\t") || strings.HasPrefix(s, "\r") {
		return "'" + s
	}
	trimmed := strings.TrimLeft(s, " ")
	if trimmed == "" {
		return s
	}
	for _, p := range csvFormulaPrefixes {
		if strings.HasPrefix(trimmed, p) {
			return "'" + s
		}
	}
	return s
}

// --- Text --------------------------------------------------------------------

// Text renders a plain-text summary for a terminal or a log.
type Text struct{}

func (Text) Format() string    { return FormatText }
func (Text) Extension() string { return ".txt" }

func (Text) Render(r Report) ([]byte, error) {
	s := r.Summary()
	ordered := sortFindings(r.Findings)

	var b strings.Builder
	b.WriteString(htmlReportTitle(r) + "\n")
	b.WriteString(strings.Repeat("=", len(htmlReportTitle(r))) + "\n\n")
	if r.Metadata.PassiveOnly {
		b.WriteString("PASSIVE-ONLY ENGAGEMENT: no request was sent to any target.\n\n")
	}
	if len(r.Metadata.Scope) > 0 {
		b.WriteString("In scope:    " + strings.Join(dedupeSorted(r.Metadata.Scope), ", ") + "\n")
	}
	if ex := dedupeSorted(r.Metadata.Exclusions); len(ex) > 0 {
		b.WriteString("Excluded:    " + strings.Join(ex, ", ") + "\n")
	}
	for _, w := range r.Metadata.Warnings {
		b.WriteString("WARNING:     " + safe(w) + "\n")
	}
	b.WriteString("\n")

	for _, sev := range severitiesInOrder {
		if n := s.BySeverity[sev]; n > 0 {
			b.WriteString(fmt.Sprintf("%-14s %d\n", strings.ToUpper(string(sev)), n))
		}
	}
	b.WriteString(fmt.Sprintf("%-14s %d (%d need manual verification)\n\n", "TOTAL", s.Total, s.NeedsManual))

	if len(ordered) == 0 {
		b.WriteString("No findings were produced. This is not a clean bill of health: it means the\n")
		b.WriteString("checks that ran found nothing. See any warnings above.\n")
		return []byte(b.String()), nil
	}

	for _, f := range ordered {
		flag := ""
		if f.ManualVerificationRequired {
			flag = " [NEEDS MANUAL VERIFICATION]"
		}
		b.WriteString(fmt.Sprintf("%-14s %s%s\n", strings.ToUpper(string(f.Severity)), safe(f.Title), flag))
		b.WriteString("  asset:  " + assetLabel(f.Asset) + "\n")
		if f.Endpoint != "" {
			b.WriteString("  url:    " + safe(f.Endpoint) + "\n")
		}
		if f.Impact != "" {
			b.WriteString("  impact: " + wrap(safe(f.Impact), 70, "          ") + "\n")
		}
		b.WriteString("\n")
	}
	return []byte(b.String()), nil
}

// wrap breaks text to a width, indenting continuation lines. It is used only
// for the terminal renderer, where a single very long line is unreadable.
func wrap(s string, width int, indent string) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	var b strings.Builder
	lineLen := 0
	for i, w := range words {
		if i > 0 {
			if lineLen+1+len(w) > width {
				b.WriteString("\n" + indent)
				lineLen = 0
			} else {
				b.WriteString(" ")
				lineLen++
			}
		}
		b.WriteString(w)
		lineLen += len(w)
	}
	return b.String()
}

// --- shared helpers ----------------------------------------------------------

func filterSeverity(in []models.Finding, sev models.Severity) []models.Finding {
	var out []models.Finding
	for _, f := range in {
		if f.Severity == sev {
			out = append(out, f)
		}
	}
	return out
}

func countAssets(findings []models.Finding) int {
	seen := map[string]struct{}{}
	for _, f := range findings {
		if f.Asset != "" {
			seen[f.Asset] = struct{}{}
		}
	}
	return len(seen)
}

func severityCounts(s Summary) map[string]int {
	out := make(map[string]int, len(s.BySeverity))
	for _, sev := range severitiesInOrder {
		if n, ok := s.BySeverity[sev]; ok {
			out[string(sev)] = n
		}
	}
	return out
}

func statusCounts(s Summary) map[string]int {
	out := make(map[string]int, len(s.ByStatus))
	for k, v := range s.ByStatus {
		out[string(k)] = v
	}
	return out
}

func generatedAt(r Report) time.Time {
	if r.GeneratedAt.IsZero() {
		return time.Now().UTC()
	}
	return r.GeneratedAt
}

func optTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func redactStringSlice(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, safe(s))
	}
	return out
}

func redactMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[safe(k)] = safe(v)
	}
	return out
}
