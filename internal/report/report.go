// Package report renders findings and run metadata for humans and for other
// tools.
//
// Every renderer shares one rule: the toolkit reports what it observed, marks
// clearly what a human still has to confirm, and never presents a candidate as
// a confirmed issue. A report is the only artefact a client actually reads, so
// a renderer that overstates confidence causes more damage than a renderer that
// is merely terse.
package report

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/bbtoolkit/bugbounty/internal/findings"
	"github.com/bbtoolkit/bugbounty/internal/redact"
	"github.com/bbtoolkit/bugbounty/pkg/models"
)

// Formats a renderer can produce.
const (
	FormatJSON     = "json"
	FormatMarkdown = "markdown"
	FormatSARIF    = "sarif"
	FormatHTML     = "html"
	FormatCSV      = "csv"
	FormatText     = "text"
)

// ErrUnsupportedFormat is returned for a format with no renderer.
var ErrUnsupportedFormat = errors.New("report: unsupported format")

// Metadata describes the engagement a report covers. It is rendered into every
// output so a report found on a disk months later still says what it was.
type Metadata struct {
	// Engagement is the client or programme name.
	Engagement string
	// RunID ties the report to a stored run.
	RunID string
	// Seed is the domain or URL the run started from.
	Seed string
	// Scope records what was and was not authorised, so a report cannot be
	// read later as consent to test something it did not cover.
	Scope []string
	// Exclusions records what was explicitly ruled out.
	Exclusions []string
	// StartedAt and FinishedAt bound the run.
	StartedAt  time.Time
	FinishedAt time.Time
	// PassiveOnly records whether the run was authorised to touch the target
	// at all. This is rendered prominently.
	PassiveOnly bool
	// Warnings carries problems the operator must see, such as a stage that
	// did not complete.
	Warnings []string
	// ToolkitVersion identifies the build that produced the report.
	ToolkitVersion string
}

// Report is the complete input to a renderer.
type Report struct {
	Metadata Metadata
	Findings []models.Finding
	// Counts by severity, recomputed by Summary so a renderer cannot report a
	// stale number.
	GeneratedAt time.Time
}

// Summary recomputes the severity breakdown from the findings themselves, so
// the counts can never disagree with the list beside them.
func (r Report) Summary() Summary {
	s := Summary{
		BySeverity: map[models.Severity]int{},
		ByStatus:   map[models.Status]int{},
	}
	for _, f := range r.Findings {
		s.Total++
		s.BySeverity[f.Severity]++
		s.ByStatus[f.Status]++
		if f.ManualVerificationRequired {
			s.NeedsManual++
		}
	}
	return s
}

// Summary is a severity and status breakdown.
type Summary struct {
	Total       int
	NeedsManual int
	BySeverity  map[models.Severity]int
	ByStatus    map[models.Status]int
}

// New returns a renderer for a format name.
func New(format string) (Renderer, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case FormatJSON, "":
		return JSON{}, nil
	case FormatMarkdown, "md":
		return Markdown{}, nil
	case FormatSARIF:
		return SARIF{}, nil
	case FormatHTML:
		return HTML{}, nil
	case FormatCSV:
		return CSV{}, nil
	case FormatText, "txt":
		return Text{}, nil
	default:
		return nil, fmt.Errorf("%w: %q (known: %s)", ErrUnsupportedFormat, format, strings.Join(Formats(), ", "))
	}
}

// Formats lists the supported formats in a stable order.
func Formats() []string {
	return []string{FormatCSV, FormatHTML, FormatJSON, FormatMarkdown, FormatSARIF, FormatText}
}

// Renderer produces a report.
type Renderer interface {
	// Format is the name the renderer answers to.
	Format() string
	// Extension is the file suffix to use, including the dot.
	Extension() string
	// Render produces the report. It never returns an error for a
	// well-formed Report; a renderer fails only on an internal fault.
	Render(r Report) ([]byte, error)
}

// renderContentType is the media type for a format.
var renderContentType = map[string]string{
	FormatJSON:     "application/json",
	FormatMarkdown: "text/markdown",
	FormatSARIF:    "application/sarif+json",
	FormatHTML:     "text/html",
	FormatCSV:      "text/csv",
	FormatText:     "text/plain",
}

// ContentType returns the media type for a format name.
func ContentType(format string) string {
	if ct, ok := renderContentType[strings.ToLower(format)]; ok {
		return ct
	}
	return "application/octet-stream"
}

// sortFindings puts a report's findings in the order a reviewer wants to read
// them: worst first, then most certain, then by asset.
func sortFindings(in []models.Finding) []models.Finding {
	out := append([]models.Finding(nil), in...)
	models.SortFindings(out)
	return out
}

// writeAll is the single place a renderer escapes text going into a
// structured output, so no renderer can forget.
func safe(s string) string { return redact.Text(s) }

// assetLabel renders an asset for a heading without pretending a URL is a
// hostname.
func assetLabel(asset string) string {
	a := strings.TrimSpace(asset)
	if a == "" {
		return "(unnamed asset)"
	}
	return safe(a)
}

// severitiesInOrder is the fixed order summaries iterate in, so two reports
// with the same findings read identically.
var severitiesInOrder = []models.Severity{
	models.SeverityCritical,
	models.SeverityHigh,
	models.SeverityMedium,
	models.SeverityLow,
	models.SeverityInformational,
}

// formatDuration renders an elapsed time for a human.
func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	return d.Round(time.Second).String()
}

// dedupeSorted returns sorted, de-duplicated non-empty strings.
func dedupeSorted(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// ruleMetadata pairs a rule ID with its description for SARIF, where each
// reported result must name a rule that is declared in the tool's rule table.
func ruleMetadata() map[string]struct {
	Title       string
	Description string
	Severity    models.Severity
} {
	out := make(map[string]struct {
		Title       string
		Description string
		Severity    models.Severity
	})
	for _, r := range findings.DefaultRules() {
		out[r.ID] = struct {
			Title       string
			Description string
			Severity    models.Severity
		}{Title: r.Title, Description: r.Description, Severity: r.Severity}
	}
	return out
}
