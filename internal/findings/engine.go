package findings

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/bbtoolkit/bugbounty/internal/redact"
	"github.com/bbtoolkit/bugbounty/pkg/models"
)

// MaxEvidencePerFinding bounds how much evidence a single finding carries.
// Without it, an asset reachable through a thousand URLs produces a finding
// with a thousand evidence rows, which is unusable in a report and slow to
// store. The oldest observations are dropped first, so what remains is the
// most recent evidence.
const MaxEvidencePerFinding = 12

// ErrEmptyRule is returned when a rule with no Check is registered.
var ErrEmptyRule = errors.New("findings: rule has no Check function")

// ErrDuplicateRule is returned when two rules share an ID, which would make
// the suppress list ambiguous.
var ErrDuplicateRule = errors.New("findings: duplicate rule ID")

// Engine evaluates a rule set. It is immutable once built and safe for
// concurrent use.
type Engine struct {
	rules []Rule
}

// NewEngine builds an engine from rules. It validates the rules eagerly so a
// malformed rule is a startup failure rather than a silent absence of findings
// halfway through an engagement.
func NewEngine(rules ...Rule) (*Engine, error) {
	seen := make(map[string]struct{}, len(rules))
	for i, r := range rules {
		if r.Check == nil {
			return nil, fmt.Errorf("%w: %q", ErrEmptyRule, r.ID)
		}
		if r.ID == "" {
			return nil, fmt.Errorf("%w: rule %d has no ID", ErrEmptyRule, i)
		}
		if _, dup := seen[r.ID]; dup {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateRule, r.ID)
		}
		seen[r.ID] = struct{}{}
		if !r.Severity.Valid() {
			return nil, fmt.Errorf("findings: rule %q has invalid severity %q", r.ID, r.Severity)
		}
		if !r.Confidence.Valid() {
			return nil, fmt.Errorf("findings: rule %q has invalid confidence %q", r.ID, r.Confidence)
		}
		if r.ManualVerificationRequired && len(r.ManualVerification) == 0 {
			// A finding that says "a human must check this" but does not say
			// what to check wastes the reviewer's most expensive resource.
			return nil, fmt.Errorf("findings: rule %q requires manual verification but lists no steps", r.ID)
		}
	}
	return &Engine{rules: append([]Rule(nil), rules...)}, nil
}

// DefaultEngine returns the standard rule set.
func DefaultEngine() *Engine {
	e, err := NewEngine(DefaultRules()...)
	if err != nil {
		// The default set is compiled by hand; a failure here is a
		// programming error, not a runtime condition to handle.
		panic("findings: built-in rule set is invalid: " + err.Error())
	}
	return e
}

// RuleIDs lists the registered rule IDs in sorted order.
func (e *Engine) RuleIDs() []string {
	out := make([]string, 0, len(e.rules))
	for _, r := range e.rules {
		out = append(out, r.ID)
	}
	sort.Strings(out)
	return out
}

// Rules returns the registered rules.
func (e *Engine) Rules() []Rule { return append([]Rule(nil), e.rules...) }

// Filter returns a new engine containing only the rules whose IDs are in keep.
// An empty keep list yields an engine with every rule, which is what a command
// line with no explicit selection should do.
func (e *Engine) Filter(keep []string) *Engine {
	if len(keep) == 0 {
		return e
	}
	want := make(map[string]struct{}, len(keep))
	for _, id := range keep {
		want[id] = struct{}{}
	}
	var out []Rule
	for _, r := range e.rules {
		if _, ok := want[r.ID]; ok {
			out = append(out, r)
		}
	}
	// NewEngine cannot fail here: the rules already passed validation and
	// filtering by ID cannot introduce a duplicate.
	filtered, err := NewEngine(out...)
	if err != nil {
		return e
	}
	return filtered
}

// Evaluate runs every rule over in and returns deduplicated, redacted
// findings sorted for reporting.
//
// A rule that panics or misbehaves must not destroy the run: the engine
// recovers per rule and records the failure as a finding-level error so the
// operator learns that a check silently did not run, instead of believing a
// clean result.
func (e *Engine) Evaluate(ctx context.Context, in Input) ([]models.Finding, []error) {
	if in.Now.IsZero() {
		in.Now = time.Now()
	}
	if in.Asset == "" {
		in.Asset = primaryAsset(in)
	}

	var raw []models.Finding
	var errs []error
	for _, r := range e.rules {
		results, err := e.runRule(ctx, r, in)
		if err != nil {
			errs = append(errs, fmt.Errorf("rule %q: %w", r.ID, err))
			continue
		}
		for _, res := range results {
			raw = append(raw, e.materialize(r, res, in))
		}
	}

	correlated, corrErrs := Correlate(raw)
	errs = append(errs, corrErrs...)
	return correlated, errs
}

// runRule isolates one rule so a panic in a check does not take down the run.
func (e *Engine) runRule(ctx context.Context, r Rule, in Input) (results []Result, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("check panicked: %v", rec)
			results = nil
		}
	}()

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return r.Check(ctx, in), nil
}

// materialize turns one rule result into a finding, redacting everything that
// came from the target.
func (e *Engine) materialize(r Rule, res Result, in Input) models.Finding {
	asset := res.Asset
	if asset == "" {
		asset = in.Asset
	}
	asset = redact.Text(asset)

	severity := r.Severity
	if res.Severity != nil && res.Severity.Valid() {
		severity = *res.Severity
	}
	confidence := r.Confidence
	if res.Confidence != nil && res.Confidence.Valid() {
		confidence = *res.Confidence
	}

	observedAt := in.Now
	data, changed := redact.Scrub(res.Data)
	if changed {
		// The scrubber changed something, which means a value that looked
		// like a credential was about to be written to disk or printed. The
		// finding says so rather than letting a leak look like clean output.
		data["redaction_applied"] = "true"
	}

	evidence := []models.Evidence{{
		Source:     r.sourceFor(res),
		Summary:    redact.Text(res.Summary),
		Data:       data,
		Redacted:   changed,
		ObservedAt: observedAt,
	}}
	for _, ev := range res.Evidence {
		ev.Source = redact.Text(ev.Source)
		ev.Summary = redact.Text(ev.Summary)
		if ev.ObservedAt.IsZero() {
			ev.ObservedAt = observedAt
		}
		evData, evChanged := redact.Scrub(ev.Data)
		ev.Data = evData
		ev.Redacted = ev.Redacted || evChanged
		evidence = append(evidence, ev)
	}

	// Tags extend, never replace, the rule's tags. The finding's identity
	// includes them, so a rule reporting one result per item has to
	// discriminate on something or distinct items merge into one.
	tags := append([]string(nil), r.Tags...)
	tags = unionStrings(tags, res.Tags)

	f := models.Finding{
		Type:                       r.findingType(),
		Title:                      redact.Text(r.Title),
		Severity:                   severity,
		Confidence:                 confidence,
		Asset:                      asset,
		Endpoint:                   redact.URL(res.Endpoint),
		Description:                r.Description,
		ManualVerification:         append([]string(nil), r.ManualVerification...),
		Impact:                     r.Impact,
		Remediation:                r.Remediation,
		References:                 append([]string(nil), r.References...),
		Evidence:                   evidence,
		Status:                     models.StatusNew,
		Tags:                       tags,
		Source:                     r.ID,
		ManualVerificationRequired: r.ManualVerificationRequired,
		FirstSeen:                  observedAt,
		LastSeen:                   observedAt,
	}
	f.Fingerprint = f.ComputeFingerprint()
	if f.ID == "" {
		// The ID is derived from the fingerprint rather than randomly
		// generated, so re-running the same engagement produces the same IDs
		// and a report diff shows only what actually changed.
		f.ID = "F-" + shortID(f.Fingerprint)
	}
	return f
}

// shortID returns a stable, human-quotable identifier fragment.
func shortID(fingerprint string) string {
	const n = 16
	if len(fingerprint) < n {
		return fingerprint
	}
	return fingerprint[:n]
}

// primaryAsset picks a sensible asset label for a batch that did not name one,
// so findings are never recorded against the empty string.
func primaryAsset(in Input) string {
	if len(in.HTTP) > 0 && in.HTTP[0].URL != "" {
		return in.HTTP[0].URL
	}
	if len(in.DNS) > 0 && in.DNS[0].Name != "" {
		return in.DNS[0].Name
	}
	if len(in.Endpoints) > 0 && in.Endpoints[0].URL != "" {
		return in.Endpoints[0].URL
	}
	return "unknown"
}
