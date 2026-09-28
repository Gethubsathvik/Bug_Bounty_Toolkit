package findings

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/bbtoolkit/bugbounty/pkg/models"
)

// Correlate merges duplicate findings, adjusts confidence from corroboration,
// drops findings a control already covers, and returns the result ready for
// storage.
//
// The errors it returns describe findings that were dropped because they were
// invalid. They are returned rather than swallowed so a caller can fail the
// stage: an invalid finding reaching the database would be worse than a
// failed run.
func Correlate(in []models.Finding) ([]models.Finding, []error) {
	var errs []error

	// Validate before merging. Merging would otherwise let one bad finding
	// poison a good one that happens to share its fingerprint.
	kept := make([]models.Finding, 0, len(in))
	for i := range in {
		f := in[i]
		// Recompute rather than trust the caller's copy. A fingerprint derived
		// from fields goes stale the moment a caller adjusts a tag, and a
		// stale one silently merges two unrelated findings into a single
		// entry that then looks like a corroborated result.
		f.Fingerprint = f.ComputeFingerprint()
		if f.Status == "" {
			f.Status = models.StatusNew
		}
		if f.ManualVerificationRequired && f.Status == models.StatusNew {
			f.Status = models.StatusNeedsManual
		}
		if err := f.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("findings: dropping invalid finding %q (%s): %w", f.Title, f.Type, err))
			continue
		}
		kept = append(kept, f)
	}

	merged := mergeDuplicates(kept)
	for i := range merged {
		merged[i].Evidence = boundEvidence(merged[i].Evidence)
		merged[i] = corroborate(merged[i])
	}
	merged = suppressRedundant(merged)

	models.SortFindings(merged)
	return merged, errs
}

// mergeDuplicates folds findings sharing a fingerprint into one, keeping the
// most severe and most confident reading and the union of their evidence.
func mergeDuplicates(in []models.Finding) []models.Finding {
	order := make([]string, 0, len(in))
	byKey := make(map[string]*models.Finding, len(in))

	for i := range in {
		f := in[i]
		key := f.Fingerprint
		existing, ok := byKey[key]
		if !ok {
			copied := f
			copied.Evidence = append([]models.Evidence(nil), f.Evidence...)
			byKey[key] = &copied
			order = append(order, key)
			continue
		}
		mergeInto(existing, f)
	}

	out := make([]models.Finding, 0, len(order))
	for _, key := range order {
		out = append(out, *byKey[key])
	}
	return out
}

// mergeInto folds src into dst, which dst must be a pointer to a value the
// caller owns.
func mergeInto(dst *models.Finding, src models.Finding) {
	if src.Severity.SeverityRank() > dst.Severity.SeverityRank() {
		dst.Severity = src.Severity
	}
	if src.Confidence.ConfidenceRank() > dst.Confidence.ConfidenceRank() {
		dst.Confidence = src.Confidence
	}
	if src.ManualVerificationRequired {
		dst.ManualVerificationRequired = true
		dst.Status = models.StatusNeedsManual
	}
	if !src.FirstSeen.IsZero() && (dst.FirstSeen.IsZero() || src.FirstSeen.Before(dst.FirstSeen)) {
		dst.FirstSeen = src.FirstSeen
	}
	if src.LastSeen.After(dst.LastSeen) {
		dst.LastSeen = src.LastSeen
	}
	dst.Evidence = append(dst.Evidence, src.Evidence...)
	dst.References = unionStrings(dst.References, src.References)
	dst.ManualVerification = unionStrings(dst.ManualVerification, src.ManualVerification)
	dst.Tags = unionStrings(dst.Tags, src.Tags)
	if dst.Remediation == "" {
		dst.Remediation = src.Remediation
	}
	if dst.Impact == "" {
		dst.Impact = src.Impact
	}
}

// corroborate raises confidence when independent sources agree, and lowers it
// when they disagree about whether the observation is even real.
//
// Confidence is the one field the engine is allowed to move on its own,
// because it describes how sure the toolkit is, not how bad the issue is.
// Severity is never touched: a reporter who sees "high, high confidence" and
// "high, low confidence" learns something a severity bump would destroy.
//
// A finding observed by two different modules is not automatically more likely
// to be real, since one signal usually derives from the other. It is raised by
// one step, not to the top, and never above the highest confidence any single
// source claimed plus one.
func corroborate(f models.Finding) models.Finding {
	sources := map[string]struct{}{}
	observations := 0
	for _, ev := range f.Evidence {
		if ev.Source != "" {
			sources[ev.Source] = struct{}{}
		}
		if ev.Summary != "" {
			observations++
		}
	}
	switch {
	case len(sources) >= 2:
		f.Confidence = raiseConfidence(f.Confidence)
	case observations == 0:
		// Nothing backs this up. It should not be recorded as if it did.
		f.Confidence = models.ConfidenceLow
	}
	return f
}

// raiseConfidence steps a confidence up one level, stopping at high. There is
// no level above high: the toolkit never marks its own output as proven, only
// a human closing a ticket can do that.
func raiseConfidence(c models.Confidence) models.Confidence {
	switch c {
	case models.ConfidenceLow:
		return models.ConfidenceMedium
	case models.ConfidenceMedium:
		return models.ConfidenceHigh
	default:
		return c
	}
}

// suppressRedundant drops findings that another already-observed fact makes
// pointless to report.
//
// Reporting an HSTS gap for a host that does not serve HTTPS trains a client
// to ignore the toolkit's output. Noise costs credibility on the findings
// that matter. Redundancy that depends on parsing a header is handled inside
// the rule that owns that header; only cross-rule facts belong here.
func suppressRedundant(in []models.Finding) []models.Finding {
	servesHTTPS := map[string]bool{}
	for _, f := range in {
		if !strings.EqualFold(f.Type, RuleHTTPSPresent) {
			continue
		}
		servesHTTPS[f.Asset] = true
	}
	if len(servesHTTPS) == 0 {
		return in
	}

	out := in[:0:0]
	for _, f := range in {
		// HSTS can only take effect on a host that serves HTTPS at all. On a
		// host that does not, its absence is not a finding.
		if strings.EqualFold(f.Type, RuleMissingHSTS) && !servesHTTPS[f.Asset] {
			continue
		}
		out = append(out, f)
	}
	return out
}

// boundEvidence keeps the most recent evidence items.
func boundEvidence(in []models.Evidence) []models.Evidence {
	if len(in) <= MaxEvidencePerFinding {
		return in
	}
	sorted := append([]models.Evidence(nil), in...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].ObservedAt.After(sorted[j].ObservedAt)
	})
	// Keep the most recent, then restore a stable order for reporting.
	kept := sorted[:MaxEvidencePerFinding]
	sort.SliceStable(kept, func(i, j int) bool {
		if kept[i].ObservedAt.Equal(kept[j].ObservedAt) {
			return kept[i].Summary < kept[j].Summary
		}
		return kept[i].ObservedAt.Before(kept[j].ObservedAt)
	})
	return kept
}

func unionStrings(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, list := range [][]string{a, b} {
		for _, s := range list {
			if s == "" {
				continue
			}
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// Stamp sets FirstSeen and LastSeen on findings that have none, so a rule
// author cannot forget them and produce a finding that will not persist.
func Stamp(findings []models.Finding, at time.Time) []models.Finding {
	for i := range findings {
		if findings[i].FirstSeen.IsZero() {
			findings[i].FirstSeen = at
		}
		if findings[i].LastSeen.IsZero() {
			findings[i].LastSeen = findings[i].FirstSeen
		}
	}
	return findings
}
