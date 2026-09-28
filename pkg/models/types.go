// Package models contains the shared, normalized domain types used across the
// toolkit. Everything that crosses a package boundary (scope engine, storage,
// reporting, plugins) uses these types so that serialization stays stable.
package models

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"
)

// Severity is the impact-oriented classification of a finding.
//
// Severity is NEVER derived automatically from a single heuristic. Detection
// modules propose a severity and a confidence separately, and both are stored
// independently so a human can re-rank later.
type Severity string

const (
	SeverityInformational Severity = "informational"
	SeverityLow           Severity = "low"
	SeverityMedium        Severity = "medium"
	SeverityHigh          Severity = "high"
	SeverityCritical      Severity = "critical"
)

// SeverityRank returns a sortable rank; unknown severities sort lowest.
func (s Severity) SeverityRank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInformational:
		return 1
	default:
		return 0
	}
}

func (s Severity) Valid() bool { return s.SeverityRank() > 0 }

// ParseSeverity normalizes free-form user input (e.g. "INFO", "medium").
func ParseSeverity(in string) (Severity, bool) {
	switch strings.ToLower(strings.TrimSpace(in)) {
	case "info", "informational", "none":
		return SeverityInformational, true
	case "low":
		return SeverityLow, true
	case "medium", "med":
		return SeverityMedium, true
	case "high":
		return SeverityHigh, true
	case "critical", "crit":
		return SeverityCritical, true
	default:
		return "", false
	}
}

// Confidence expresses how strongly the toolkit believes the observation is
// real. It is intentionally independent of Severity.
type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

func (c Confidence) ConfidenceRank() int {
	switch c {
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	case ConfidenceLow:
		return 1
	default:
		return 0
	}
}

func (c Confidence) Valid() bool { return c.ConfidenceRank() > 0 }

// ParseConfidence normalizes free-form user input.
func ParseConfidence(in string) (Confidence, bool) {
	switch strings.ToLower(strings.TrimSpace(in)) {
	case "low", "weak":
		return ConfidenceLow, true
	case "medium", "med", "moderate":
		return ConfidenceMedium, true
	case "high", "strong":
		return ConfidenceHigh, true
	default:
		return "", false
	}
}

// Status is the triage state of a finding.
type Status string

const (
	StatusNew           Status = "new"
	StatusTriaged       Status = "triaged"
	StatusNeedsManual   Status = "needs_manual_verification"
	StatusFalsePositive Status = "false_positive"
	StatusResolved      Status = "resolved"
)

func (s Status) Valid() bool {
	switch s {
	case StatusNew, StatusTriaged, StatusNeedsManual, StatusFalsePositive, StatusResolved:
		return true
	default:
		return false
	}
}

// TargetKind enumerates the kinds of asset a plugin or stage can operate on.
type TargetKind string

const (
	TargetDomain    TargetKind = "domain"
	TargetSubdomain TargetKind = "subdomain"
	TargetIP        TargetKind = "ip"
	TargetCIDR      TargetKind = "cidr"
	TargetURL       TargetKind = "url"
	TargetIPRange   TargetKind = "ip_range"
)

// Target is the unit of work handed to plugins and pipeline stages.
type Target struct {
	Kind  TargetKind          `json:"kind"`
	Value string              `json:"value"`
	Meta  map[string]string   `json:"meta,omitempty"`
	Scope string              `json:"scope,omitempty"` // the scope rule that admitted this target
	Refs  map[string][]string `json:"refs,omitempty"`  // graph links, e.g. service -> endpoint
}

func (t Target) Clone() Target {
	c := t
	c.Meta = copyStrMap(t.Meta)
	if t.Refs != nil {
		c.Refs = make(map[string][]string, len(t.Refs))
		for k, v := range t.Refs {
			cp := make([]string, len(v))
			copy(cp, v)
			c.Refs[k] = cp
		}
	}
	return c
}

func copyStrMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// Observation is a single fact learned by a plugin. Observations are
// untrusted input from the network: they are always re-validated by the scope
// engine before they are persisted.
type Observation struct {
	Type      string            `json:"type"`
	Asset     string            `json:"asset"`
	Source    string            `json:"source"`
	Data      map[string]string `json:"data,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
	// Confidence of the observation itself (e.g. a provider returning a name
	// derived from a wildcard cert gets lower confidence than a direct A record).
	Confidence Confidence `json:"confidence,omitempty"`
}

// Evidence is an immutable observation backing a finding. Evidence payloads are
// always passed through the redactor before they reach storage or a report.
type Evidence struct {
	ID         int64             `json:"id,omitempty"`
	FindingID  string            `json:"finding_id,omitempty"`
	Source     string            `json:"source"`
	Summary    string            `json:"summary"`
	Data       map[string]string `json:"data,omitempty"`
	Redacted   bool              `json:"redacted,omitempty"`
	ObservedAt time.Time         `json:"observed_at"`
}

// Finding is the normalized unit of output of the finding engine.
type Finding struct {
	ID          string     `json:"id"`
	Fingerprint string     `json:"fingerprint"`
	Type        string     `json:"type"`
	Title       string     `json:"title"`
	Severity    Severity   `json:"severity"`
	Confidence  Confidence `json:"confidence"`
	Asset       string     `json:"asset"`
	Endpoint    string     `json:"endpoint,omitempty"`

	// WHY_IT_WAS_FLAGGED
	Description string `json:"description"`
	// WHAT_TO_VERIFY_MANUALLY
	ManualVerification []string `json:"manual_verification_steps"`
	// POSSIBLE_IMPACT
	Impact string `json:"possible_impact"`
	// REMEDIATION
	Remediation string   `json:"remediation,omitempty"`
	References  []string `json:"references,omitempty"`

	Evidence []Evidence `json:"evidence,omitempty"`
	Status   Status     `json:"status"`
	Tags     []string   `json:"tags,omitempty"`
	Source   string     `json:"source"`
	// ManualVerificationRequired is true for anything that would need a human
	// to confirm. The toolkit never auto-verifies exploitability.
	ManualVerificationRequired bool `json:"manual_verification_required"`
	// RunID ties a finding to the engagement that produced it, so a report
	// can cover one run rather than everything ever stored. It is empty for a
	// finding that did not come from a scan.
	RunID     string    `json:"run_id,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Validate enforces the invariants every finding must satisfy before it can be
// persisted. It is deliberately strict: bad data must never reach the database.
func (f *Finding) Validate() error {
	if strings.TrimSpace(f.ID) == "" {
		return ErrFindingNoID
	}
	if strings.TrimSpace(f.Type) == "" {
		return ErrFindingNoType
	}
	if !f.Severity.Valid() {
		return ErrFindingBadSeverity
	}
	if !f.Confidence.Valid() {
		return ErrFindingBadConfidence
	}
	if !f.Status.Valid() {
		f.Status = StatusNew
	}
	if f.FirstSeen.IsZero() {
		return ErrFindingNoFirstSeen
	}
	if f.LastSeen.IsZero() {
		f.LastSeen = f.FirstSeen
	}
	if len(f.ManualVerification) == 0 && f.ManualVerificationRequired {
		return ErrFindingNoVerificationSteps
	}
	return nil
}

// ComputeFingerprint computes the stable identity of a finding. Two findings with the
// same type, asset, endpoint and tags are the same finding no matter which
// module produced them or how many times it was seen. Tags act as a
// discriminator so one rule can report several distinct problems on a single
// asset without them collapsing together.
//
// It lives here rather than in the storage layer so the finding engine can
// deduplicate without depending on the database driver.
func (f *Finding) ComputeFingerprint() string {
	key := strings.Join([]string{
		strings.ToLower(f.Type),
		strings.ToLower(f.Asset),
		strings.ToLower(f.Endpoint),
		strings.ToLower(strings.Join(f.Tags, ",")),
	}, "|")
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// SortFindings orders findings by severity, then confidence, then asset.
func SortFindings(in []Finding) {
	sort.SliceStable(in, func(i, j int) bool {
		a, b := in[i], in[j]
		if a.Severity.SeverityRank() != b.Severity.SeverityRank() {
			return a.Severity.SeverityRank() > b.Severity.SeverityRank()
		}
		if a.Confidence.ConfidenceRank() != b.Confidence.ConfidenceRank() {
			return a.Confidence.ConfidenceRank() > b.Confidence.ConfidenceRank()
		}
		return a.Asset < b.Asset
	})
}
