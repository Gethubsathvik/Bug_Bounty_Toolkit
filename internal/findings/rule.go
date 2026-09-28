// Package findings turns collected observations into normalized, deduplicated
// findings.
//
// The engine is deliberately conservative. It reports what it can evidence and
// nothing more: severity comes from a rule, never from arithmetic on how many
// signals fired, and anything that would need a human to confirm is marked as
// requiring manual verification rather than being asserted as a result.
//
// Every piece of free text that leaves this package passes through the
// redactor, because evidence is built from attacker-controlled response
// bodies, header values and parameter names.
package findings

import (
	"context"
	"time"

	"github.com/bbtoolkit/bugbounty/internal/fingerprint"
	"github.com/bbtoolkit/bugbounty/pkg/models"
)

// Input is everything a rule may look at. It is a plain value so a rule
// cannot reach back into the running pipeline, and so a test can build the
// exact scenario it cares about.
type Input struct {
	// Asset is the host or URL the whole batch belongs to.
	Asset string
	// HTTP is one record per probed HTTP endpoint.
	HTTP []models.HTTPSvc
	// DNS is one record per collected DNS name.
	DNS []models.DNSResult
	// Posture is one record per assessed DNS zone.
	Posture []models.SecurityPosture
	// Endpoints is the crawler's endpoint inventory.
	Endpoints []models.Endpoint
	// Tech is the fingerprint match set for the primary URL.
	Tech []fingerprint.Hit
	// Baseline is the operator's technology support table. A nil Baseline
	// means no currency rule can fire, which is the safe default.
	Baseline *Baseline
	// Now is the observation time stamped onto generated findings. It is
	// injected rather than read from the clock so output is deterministic.
	Now time.Time
}

// Result is one thing a rule noticed. A rule may return several results, and
// several rules may describe the same underlying problem.
type Result struct {
	// Asset overrides Input.Asset when a rule notices something on a
	// different host, such as a CNAME target.
	Asset string
	// Endpoint narrows the finding to a specific URL when applicable.
	Endpoint string
	// Summary is the one-line human explanation of what was observed.
	Summary string
	// Data is structured supporting detail. Values are scrubbed on the way out.
	Data map[string]string
	// Severity and Confidence override the rule's defaults when the evidence
	// genuinely differs, such as an expired certificate on a login page versus
	// on an unused host.
	Severity   *models.Severity
	Confidence *models.Confidence
	// Tags extend the rule's own tags for this result. They are part of the
	// dedup fingerprint, so a rule that reports one finding per item must
	// discriminate here or the correlator will merge distinct items into one.
	Tags []string
	// Evidence is any additional supporting records, beyond the one the
	// engine builds from Summary and Data.
	Evidence []models.Evidence
}

// Rule is a single check. Check must be pure with respect to its input and
// must respect ctx; it is never allowed to perform network access, since the
// stage that gathered the data already decided what is in scope.
type Rule struct {
	// ID is stable across releases and appears in reports and in the
	// suppress list, so it must never be reused for a different meaning.
	ID string
	// Title is a short human label.
	Title string
	// Type is the finding type recorded on the finding. It defaults to ID.
	Type string
	// Severity is the default severity for everything this rule reports.
	Severity models.Severity
	// Confidence is the default confidence for everything this rule reports.
	Confidence models.Confidence
	// Description explains why this matters, in the reporter's words.
	Description string
	// ManualVerification lists what a human must check to turn this into a
	// confirmed issue. A rule that cannot be verified by observation alone
	// should set ManualVerificationRequired.
	ManualVerification []string
	// Impact describes the plausible consequence if the issue is real.
	Impact string
	// Remediation is the fix, or a pointer to it.
	Remediation string
	// References are supporting URLs.
	References []string
	// Tags are used both for reporting and as part of the dedup fingerprint.
	// Two findings of the same type on the same asset with different tags are
	// deliberately kept apart.
	Tags []string
	// ManualVerificationRequired marks findings that a human must confirm
	// before they are reported as a result.
	ManualVerificationRequired bool
	// Check inspects the input and returns what it found.
	Check func(ctx context.Context, in Input) []Result
}

func (r Rule) findingType() string {
	if r.Type != "" {
		return r.Type
	}
	return r.ID
}

// sourceFor names the module a result came from, so the report can attribute
// it and so the correlator can tell two independent observations apart.
func (r Rule) sourceFor(res Result) string {
	for _, ev := range res.Evidence {
		if ev.Source != "" {
			return ev.Source
		}
	}
	return r.ID
}
