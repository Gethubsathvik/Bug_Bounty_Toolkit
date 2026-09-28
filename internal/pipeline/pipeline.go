// Package pipeline runs an engagement as a sequence of stages and turns what
// they observed into findings and a report.
//
// The pipeline owns three responsibilities that no individual module does:
//
//   - it decides which stages may run at all, so a passive engagement can
//     never reach a stage that would touch a target;
//   - it records every stage's outcome, so a run that could not finish says so
//     rather than looking like a clean result;
//   - it carries an incomplete run's warnings all the way into the report,
//     because the most damaging artefact in security testing is a report that
//     looks complete when it was not.
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/bbtoolkit/bugbounty/internal/findings"
	"github.com/bbtoolkit/bugbounty/internal/fingerprint"
	"github.com/bbtoolkit/bugbounty/internal/ratelimit"
	"github.com/bbtoolkit/bugbounty/internal/recon"
	"github.com/bbtoolkit/bugbounty/internal/report"
	"github.com/bbtoolkit/bugbounty/internal/scope"
	"github.com/bbtoolkit/bugbounty/internal/storage"
	"github.com/bbtoolkit/bugbounty/pkg/models"
)

// Stage names. They are recorded in the database and appear in stage state
// rows, so they are part of the stored contract.
const (
	StagePassiveRecon = "passive-recon"
	StageDNS          = "dns"
	StageHTTP         = "http"
	StageFingerprint  = "fingerprint"
	StageCrawl        = "crawl"
	StageFindings     = "findings"
	StageReport       = "report"
)

// allStages is the fixed order. Order matters: discovery feeds the stages that
// act on what was discovered, and the finding engine must see every stage's
// output before it runs.
var allStages = []string{
	StagePassiveRecon,
	StageDNS,
	StageHTTP,
	StageFingerprint,
	StageCrawl,
	StageFindings,
	StageReport,
}

// ErrNoStages is returned when a pipeline is asked to run nothing.
var ErrNoStages = errors.New("pipeline: no stages to run")

// ErrNoScope is returned when a run is attempted without a scope engine.
var ErrNoScope = errors.New("pipeline: a scope engine is required; a run without one is an indiscriminate scanner")

// Observation is what a stage hands on. Stages fill only the parts they
// produced, and every stage's output is redacted before it is stored.
type Observation struct {
	HTTP      []models.HTTPSvc
	DNS       []models.DNSResult
	Posture   []models.SecurityPosture
	Endpoints []models.Endpoint
	Tech      []fingerprint.Hit
	Assets    []recon.Asset
	// Warnings are problems the stage hit that did not stop it. They travel
	// into the report.
	Warnings []string
	// Err is a fatal problem for this stage only.
	Err error
}

// Stage is one unit of work.
type Stage struct {
	// Name identifies the stage in stored state and in the report.
	Name string
	// Active marks a stage that contacts the target. A passive-only engagement
	// refuses to run any active stage, and says so rather than skipping it
	// silently.
	Active bool
	// Run performs the stage. It receives the scope engine, the rate limiter
	// and everything earlier stages observed.
	Run func(ctx context.Context, in Input) (Observation, error)
}

// Input is a stage's view of the run.
type Input struct {
	Scope  *scope.Engine
	Limit  *ratelimit.Limiter
	Client HTTPDoer
	// Seed is the domain or URL the engagement started from.
	Seed string
	// Observed is the merged output of every stage that ran before this one.
	Observed Observation
	// PassiveOnly is true when the operator authorised no contact.
	PassiveOnly bool
	// Now is the injected clock.
	Now time.Time
}

// HTTPDoer is the request capability a stage may use. It is the scoped client
// in a real run; the interface exists so a test can supply a stub.
type HTTPDoer interface {
	Do(ctx context.Context, req Request) (*Response, error)
}

// Request and Response mirror the transport's types without importing it, so
// the pipeline does not depend on a particular HTTP implementation.
type Request struct {
	URL               string
	Method            string
	Headers           map[string]string
	TruncateBody      bool
	NoFollowRedirects bool
}

// Response is a bounded HTTP result.
type Response struct {
	URL         string
	StatusCode  int
	ContentType string
	Title       string
	Header      map[string][]string
	Body        []byte
	TLS         *models.TLSInfo
	IPs         []string
	CNAME       string
	Tech        []string
	FinalURL    string
	Observed    time.Time
	Note        string
}

// Result is the outcome of a whole run.
type Result struct {
	RunID     string
	StartedAt time.Time
	EndedAt   time.Time
	// Findings are the correlated, redacted findings.
	Findings []models.Finding
	// Reports are the rendered reports, keyed by format.
	Reports map[string][]byte
	// StageStatus records what each stage did.
	StageStatus []storage.StageStatusRecord
	// Warnings collects everything that would otherwise make an incomplete run
	// look like a clean one.
	Warnings []string
	// Err is set when the run could not proceed at all.
	Err error
}

// Options configures a run.
type Options struct {
	// RunID identifies the run. One is generated when empty.
	RunID string
	// StagesToRun selects stages by name. Empty means all.
	StagesToRun []string
	// Rules selects finding rules by ID. Empty means all.
	Rules []string
	// ReportFormats are rendered at the end. Empty means none.
	ReportFormats []string
	// Seed is the domain or URL under test.
	Seed string
	// PassiveOnly forbids every active stage.
	PassiveOnly bool
	// Store persists the run. It may be nil for a dry run.
	Store *storage.Store
	// Engagement labels the report.
	Engagement string
	// Profile names the configuration profile.
	Profile string
	// Now is the injected clock.
	Now time.Time
	// Resume allows a run to continue from recorded stage state.
	Resume bool
}

// Pipeline runs a fixed set of stages.
type Pipeline struct {
	stages []Stage
}

// New builds a pipeline from stages, ordering them by the canonical stage
// order and rejecting an unknown or duplicated name.
func New(stages ...Stage) (*Pipeline, error) {
	known := stageOrder()
	seen := map[string]struct{}{}
	ordered := make([]Stage, 0, len(stages))
	for _, s := range stages {
		if _, ok := known[s.Name]; !ok {
			return nil, fmt.Errorf("pipeline: unknown stage %q", s.Name)
		}
		if _, dup := seen[s.Name]; dup {
			return nil, fmt.Errorf("pipeline: stage %q registered twice", s.Name)
		}
		if s.Run == nil {
			return nil, fmt.Errorf("pipeline: stage %q has no Run function", s.Name)
		}
		seen[s.Name] = struct{}{}
		ordered = append(ordered, s)
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		return known[ordered[i].Name] < known[ordered[j].Name]
	})
	if len(ordered) == 0 {
		return nil, ErrNoStages
	}
	return &Pipeline{stages: ordered}, nil
}

func stageOrder() map[string]int {
	m := make(map[string]int, len(allStages))
	for i, s := range allStages {
		m[s] = i
	}
	return m
}

// AllStageNames lists every stage the pipeline can run, in execution order.
func AllStageNames() []string { return append([]string(nil), allStages...) }

// SeedHost reduces a scan target to a bare host name, which is what the scope
// engine's host rules match against. A target given as a URL is accepted; a
// target that is neither a URL nor a plausible host yields the empty string,
// which matches nothing.
func SeedHost(target string) string {
	target = strings.TrimSpace(strings.ToLower(target))
	if target == "" {
		return ""
	}
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		target = u.Hostname()
	}
	if i := strings.IndexAny(target, "/?#"); i >= 0 {
		target = target[:i]
	}
	if i := strings.Index(target, ":"); i >= 0 {
		target = target[:i]
	}
	return strings.TrimSuffix(target, ".")
}

// StageNames lists the pipeline's stages in execution order.
func (p *Pipeline) StageNames() []string {
	out := make([]string, 0, len(p.stages))
	for _, s := range p.stages {
		out = append(out, s.Name)
	}
	return out
}

// Run executes the pipeline.
//
// A stage failure is recorded and the run continues, because one unavailable
// source or one refused request should not discard the evidence the other
// stages gathered. What it must never do is let the run finish looking
// complete, so every failure becomes a warning that reaches the report.
func (p *Pipeline) Run(ctx context.Context, in Input, opts Options) *Result {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	runID := opts.RunID
	if runID == "" {
		runID = fmt.Sprintf("run-%d", now.UTC().UnixNano())
	}

	res := &Result{
		RunID:     runID,
		StartedAt: now,
		Reports:   map[string][]byte{},
	}
	// A pipeline with no scope engine is an indiscriminate scanner, so this is
	// refused outright rather than defaulted to something permissive.
	if in.Scope == nil {
		res.Err = ErrNoScope
		res.EndedAt = now
		return res
	}

	// Either signal can forbid contact; neither can permit it. The operator's
	// flag, the configuration and the scope file are all allowed to say
	// "passive", and it takes only one of them to bind every stage. Trusting
	// the run options alone would mean a scope file marked passive-only was
	// silently overridden by a command line that forgot the flag.
	if opts.PassiveOnly || in.PassiveOnly || in.Scope.PassiveOnly() {
		in.PassiveOnly = true
	}
	in.Now = now

	selected := p.select_(opts.StagesToRun)
	if len(selected) == 0 {
		res.Err = ErrNoStages
		res.EndedAt = now
		return res
	}

	// Resume skips stages that a previous run recorded as completed. It never
	// skips a stage that failed, because the failure is why it is worth
	// retrying.
	completed := map[string]bool{}
	if opts.Resume && opts.Store != nil {
		completed = p.completedStages(ctx, opts.Store, runID)
		if len(completed) > 0 {
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("resuming: %d stage(s) skipped because a previous run completed them", len(completed)))
		}
	}

	stageErrs := make(chan error, len(selected))
	for i, stage := range selected {
		seq := i
		rec := storage.StageStatusRecord{
			Run:    runID,
			Name:   stage.Name,
			Seq:    seq,
			Status: storage.StagePending,
		}

		if completed[stage.Name] {
			rec.Status = storage.StageSkipped
			res.StageStatus = append(res.StageStatus, rec)
			continue
		}

		// A passive-only engagement must refuse an active stage visibly. The
		// operator asked for a promise the stage cannot keep, and the only
		// honest outcome is to say the stage was not run and why.
		if stage.Active && in.PassiveOnly {
			rec.Status = storage.StageSkipped
			rec.Error = "passive-only engagement: this stage contacts the target and was not run"
			res.StageStatus = append(res.StageStatus, rec)
			res.Warnings = append(res.Warnings, fmt.Sprintf(
				"stage %q was skipped: it contacts the target, and this engagement is passive-only", stage.Name))
			continue
		}

		rec.Status = storage.StageRunning
		rec.StartedAt = now
		p.record(ctx, opts, rec)

		out, err := runStage(ctx, stage, in)
		rec.FinishedAt = time.Now()
		switch {
		case err != nil:
			rec.Status = storage.StageFailed
			rec.Error = err.Error()
			res.Warnings = append(res.Warnings, fmt.Sprintf("stage %q failed: %v", stage.Name, err))
			stageErrs <- err
		default:
			rec.Status = storage.StageCompleted
			rec.Error = ""
		}
		mergeObservation(&in.Observed, out)
		res.Warnings = append(res.Warnings, out.Warnings...)
		res.StageStatus = append(res.StageStatus, rec)
		p.record(ctx, opts, rec)
	}
	close(stageErrs)

	res.Findings = p.evaluate(ctx, in, opts)
	res.Reports = p.render(res, in, opts)
	res.EndedAt = time.Now()
	if res.EndedAt.Before(res.StartedAt) {
		res.EndedAt = res.StartedAt
	}

	if opts.Store != nil {
		status := storage.RunCompleted
		if len(res.Warnings) > 0 {
			// A run with warnings is still a run that finished, but it is not
			// a clean one. Recording it as resumable means the next invocation
			// retries the stages that did not succeed.
			status = storage.RunResumable
		}
		_ = opts.Store.FinishRun(ctx, runID, status, map[string]any{
			"findings": len(res.Findings),
			"warnings": len(res.Warnings),
			"stages":   len(res.StageStatus),
			"passive":  in.PassiveOnly,
		})
	}

	if len(res.Warnings) == 0 {
		res.Warnings = append(res.Warnings, "")
		res.Warnings = res.Warnings[:0]
	}
	return res
}

// select_ applies the stage filter. The name ends in an underscore because
// select is a keyword.
func (p *Pipeline) select_(names []string) []Stage {
	if len(names) == 0 {
		return p.stages
	}
	want := make(map[string]struct{}, len(names))
	for _, n := range names {
		want[n] = struct{}{}
	}
	var out []Stage
	for _, s := range p.stages {
		if _, ok := want[s.Name]; ok {
			out = append(out, s)
		}
	}
	return out
}

func (p *Pipeline) completedStages(ctx context.Context, s *storage.Store, runID string) map[string]bool {
	out := map[string]bool{}
	states, err := s.StageStates(ctx, runID)
	if err != nil {
		return out
	}
	for _, st := range states {
		if st.Status == storage.StageCompleted {
			out[st.Name] = true
		}
	}
	return out
}

func (p *Pipeline) record(ctx context.Context, opts Options, rec storage.StageStatusRecord) {
	if opts.Store == nil {
		return
	}
	_ = opts.Store.SetStageState(ctx, rec)
}

// runStage isolates a stage so a panic in one module cannot take down the run
// and lose everything the earlier stages found.
func runStage(ctx context.Context, s Stage, in Input) (out Observation, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("stage panicked: %v", rec)
			out = Observation{}
		}
	}()
	if err := ctx.Err(); err != nil {
		return Observation{}, err
	}
	o, err := s.Run(ctx, in)
	return o, err
}

// mergeObservation folds a stage's output into the accumulated observation.
func mergeObservation(dst *Observation, src Observation) {
	dst.HTTP = append(dst.HTTP, src.HTTP...)
	dst.DNS = append(dst.DNS, src.DNS...)
	dst.Posture = append(dst.Posture, src.Posture...)
	dst.Endpoints = append(dst.Endpoints, src.Endpoints...)
	dst.Tech = append(dst.Tech, src.Tech...)
	dst.Assets = append(dst.Assets, src.Assets...)
	dst.Warnings = append(dst.Warnings, src.Warnings...)
}

// evaluate runs the finding engine over everything observed.
func (p *Pipeline) evaluate(ctx context.Context, in Input, opts Options) []models.Finding {
	engine := findings.DefaultEngine()
	if len(opts.Rules) > 0 {
		engine = engine.Filter(opts.Rules)
	}
	produced, errs := engine.Evaluate(ctx, findings.Input{
		Asset:     in.Seed,
		HTTP:      in.Observed.HTTP,
		DNS:       in.Observed.DNS,
		Posture:   in.Observed.Posture,
		Endpoints: in.Observed.Endpoints,
		Tech:      in.Observed.Tech,
		Now:       in.Now,
	})
	// Engine errors are dropped findings, and a dropped finding is a gap in
	// the report. They become warnings rather than vanishing.
	for _, err := range errs {
		in.Observed.Warnings = append(in.Observed.Warnings, "finding engine: "+err.Error())
	}
	return produced
}

// render produces the requested report formats.
func (p *Pipeline) render(res *Result, in Input, opts Options) map[string][]byte {
	out := map[string][]byte{}
	if len(opts.ReportFormats) == 0 {
		return out
	}
	allowed, excluded := in.Scope.Rules()
	scopeRules := make([]string, 0, len(allowed))
	for _, r := range allowed {
		scopeRules = append(scopeRules, r.String())
	}
	exclusions := make([]string, 0, len(excluded))
	for _, r := range excluded {
		exclusions = append(exclusions, r.String())
	}

	rep := report.Report{
		Metadata: report.Metadata{
			Engagement:  opts.Engagement,
			RunID:       res.RunID,
			Seed:        opts.Seed,
			Scope:       scopeRules,
			Exclusions:  exclusions,
			StartedAt:   res.StartedAt,
			FinishedAt:  res.EndedAt,
			PassiveOnly: in.PassiveOnly,
			Warnings:    res.Warnings,
		},
		Findings: res.Findings,
	}
	for _, format := range opts.ReportFormats {
		rd, err := report.New(format)
		if err != nil {
			res.Warnings = append(res.Warnings, "report: "+err.Error())
			continue
		}
		b, err := rd.Render(rep)
		if err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("report %s: %v", format, err))
			continue
		}
		// Keyed on the normalised name, not the text the operator typed.
		// report.New accepts "MD", "Markdown" and "md" alike, and the CLI looks
		// the rendered report up by its lowercased name. Keying on the raw
		// string let --report Markdown render perfectly and then report
		// "was not produced" -- a format the tool accepts but cannot deliver.
		out[strings.ToLower(strings.TrimSpace(format))] = b
	}
	return out
}

// Sprint returns a one-line description of a run's outcome, for logs.
func (r *Result) Sprint() string {
	counts := map[models.Severity]int{}
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	var parts []string
	for _, sev := range []models.Severity{
		models.SeverityCritical, models.SeverityHigh, models.SeverityMedium,
		models.SeverityLow, models.SeverityInformational,
	} {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	if len(parts) == 0 {
		return "no findings"
	}
	return strings.Join(parts, ", ")
}
