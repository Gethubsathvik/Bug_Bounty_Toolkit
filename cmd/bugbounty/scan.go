package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/bbtoolkit/bugbounty/internal/config"
	"github.com/bbtoolkit/bugbounty/internal/dns"
	"github.com/bbtoolkit/bugbounty/internal/fingerprint"
	httpclient "github.com/bbtoolkit/bugbounty/internal/http"
	"github.com/bbtoolkit/bugbounty/internal/pipeline"
	"github.com/bbtoolkit/bugbounty/internal/ratelimit"
	"github.com/bbtoolkit/bugbounty/internal/recon"
	"github.com/bbtoolkit/bugbounty/internal/report"
	"github.com/bbtoolkit/bugbounty/internal/scope"
	"github.com/bbtoolkit/bugbounty/internal/storage"
	"github.com/spf13/cobra"
)

type scanFlags struct {
	scopeFile   string
	excludeFile string
	passiveOnly bool
	insecure    bool
	rateLimit   float64
	concurrency int
	timeout     time.Duration
	stages      []string
	rules       []string
	formats     []string
	providers   []string
	noDatabase  bool
	resume      bool
	runID       string
	engagement  string
	outputFile  string
	dryRun      bool
}

func newScanCommand(g *globalFlags) *cobra.Command {
	f := &scanFlags{}

	cmd := &cobra.Command{
		Use:   "scan <target>",
		Short: "Run an assessment against an in-scope target",
		Long: strings.TrimSpace(`
Run the pipeline against a target that is already covered by a scope file.

The target must be inside the scope. No flag widens scope for a single run,
because scope is the one thing that has to stay deliberate: a typo in a
hostname must never become authorisation to test a stranger's domain.

Everything the run could not complete is reported as a warning, and those
warnings appear in every output format. A run with warnings is an incomplete
result, not a clean one.`),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd, g, f, args[0])
		},
	}

	fl := cmd.Flags()
	fl.StringVar(&f.scopeFile, "scope", "", "path to the scope file defining what may be tested (required)")
	fl.StringVar(&f.excludeFile, "exclude", "", "additional file of rules to exclude; it can only narrow the scope")
	fl.BoolVar(&f.passiveOnly, "passive-only", false, "run no active stage and contact no target at all")
	fl.BoolVar(&f.insecure, "insecure", false, "skip TLS certificate verification; command line only, never read from a file")
	fl.Float64Var(&f.rateLimit, "rate", 0, "requests per second; overrides the configuration")
	fl.IntVar(&f.concurrency, "concurrency", 0, "maximum concurrent requests; overrides the configuration")
	fl.DurationVar(&f.timeout, "timeout", 0, "overall time limit for the run")
	fl.StringSliceVar(&f.stages, "stage", nil, "run only these stages: "+strings.Join(pipeline.AllStageNames(), ", "))
	fl.StringSliceVar(&f.rules, "rule", nil, "run only these finding rules")
	fl.StringSliceVar(&f.formats, "report", []string{report.FormatMarkdown, report.FormatJSON}, "report formats to write")
	fl.StringSliceVar(&f.providers, "provider", nil, "passive sources to use: certtransparency")
	fl.BoolVar(&f.noDatabase, "no-db", false, "do not open the database; nothing is persisted")
	fl.BoolVar(&f.resume, "resume", false, "continue the last resumable run for this target, skipping stages it already completed")
	fl.StringVar(&f.runID, "run", "", "with --resume, continue this specific run instead of the most recent one")
	fl.StringVar(&f.engagement, "engagement", "", "client or programme name recorded in the report")
	fl.StringVar(&f.outputFile, "output-file", "", "write the first report to this exact path instead of the default name")
	fl.BoolVar(&f.dryRun, "dry-run", false, "validate the configuration and scope, then exit without scanning")

	if err := cmd.MarkFlagRequired("scope"); err != nil {
		panic(err)
	}
	return cmd
}

func runScan(cmd *cobra.Command, g *globalFlags, f *scanFlags, target string) error {
	cfg, err := g.loadConfig()
	if err != nil {
		return err
	}
	applyScanOverrides(&cfg, f)

	// The scope is built before anything else can happen, so a run that is not
	// authorised never reaches a network call.
	sc, sources, err := buildScope(f.scopeFile, f.excludeFile, cfg)
	if err != nil {
		return err
	}
	sc.SetSourcePath(f.scopeFile)
	for _, w := range sc.Warnings() {
		failc(cmd, "scope warning: %s", w)
	}

	if !sc.HostInScope(pipeline.SeedHost(target)) && !targetInScope(sc, target) {
		return fmt.Errorf("SECURITY: %q is not covered by the scope file; refusing to scan it", target)
	}

	// Checked before the dry-run exit, so validating the combination does not
	// depend on how far the command happens to get. Resuming reads recorded
	// stage state, so there has to be a database to read it from; accepting the
	// combination and quietly scanning from scratch would look exactly like a
	// resume that worked.
	if f.resume && f.noDatabase {
		return errors.New("--resume needs the recorded run history, but --no-db was given; drop one or the other")
	}

	if f.dryRun {
		printDryRun(cmd, target, sc, cfg, f)
		return nil
	}

	deps, limit, err := buildDependencies(cmd, cfg, sc, sources, f)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if f.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, f.timeout)
		defer cancel()
	}

	runID := fmt.Sprintf("run-%d", time.Now().UTC().UnixNano())
	opts := pipeline.Options{
		RunID:         runID,
		StagesToRun:   f.stages,
		Rules:         f.rules,
		ReportFormats: f.formats,
		Seed:          target,
		PassiveOnly:   cfg.PassiveOnly,
		Engagement:    f.engagement,
		Profile:       g.profile,
		Resume:        f.resume,
	}

	// Resuming reads recorded stage state, so there has to be a database to
	// read it from. Checked above, before the dry-run exit.
	var store *storage.Store
	if !f.noDatabase {
		store, err = storage.Open(ctx, storage.Options{Path: cfg.Database.Path})
		if err != nil {
			return fmt.Errorf("opening the database: %w", err)
		}
		defer store.Close()
		opts.Store = store

		// Resume has to be resolved before the run is created, because a
		// resumed run continues the *existing* run id. Minting a fresh one and
		// then asking for its stage history would find nothing, so --resume
		// would quietly rescan everything from the start.
		if f.resume {
			prev, err := resolveResume(ctx, store, f.runID, target)
			if err != nil {
				return err
			}
			runID = prev.ID
			opts.RunID = prev.ID
			// The row already exists: StartRun would reject the duplicate id,
			// which is the correct behaviour for a genuinely new run but not
			// for this one. The stage history it holds is the point.
			if !g.quiet {
				failc(cmd, "resuming run %s (started %s)", prev.ID, prev.StartedAt.Format(time.RFC3339))
			}
		} else {
			if err := store.StartRun(ctx, storage.ScanRun{
				ID:        runID,
				Name:      target,
				Profile:   g.profile,
				ScopeFile: f.scopeFile,
				Status:    storage.RunRunning,
				Config:    describeConfig(cfg),
			}); err != nil {
				return fmt.Errorf("recording the run: %w", err)
			}
		}
	}

	pipe, err := pipeline.New(pipeline.DefaultStages(deps)...)
	if err != nil {
		return err
	}

	if !g.quiet {
		failc(cmd, "scanning %s (run %s)%s", target, runID, passiveNote(cfg.PassiveOnly))
	}
	res := pipe.Run(ctx, pipeline.Input{
		Scope:       sc,
		Limit:       limit,
		Seed:        target,
		PassiveOnly: cfg.PassiveOnly,
	}, opts)

	// Findings are persisted even on failure. A run cancelled after twenty
	// minutes of work should not throw the evidence away.
	if store != nil {
		saveFindings(context.WithoutCancel(ctx), store, res)
	}

	if !g.quiet {
		failc(cmd, "%s", res.Sprint())
		for _, w := range res.Warnings {
			failc(cmd, "warning: %s", w)
		}
	}
	if res.Err != nil {
		return res.Err
	}
	return writeReports(cmd, res, cfg, f, g)
}

// resolveResume decides which recorded run a --resume invocation continues.
//
// A run is only a candidate if it is for the same target. Continuing some other
// run would attach this target's findings to another engagement's report, and
// for a tool whose purpose is keeping engagements separate that is worse than
// starting over.
func resolveResume(ctx context.Context, store *storage.Store, wantID, target string) (storage.ScanRun, error) {
	if wantID != "" {
		prev, err := store.GetRun(ctx, wantID)
		if err != nil {
			return storage.ScanRun{}, fmt.Errorf("run %s cannot be resumed: %w", wantID, err)
		}
		if prev.Status == storage.RunCompleted {
			return storage.ScanRun{}, fmt.Errorf(
				"run %s already completed; it has no unfinished stages to continue", wantID)
		}
		if prev.Name != "" && prev.Name != target {
			return storage.ScanRun{}, fmt.Errorf(
				"run %s is for target %q, not %q; resuming it would file these findings under the wrong engagement",
				wantID, prev.Name, target)
		}
		return prev, nil
	}

	prev, err := store.LatestResumableRun(ctx)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			// Wrapped rather than replaced, so the message is actionable and
			// the sentinel is still available to a caller that checks.
			return storage.ScanRun{}, fmt.Errorf(
				"--resume found no previous run to continue; this would be a fresh run, so omit --resume: %w",
				storage.ErrNotFound)
		}
		return storage.ScanRun{}, fmt.Errorf("looking for a run to resume: %w", err)
	}
	if prev.Name != "" && prev.Name != target {
		return storage.ScanRun{}, fmt.Errorf(
			"the only resumable run (%s) is for target %q, not %q; continuing it would file these findings under the wrong engagement",
			prev.ID, prev.Name, target)
	}
	return prev, nil
}

// targetInScope reports whether a scan target is covered, accepting either a
// bare host or a full URL.
func targetInScope(sc *scope.Engine, target string) bool {
	u, err := url.Parse(target)
	if err != nil {
		return false
	}
	if u.Scheme == "" || u.Host == "" {
		u = &url.URL{Scheme: "https", Host: target}
	}
	return sc.URLInScope(u)
}

// saveFindings upserts every finding, recording a failure rather than
// returning it, because losing persistence should not discard a completed
// assessment's output.
func saveFindings(ctx context.Context, store *storage.Store, res *pipeline.Result) {
	for i := range res.Findings {
		if _, _, err := store.UpsertFinding(ctx, res.Findings[i]); err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("persisting finding %s: %v", res.Findings[i].Type, err))
		}
	}
}

func passiveNote(passive bool) string {
	if passive {
		return " in PASSIVE-ONLY mode; no target will be contacted"
	}
	return ""
}

func applyScanOverrides(cfg *config.Config, f *scanFlags) {
	if f.passiveOnly {
		cfg.PassiveOnly = true
	}
	if f.rateLimit > 0 {
		cfg.Limits.RequestsPerSecond = f.rateLimit
	}
	if f.concurrency > 0 {
		cfg.Limits.Concurrency = f.concurrency
	}
	if f.insecure {
		// Only the command line may do this, and only because the operator
		// watches it happen. The configuration loader refuses the same setting
		// so that it cannot be committed to a repository and forgotten.
		cfg.HTTP.InsecureSkipVerify = true
	}
}

// buildScope reads the scope file, applies the exclusion file, and folds in
// the command line and configuration limits.
//
// The direction of every override is downward. A flag may lower the request
// rate, never raise it above what the client signed off on, because the
// engagement terms and the operator's own configuration both exist to protect
// the target from exactly the kind of adjustment a convenient flag invites.
func buildScope(scopeFile, excludeFile string, cfg config.Config) (*scope.Engine, []string, error) {
	if scopeFile == "" {
		return nil, nil, errors.New("no scope file given; nothing may be tested without one")
	}
	_, file, err := scope.LoadFile(scopeFile)
	if err != nil {
		return nil, nil, fmt.Errorf("reading the scope file: %w", err)
	}
	if len(file.Scope.Allowed) == 0 {
		return nil, nil, fmt.Errorf("the scope file %s authorises nothing; there is no permitted target", scopeFile)
	}

	allowed := append([]string(nil), file.Scope.Allowed...)
	excluded := append([]string(nil), file.Scope.Excluded...)

	if excludeFile != "" {
		_, extra, err := scope.LoadFile(excludeFile)
		if err != nil {
			return nil, nil, fmt.Errorf("reading the exclusion file: %w", err)
		}
		// An exclusion file may only narrow. Its "allowed" list is treated
		// entirely as exclusions, so pointing it at the wrong file removes
		// targets rather than adding any.
		excluded = append(excluded, extra.Scope.Allowed...)
		excluded = append(excluded, extra.Scope.Excluded...)
	}

	policy := file.Policy
	if cfg.PassiveOnly {
		policy.PassiveOnly = true
	}
	if cfg.Limits.RequestsPerSecond > 0 {
		policy.MaxRPS = minFloat(policy.MaxRPS, cfg.Limits.RequestsPerSecond)
		if policy.MaxRPS == 0 {
			policy.MaxRPS = cfg.Limits.RequestsPerSecond
		}
	}
	if cfg.Limits.Concurrency > 0 {
		if policy.MaxConcurrency == 0 || cfg.Limits.Concurrency < policy.MaxConcurrency {
			policy.MaxConcurrency = cfg.Limits.Concurrency
		}
	}
	if cfg.Limits.MaxRequestsPerRun > 0 {
		if policy.MaxRequestsPerRun == 0 || cfg.Limits.MaxRequestsPerRun < policy.MaxRequestsPerRun {
			policy.MaxRequestsPerRun = cfg.Limits.MaxRequestsPerRun
		}
	}
	if cfg.HTTP.Timeout.D() > 0 {
		if policy.RequestTimeout == 0 || cfg.HTTP.Timeout.D() < policy.RequestTimeout.D() {
			policy.RequestTimeout = scope.Duration(cfg.HTTP.Timeout.D())
		}
	}
	if cfg.HTTP.MaxResponseBytes > 0 {
		if policy.MaxResponseBytes == 0 || cfg.HTTP.MaxResponseBytes < policy.MaxResponseBytes {
			policy.MaxResponseBytes = cfg.HTTP.MaxResponseBytes
		}
	}
	// The scope file's own passive-only setting is preserved; nothing here can
	// clear it.
	policy.AllowCloudMetadata = false

	sources := append([]string(nil), file.Sources.Enabled...)
	sources = append(sources, file.Sources.Disabled...)

	sc, err := scope.New(allowed, excluded, policy)
	if err != nil {
		return nil, nil, fmt.Errorf("the scope is not usable: %w", err)
	}
	// A source listed as disabled must not come back through a default.
	disabled := map[string]bool{}
	for _, s := range file.Sources.Disabled {
		disabled[strings.ToLower(strings.TrimSpace(s))] = true
	}
	kept := sources[:0]
	for _, s := range sources {
		if !disabled[strings.ToLower(strings.TrimSpace(s))] {
			kept = append(kept, s)
		}
	}
	return sc, kept, nil
}

func minFloat(a, b float64) float64 {
	if a == 0 {
		return b
	}
	if b == 0 {
		return a
	}
	if a < b {
		return a
	}
	return b
}

// buildDependencies constructs only the modules this run is allowed to use.
//
// In a passive-only run the HTTP client, the resolver and the crawler are
// never constructed at all. Building them is not dangerous, but a run that
// says it touched nothing should be built from nothing that could.
func buildDependencies(cmd *cobra.Command, cfg config.Config, sc *scope.Engine, scopeSources []string, f *scanFlags) (pipeline.Dependencies, *ratelimit.Limiter, error) {
	var out pipeline.Dependencies

	limit := ratelimit.New(cfg.Limits.RequestsPerSecond, cfg.Limits.Concurrency, cfg.Limits.MaxRequestsPerRun)

	if sources := selectSources(cmd, f.providers, scopeSources); len(sources) > 0 {
		collector, err := recon.NewCollector(sc, sources, recon.Options{
			MaxNames:      orDefault(cfg.Limits.MaxSubdomains, 500),
			Concurrency:   cfg.Limits.Concurrency,
			SourceTimeout: cfg.Passive.Timeout.D(),
		})
		if err != nil {
			// No usable passive source is not fatal; the rest of the run works.
			failc(cmd, "passive recon unavailable: %v", err)
		} else {
			out.Recon = collector
		}
	}

	if cfg.PassiveOnly {
		return out, limit, nil
	}

	httpCfg := httpclient.DefaultConfig()
	httpCfg.Timeout = cfg.HTTP.Timeout.D()
	httpCfg.Retries = cfg.HTTP.Retries
	httpCfg.UserAgent = cfg.HTTP.UserAgent
	httpCfg.MaxResponseBytes = cfg.HTTP.MaxResponseBytes
	httpCfg.FollowRedirects = cfg.HTTP.FollowRedirects
	httpCfg.MaxRedirects = cfg.HTTP.MaxRedirects
	httpCfg.InsecureSkipVerify = cfg.HTTP.InsecureSkipVerify
	httpCfg.Proxy = cfg.HTTP.Proxy
	httpCfg.MaxIdleConnsPerHost = cfg.HTTP.MaxIdleConnsPerHost

	client, err := httpclient.New(httpCfg, sc, limit, nil)
	if err != nil {
		return out, limit, fmt.Errorf("building the HTTP client: %w", err)
	}
	out.HTTP = client

	resolver := net.DefaultResolver
	collector, err := dns.NewCollector(sc, resolver, dns.ResolverConfig{
		Timeout:  cfg.Limits.DNSTimeout.D(),
		CacheTTL: cfg.Passive.CacheTTL.D(),
	})
	if err != nil {
		failc(cmd, "dns stage unavailable: %v", err)
	} else {
		out.DNS = collector
	}

	set, err := fingerprint.Load()
	if err != nil {
		failc(cmd, "fingerprinting unavailable: %v", err)
	} else {
		out.Fingerprint = set
	}
	return out, limit, nil
}

func orDefault(v, fallback int) int {
	if v > 0 {
		return v
	}
	return fallback
}

// selectSources maps names to source implementations. Certificate transparency
// needs no credential, so it is the only default.
func selectSources(cmd *cobra.Command, requested, fromScope []string) []recon.Source {
	enabled := map[string]bool{}
	if len(requested) > 0 {
		for _, p := range requested {
			enabled[strings.ToLower(strings.TrimSpace(p))] = true
		}
	} else {
		for _, p := range fromScope {
			if k := strings.ToLower(strings.TrimSpace(p)); k != "" {
				enabled[k] = true
			}
		}
		if len(enabled) == 0 {
			enabled["certtransparency"] = true
		}
	}

	var out []recon.Source
	if enabled["certtransparency"] || enabled["crt.sh"] || enabled["crtsh"] {
		out = append(out, recon.NewCrtShSource())
	}
	var unknown []string
	for k := range enabled {
		switch k {
		case "certtransparency", "crt.sh", "crtsh":
		default:
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		failc(cmd, "unknown passive source(s) ignored: %s", strings.Join(unknown, ", "))
	}
	return out
}

func writeReports(cmd *cobra.Command, res *pipeline.Result, cfg config.Config, f *scanFlags, g *globalFlags) error {
	if len(f.formats) == 0 {
		return nil
	}
	dir := cfg.Output.Dir
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("creating the output directory: %w", err)
	}

	primary := strings.ToLower(strings.TrimSpace(f.formats[0]))
	for _, format := range f.formats {
		key := strings.ToLower(strings.TrimSpace(format))
		body, ok := res.Reports[key]
		if !ok {
			failc(cmd, "report %s was not produced", key)
			continue
		}
		name := defaultReportName(res.RunID, key)
		if key == primary && f.outputFile != "" {
			name = f.outputFile
		}
		path := name
		if !filepath.IsAbs(path) {
			path = filepath.Join(dir, name)
		}
		// 0640 rather than 0644: a report names assets and their weaknesses,
		// which is not something to leave world-readable by default.
		if err := os.WriteFile(path, body, 0o640); err != nil {
			return fmt.Errorf("writing %s: %w", path, err)
		}
		if !g.quiet {
			failc(cmd, "wrote %s", path)
		}
	}
	return nil
}

func defaultReportName(runID, format string) string {
	ext := format
	if r, err := report.New(format); err == nil {
		ext = strings.TrimPrefix(r.Extension(), ".")
	}
	return fmt.Sprintf("report-%s.%s", runID, ext)
}

func printDryRun(cmd *cobra.Command, target string, sc *scope.Engine, cfg config.Config, f *scanFlags) {
	out := cmd.OutOrStdout()
	allowed, excluded := sc.Rules()

	fmt.Fprintf(out, "dry run: the configuration and scope are usable\n")
	fmt.Fprintf(out, "  target:      %s\n", target)
	fmt.Fprintf(out, "  in scope:    %s\n", ruleList(allowed))
	fmt.Fprintf(out, "  excluded:    %s\n", ruleList(excluded))
	fmt.Fprintf(out, "  passive:     %t\n", cfg.PassiveOnly)
	fmt.Fprintf(out, "  rate:        %.2f req/s\n", cfg.Limits.RequestsPerSecond)
	fmt.Fprintf(out, "  concurrency: %d\n", cfg.Limits.Concurrency)
	fmt.Fprintf(out, "  reports:     %s\n", strings.Join(f.formats, ", "))
	if !cfg.PassiveOnly {
		fmt.Fprintf(out, "\nThis run would contact the targets above. Nothing was sent.\n")
	} else {
		fmt.Fprintf(out, "\nThis run would contact nothing.\n")
	}
}

func ruleList(rules []scope.Rule) string {
	if len(rules) == 0 {
		return "(none)"
	}
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.String())
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

func describeConfig(cfg config.Config) string {
	return fmt.Sprintf("passive_only=%t rate=%.2f concurrency=%d insecure=%t",
		cfg.PassiveOnly, cfg.Limits.RequestsPerSecond, cfg.Limits.Concurrency, cfg.HTTP.InsecureSkipVerify)
}
