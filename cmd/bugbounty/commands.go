package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/bbtoolkit/bugbounty/internal/config"
	"github.com/bbtoolkit/bugbounty/internal/findings"
	"github.com/bbtoolkit/bugbounty/internal/pipeline"
	"github.com/bbtoolkit/bugbounty/internal/report"
	"github.com/bbtoolkit/bugbounty/internal/scope"
	"github.com/bbtoolkit/bugbounty/internal/storage"
	"github.com/bbtoolkit/bugbounty/pkg/models"
	"github.com/spf13/cobra"
)

// newScopeCommand inspects and checks scope files without scanning anything.
func newScopeCommand(g *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scope",
		Short: "Inspect and validate scope files",
	}
	cmd.AddCommand(
		newScopeCheckCommand(g),
		newScopeExplainCommand(),
	)
	return cmd
}

func newScopeCheckCommand(g *globalFlags) *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "check <scope-file>",
		Short: "Validate a scope file and report what it authorises",
		Long: strings.TrimSpace(`
Validate a scope file without contacting anything.

This is the command to run before every engagement. A scope file that does not
parse, authorises nothing, or contains a rule broader than intended is a
mistake worth finding before a packet is sent, not after.`),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			eng, file, err := scope.LoadFile(args[0])
			if err != nil {
				return fmt.Errorf("reading the scope file: %w", err)
			}
			for _, w := range eng.Warnings() {
				failc(cmd, "warning: %s", w)
			}
			allowed, excluded := eng.Rules()
			// The effective policy, not the file's: the loader clamps values to
			// hard ceilings, so a file asking for more than is safe reports the
			// number that will actually be used.
			pol := eng.Policy()

			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintf(w, "scope file:\t%s\n", args[0])
			if file.Metadata.Program != "" {
				fmt.Fprintf(w, "programme:\t%s\n", file.Metadata.Program)
			}
			if file.Metadata.Reference != "" {
				fmt.Fprintf(w, "reference:\t%s\n", file.Metadata.Reference)
			}
			if file.Metadata.AuthorizedUntil != "" {
				fmt.Fprintf(w, "authorised until:\t%s\n", file.Metadata.AuthorizedUntil)
			}
			fmt.Fprintf(w, "passive only:\t%t\n", pol.PassiveOnly)
			fmt.Fprintf(w, "requests/second:\t%.1f\n", pol.MaxRPS)
			fmt.Fprintf(w, "concurrency:\t%d\n", pol.MaxConcurrency)
			fmt.Fprintf(w, "requests per run:\t%d\n", pol.MaxRequestsPerRun)
			fmt.Fprintf(w, "respects robots:\t%t\n", pol.RobotsEnabled())
			fmt.Fprintf(w, "cloud metadata:\t%t\n", pol.AllowCloudMetadata)
			fmt.Fprintf(w, "allowed:\t%d\n", len(allowed))
			fmt.Fprintf(w, "excluded:\t%d\n", len(excluded))
			if len(file.Sources.Enabled) > 0 {
				fmt.Fprintf(w, "sources:\t%s\n", strings.Join(file.Sources.Enabled, ", "))
			}
			if err := w.Flush(); err != nil {
				return err
			}

			if len(allowed) == 0 {
				return fmt.Errorf("SECURITY: %s authorises nothing; there is no permitted target", args[0])
			}
			fmt.Fprintln(cmd.OutOrStdout())
			fmt.Fprintln(cmd.OutOrStdout(), "Authorised targets:")
			for _, r := range sortedRules(allowed) {
				fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", r)
			}
			if len(excluded) > 0 {
				fmt.Fprintln(cmd.OutOrStdout())
				fmt.Fprintln(cmd.OutOrStdout(), "Excluded:")
				for _, r := range sortedRules(excluded) {
					fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", r)
				}
			}
			if out != "" {
				return writeBlock(cmd, out, renderScopeSummary(allowed, excluded, file.Policy))
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&out, "output", "O", "", "also write the summary to this file")
	return cmd
}

func renderScopeSummary(allowed, excluded []scope.Rule, policy scope.Policy) string {
	var b strings.Builder
	b.WriteString("# Authorised scope\n\n")
	fmt.Fprintf(&b, "- passive only: %t\n", policy.PassiveOnly)
	b.WriteString("\n## In scope\n\n")
	for _, r := range sortedRules(allowed) {
		fmt.Fprintf(&b, "- `%s`\n", r)
	}
	if len(excluded) > 0 {
		b.WriteString("\n## Excluded\n\n")
		for _, r := range sortedRules(excluded) {
			fmt.Fprintf(&b, "- `%s`\n", r)
		}
	}
	return b.String()
}

func sortedRules(rules []scope.Rule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.String())
	}
	sort.Strings(out)
	return out
}

func newScopeExplainCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "explain <target>",
		Short: "Explain how the scope engine decides about a target",
		Long: strings.TrimSpace(`
Explain whether a target would be permitted, and which rule decided.

This is for answering "why did it skip that host" without reading the scope
file. It consults the engine directly and contacts nothing.`),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := cmd.Flags().GetString("scope")
			if err != nil || path == "" {
				return fmt.Errorf("pass --scope with the scope file to consult")
			}
			sc, _, err := scope.LoadFile(path)
			if err != nil {
				return err
			}
			host := pipeline.SeedHost(args[0])
			if host == "" {
				return fmt.Errorf("%q is not a host or URL", args[0])
			}

			d := sc.CheckHost(host)
			fmt.Fprintf(cmd.OutOrStdout(), "host:\t%s\n", host)
			fmt.Fprintf(cmd.OutOrStdout(), "allowed:\t%t\n", d.Allowed)
			if d.Rule != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "matched:\t%s\n", d.Rule)
			}
			if d.Reason != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "reason:\t%s\n", d.Reason)
			}
			if !d.Allowed {
				return fmt.Errorf("%s is not in scope", host)
			}
			return nil
		},
	}
	cmd.Flags().String("scope", "", "scope file to consult (required)")
	if err := cmd.MarkFlagRequired("scope"); err != nil {
		panic(err)
	}
	return cmd
}

func writeBlock(cmd *cobra.Command, path, body string) error {
	if err := os.WriteFile(path, []byte(body), 0o640); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	failc(cmd, "wrote %s", path)
	return nil
}

// --- report ------------------------------------------------------------------

func newReportCommand(g *globalFlags) *cobra.Command {
	var (
		format    string
		runID     string
		limit     int
		minSever  string
		onlyNeeds bool
	)
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Render stored findings as a report",
		Long: strings.TrimSpace(`
Render findings already in the database. This contacts nothing.

Findings are read back exactly as they were stored, so a report regenerated
later matches the one delivered, except for its generation timestamp.`),
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := g.loadConfig()
			if err != nil {
				return err
			}
			store, err := storage.Open(cmd.Context(), storage.Options{Path: cfg.Database.Path, ReadOnly: true})
			if err != nil {
				return fmt.Errorf("opening the database: %w", err)
			}
			defer store.Close()

			filter := storage.FindingFilter{Limit: limit}
			if minSever != "" {
				sev, ok := models.ParseSeverity(minSever)
				if !ok {
					return fmt.Errorf("%q is not a severity", minSever)
				}
				filter.Severities = []models.Severity{sev}
			}
			if onlyNeeds {
				filter.Statuses = []models.Status{models.StatusNeedsManual}
			}
			if runID != "" {
				if _, err := store.GetRun(cmd.Context(), runID); err != nil {
					return fmt.Errorf("run %s: %w", runID, err)
				}
				filter.RunID = runID
			}

			list, err := store.ListFindings(cmd.Context(), filter)
			if err != nil {
				return err
			}
			rep := report.Report{
				Findings: list,
				Metadata: report.Metadata{
					Seed:     cfg.Output.Dir,
					Warnings: []string{"rendered from stored findings; scope is not restated here"},
				},
			}
			rd, err := report.New(format)
			if err != nil {
				return err
			}
			body, err := rd.Render(rep)
			if err != nil {
				return err
			}
			fmt.Fprint(cmd.OutOrStdout(), string(body))
			return nil
		},
	}
	cmd.Flags().StringVar(&format, "format", report.FormatMarkdown, "report format: "+strings.Join(report.Formats(), ", "))
	cmd.Flags().StringVar(&runID, "run", "", "restrict to findings from this run")
	cmd.Flags().IntVar(&limit, "limit", 0, "maximum findings to include; 0 means all")
	cmd.Flags().StringVar(&minSever, "min-severity", "", "only include findings at or above this severity")
	cmd.Flags().BoolVar(&onlyNeeds, "needs-manual", false, "only include findings awaiting manual verification")
	return cmd
}

// --- rules -------------------------------------------------------------------

func newRulesCommand(g *globalFlags) *cobra.Command {
	var showAll bool
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "List the finding rules and what they report",
		Long: strings.TrimSpace(`
List the built-in rules.

Each rule declares a severity and a confidence. Severity is a judgement made
in the rule, never derived from how many signals fired, and a rule that needs a
human to confirm its result is marked as such here rather than in the output.`),
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			engine := findings.DefaultEngine()
			rules := engine.Rules()
			if !showAll {
				rules = filterBySeverity(rules, minSeverityFilter(cmd))
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintf(w, "ID\tSEVERITY\tCONFIDENCE\tMANUAL\tTITLE\n")
			for _, r := range rules {
				manual := "no"
				if r.ManualVerificationRequired {
					manual = "yes"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", r.ID, r.Severity, r.Confidence, manual, r.Title)
			}
			return w.Flush()
		},
	}
	cmd.Flags().BoolVar(&showAll, "all", false, "include every rule regardless of severity")
	return cmd
}

func minSeverityFilter(cmd *cobra.Command) string {
	v, _ := cmd.Flags().GetString("min-severity")
	return v
}

func filterBySeverity(rules []findings.Rule, min string) []findings.Rule {
	if min == "" {
		return rules
	}
	threshold, ok := models.ParseSeverity(min)
	if !ok {
		return rules
	}
	var out []findings.Rule
	for _, r := range rules {
		if r.Severity.SeverityRank() >= threshold.SeverityRank() {
			out = append(out, r)
		}
	}
	return out
}

// --- config ------------------------------------------------------------------

func newConfigCommand(g *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Inspect and initialise the configuration",
	}
	cmd.AddCommand(newConfigShowCommand(g), newConfigInitCommand(g))
	return cmd
}

func newConfigShowCommand(g *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Print the effective configuration",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := g.loadConfig()
			if err != nil {
				return err
			}
			if err := cfg.Validate(); err != nil {
				return fmt.Errorf("the configuration is not usable: %w", err)
			}

			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintf(w, "path:\t%s\n", cfg.Path)
			fmt.Fprintf(w, "passive only:\t%t\n", cfg.PassiveOnly)
			fmt.Fprintf(w, "database:\t%s\n", cfg.Database.Path)
			fmt.Fprintf(w, "output:\t%s\n", cfg.Output.Dir)
			fmt.Fprintf(w, "rate:\t%.2f req/s\n", cfg.Limits.RequestsPerSecond)
			fmt.Fprintf(w, "concurrency:\t%d\n", cfg.Limits.Concurrency)
			fmt.Fprintf(w, "max requests:\t%d\n", cfg.Limits.MaxRequestsPerRun)
			fmt.Fprintf(w, "http timeout:\t%s\n", cfg.HTTP.Timeout)
			fmt.Fprintf(w, "max redirects:\t%d\n", cfg.HTTP.MaxRedirects)
			fmt.Fprintf(w, "log:\t%s/%s\n", cfg.Log.Level, cfg.Log.Format)
			if err := w.Flush(); err != nil {
				return err
			}

			// The names of configured providers, never their values.
			if names := cfg.ProvidersWithSecrets(); len(names) > 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "\ncredentials resolved for:")
				for _, n := range names {
					fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", n)
				}
			}
			fmt.Fprintln(cmd.OutOrStdout(), "\ncredentials are read from the environment at use and are never written anywhere.")
			return nil
		},
	}
}

func newConfigInitCommand(g *globalFlags) *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "init [path]",
		Short: "Write a default configuration file",
		Long: strings.TrimSpace(`
Write a configuration file with conservative defaults.

The file is created owner-only and contains no credentials. A configuration
may only name the environment variable that holds a credential; the value
itself belongs in the environment and nowhere else.`),
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := g.configPath
			if len(args) == 1 {
				path = args[0]
			}
			if path == "" {
				path = config.DefaultConfigPath()
			}
			if _, err := os.Stat(path); err == nil && !force {
				return fmt.Errorf("%s already exists; pass --force to overwrite it", path)
			}
			cfg := config.Default()
			cfg.Path = path
			if err := cfg.Save(path); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", path)
			fmt.Fprintf(cmd.OutOrStdout(), "Set credentials in the environment, for example BUGBOUNTY_CERTTRANSPARENCY_API_KEY.\n")
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing file")
	return cmd
}
