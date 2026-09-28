package main

import (
	"fmt"
	"strings"

	"github.com/bbtoolkit/bugbounty/internal/config"
	"github.com/bbtoolkit/bugbounty/internal/report"
	"github.com/spf13/cobra"
)

// Version records the build version, set at link time.
var Version = version

// globalFlags are the flags every subcommand shares.
type globalFlags struct {
	configPath string
	profile    string
	outputDir  string
	format     string
	quiet      bool
}

// register wires the shared flags onto a command.
func (g *globalFlags) register(cmd *cobra.Command) {
	f := cmd.PersistentFlags()
	f.StringVar(&g.configPath, "config", "", "path to the configuration file (default: the user config path)")
	f.StringVar(&g.profile, "profile", "", "name of a pipeline profile to apply")
	f.StringVar(&g.outputDir, "output", "", "directory to write output into")
	f.StringVar(&g.format, "format", report.FormatJSON, "report format: "+strings.Join(report.Formats(), ", "))
	f.BoolVarP(&g.quiet, "quiet", "q", false, "suppress progress output; errors are still reported")
}

func newRootCommand() *cobra.Command {
	g := &globalFlags{}

	cmd := &cobra.Command{
		Use:   "bugbounty",
		Short: "Authorised security assessment toolkit",
		Long: strings.TrimSpace(`
bugbounty runs a recon and assessment pipeline against assets that have been
explicitly placed in scope.

It is a reporting tool, not an exploitation tool. Everything it produces is a
lead derived from observation, and anything that would need a human to confirm
is marked as requiring manual verification rather than presented as a result.

An empty report is not a clean bill of health. A run that could not complete
says so in its warnings, and those warnings appear in every format.`),
		Version:       Version,
		SilenceUsage:  true,
		SilenceErrors: false,
		// The default is deliberately inert. Running a scanner because someone
		// typed the binary name and pressed enter is how a tool ends up
		// pointed at something nobody authorised.
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
	g.register(cmd)

	cmd.AddCommand(
		newScanCommand(g),
		newScopeCommand(g),
		newReportCommand(g),
		newRulesCommand(g),
		newConfigCommand(g),
		newVersionCommand(),
	)
	return cmd
}

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the build version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "bugbounty %s\n", Version)
			return nil
		},
	}
}

// loadConfig resolves the configuration, applying any profile.
func (g *globalFlags) loadConfig() (config.Config, error) {
	cfg, err := config.Load(g.configPath)
	if err != nil {
		var notFound *config.ErrNotFound
		if ok := asNotFound(err, &notFound); ok {
			// A missing config is normal for a first run. Defaults are safe,
			// so the run continues; saying so is more useful than refusing.
			if !g.quiet {
				failf("no configuration file at %s; using built-in defaults", notFound.Path)
			}
			return cfg, nil
		}
		return config.Config{}, err
	}
	if g.profile != "" {
		prof, err := config.LoadProfile(g.profile)
		if err != nil {
			return config.Config{}, err
		}
		cfg = config.Apply(cfg, prof)
	}
	if g.outputDir != "" {
		cfg.Output.Dir = g.outputDir
	}
	return cfg, nil
}

func asNotFound(err error, target **config.ErrNotFound) bool {
	if e, ok := err.(*config.ErrNotFound); ok {
		*target = e
		return true
	}
	return false
}
