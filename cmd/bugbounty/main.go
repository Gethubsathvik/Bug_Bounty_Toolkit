// Command bugbounty runs authorised security assessments against assets a
// client has explicitly placed in scope.
//
// The tool's operating posture is set by its defaults: it refuses to act
// outside a declared scope, it will not disable certificate validation from a
// configuration file, it never stores a credential, and it reports a run that
// could not finish as incomplete rather than clean. Flags exist to widen
// authorisation deliberately and visibly, not to bypass it quietly.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := newRootCommand().Execute(); err != nil {
		// Cobra has already printed the error. Exit non-zero so a script or a
		// CI job does not read a failed assessment as a successful one.
		os.Exit(1)
	}
}

// failf prints a message to stderr. Reports and errors go to stderr so that
// stdout carries only the artefact the operator asked for.
func failf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

// failc is failf routed through the command's error writer. Cobra's default is
// os.Stderr, so a real invocation behaves identically, but an embedding caller
// can capture or redirect the diagnostics.
func failc(cmd *cobra.Command, format string, args ...any) {
	fmt.Fprintf(cmd.ErrOrStderr(), format+"\n", args...)
}
