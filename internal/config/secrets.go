package config

import (
	"fmt"
	"regexp"
	"strings"
)

// envVarName is the only shape a secrets mapping value may take. At least one
// underscore is required: an environment variable reference follows a
// PREFIX_NAME convention, while a literal credential is very often a single
// unbroken run of characters (AKIAIOSFODNN7EXAMPLE, ghp_..., or a base64
// blob). Without that rule an all-caps key is indistinguishable from a
// variable name and the leak check below never fires.
var envVarName = regexp.MustCompile(`^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$`)

// credentialShape detects a value that looks like an actual credential rather
// than an environment variable name. It is a heuristic safety net: a leaked
// key in a tracked config file is a serious incident, so the loader refuses to
// continue rather than help the operator keep using it.
var credentialShape = regexp.MustCompile(`(?i)(?:^[A-Za-z0-9_\-]{16,}$)|(?:(?:key|token|secret|bearer)\s*[:=])`)

// checkSecretShape validates the secrets mapping.
func (c Config) checkSecretShape() error {
	for provider, ref := range c.Secrets {
		if ref == "" {
			return fmt.Errorf("secrets.%s: value is empty; name the environment variable that holds the credential", provider)
		}
		if !envVarName.MatchString(ref) {
			if credentialShape.MatchString(ref) {
				return fmt.Errorf("secrets.%s looks like a literal credential; store only the NAME of an environment variable (for example %s) and set the value in the environment", provider, envNameFor(provider))
			}
			return fmt.Errorf("secrets.%s must be an UPPER_SNAKE_CASE environment variable name, got %q", provider, ref)
		}
	}
	return nil
}

// envNameFor suggests a conventional environment variable name.
func envNameFor(provider string) string {
	s := strings.ToUpper(strings.NewReplacer("-", "_", ".", "_", " ", "_").Replace(provider))
	return "BUGBOUNTY_" + s + "_API_KEY"
}

// MinSecretLength is the shortest resolved value treated as a usable
// credential. Shorter values are reported as "no credential configured".
const MinSecretLength = 12

// SuggestEnvName exposes the naming convention for documentation and tests.
func SuggestEnvName(provider string) string { return envNameFor(provider) }
