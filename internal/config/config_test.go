package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/bbtoolkit/bugbounty/internal/scope"
)

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDefaultsAreUsable(t *testing.T) {
	c := Default()
	if err := c.Validate(); err != nil {
		t.Fatalf("the default configuration is not valid: %v", err)
	}
	if c.Limits.Concurrency <= 0 {
		t.Error("concurrency must be positive")
	}
	if c.HTTP.Timeout.D() <= 0 {
		t.Error("the HTTP timeout must be positive")
	}
	if c.Database.Path == "" {
		t.Error("the database path must be set")
	}
}

func TestDefaultIsPassiveSafe(t *testing.T) {
	// A default that actively scans would be a surprising thing to run.
	c := Default()
	if c.PassiveOnly {
		t.Log("the default is passive-only; active scans require an explicit opt-in")
	}
	if c.HTTP.InsecureSkipVerify {
		t.Error("SECURITY: TLS verification is disabled by default")
	}
}

func TestLoadMinimalConfig(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "config.yaml", "version: 1\n")
	c, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Path != p {
		t.Errorf("the config path was not recorded: %q", c.Path)
	}
	if err := c.Validate(); err != nil {
		t.Errorf("a minimal config did not validate: %v", err)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	// Strict decoding is what stops a typo in a security-relevant key from
	// silently leaving a default in place.
	dir := t.TempDir()
	p := write(t, dir, "c.yaml", "version: 1\npassiv_only: true\n")
	if _, err := Load(p); err == nil {
		t.Error("SECURITY: a misspelled safety key was silently ignored")
	}
	p2 := write(t, dir, "c2.yaml", "version: 1\nlimits:\n  concurrancy: 4\n")
	if _, err := Load(p2); err == nil {
		t.Error("SECURITY: a misspelled limit was silently ignored")
	}
}

func TestLoadMalformed(t *testing.T) {
	cases := map[string]string{
		"not yaml":        "\t\tthis: is: not: yaml:\n\t\t\t- [",
		"wrong type":      "version: 1\nlimits:\n  concurrency: not-a-number\n",
		"tabs for indent": "version: 1\nlimits:\n\tconcurrency: 4\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			p := write(t, t.TempDir(), "c.yaml", body)
			if _, err := Load(p); err == nil {
				t.Error("a malformed configuration was accepted")
			}
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err == nil {
		t.Fatal("a missing file was accepted")
	}
	var nf *ErrNotFound
	if !asErr(err, &nf) {
		t.Errorf("expected a not-found error, got %T: %v", err, err)
	}
}
func asErr[T error](err error, target *T) bool {
	if t, ok := err.(T); ok {
		*target = t
		return true
	}
	return false
}

func TestLoadRefusesDirectory(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(dir); err == nil {
		t.Error("SECURITY: a directory was opened as a configuration file")
	}
}

// --- secrets ----------------------------------------------------------------

func TestSecretLiteralIsRejected(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "c.yaml", "version: 1\nsecrets:\n  shodan: AKIAIOSFODNN7EXAMPLE\n")
	_, err := Load(p)
	if err == nil {
		t.Fatal("SECURITY: a literal API key in the config file was accepted")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "secret") {
		t.Errorf("the error should name the problem: %v", err)
	}
}

func TestSecretEnvVarNameIsAccepted(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "c.yaml", "version: 1\nsecrets:\n  shodan: SHODAN_API_KEY\n")
	c, err := Load(p)
	if err != nil {
		t.Fatalf("an env-var reference was rejected: %v", err)
	}
	if len(c.Secrets) == 0 {
		t.Error("the provider was not registered as having a secret")
	}
}

func TestSecretResolution(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "c.yaml", "version: 1\nsecrets:\n  shodan: BB_TEST_SHODAN_KEY\n")
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("BB_TEST_SHODAN_KEY", "s3cret-value")
	if got, ok := c.Secret("shodan"); !ok || got != "s3cret-value" {
		t.Errorf("Secret() = %q, %v", got, ok)
	}
	if got, ok := c.Secret("nonexistent"); ok || got != "" {
		t.Errorf("an unknown provider returned %q", got)
	}
}

func TestSecretUnsetIsNotAnErrorAtLoad(t *testing.T) {
	// Loading a config on a machine where the credential is not present yet
	// should succeed; the module that needs it reports the problem.
	dir := t.TempDir()
	p := write(t, dir, "c.yaml", "version: 1\nsecrets:\n  shodan: BB_TEST_ABSENT_KEY\n")
	if _, err := Load(p); err != nil {
		t.Errorf("a config referencing an unset env var was rejected: %v", err)
	}
}

func TestSecretShapeIsChecked(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "c.yaml", "version: 1\nsecrets:\n  shodan: BB_TEST_SHORT\n")
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("BB_TEST_SHORT", "abc")
	if _, ok := c.Secret("shodan"); ok {
		t.Error("SECURITY: a three-character credential was accepted as an API key")
	}
}

func TestSecretLookupIsCaseInsensitiveOnProvider(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "c.yaml", "version: 1\nsecrets:\n  Shodan: BB_TEST_SHODAN_KEY\n")
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("BB_TEST_SHODAN_KEY", "a-realistic-length-credential")
	got, ok := c.Secret("shodan")
	if !ok {
		t.Fatal("SECURITY: provider lookup failed for a differently-cased name")
	}
	if got != "a-realistic-length-credential" {
		t.Errorf("Secret = %q", got)
	}
}

// --- validation -------------------------------------------------------------

func TestValidateRejectsBadValues(t *testing.T) {
	cases := map[string]func(*Config){
		"negative concurrency":    func(c *Config) { c.Limits.Concurrency = -1 },
		"zero concurrency":        func(c *Config) { c.Limits.Concurrency = 0 },
		"negative rate":           func(c *Config) { c.Limits.RequestsPerSecond = -5 },
		"negative timeout":        func(c *Config) { c.HTTP.Timeout = scope.Duration(-1) },
		"negative response limit": func(c *Config) { c.HTTP.MaxResponseBytes = -1 },
		"too many redirects":      func(c *Config) { c.HTTP.MaxRedirects = 1000 },
		"negative retries":        func(c *Config) { c.HTTP.Retries = -1 },
		"huge concurrency":        func(c *Config) { c.Limits.Concurrency = 100000 },
		"unknown log format":      func(c *Config) { c.Log.Format = "yaml" },
		"negative crawl depth":    func(c *Config) { c.Limits.MaxCrawlDepth = -2 },
		"empty database path":     func(c *Config) { c.Database.Path = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := Default()
			mutate(&c)
			if err := c.Validate(); err == nil {
				t.Error("an invalid configuration was accepted")
			}
		})
	}
}

func TestValidateAcceptsReasonableValues(t *testing.T) {
	for _, mutate := range []func(*Config){
		func(c *Config) { c.PassiveOnly = true },
		func(c *Config) { c.Limits.RequestsPerSecond = 0.5 },
		func(c *Config) { c.Limits.Concurrency = 1 },
		func(c *Config) { c.HTTP.MaxResponseBytes = 1 << 20 },
		func(c *Config) { c.HTTP.MaxRedirects = 5 },
		func(c *Config) { c.Limits.MaxCrawlDepth = 4 },
	} {
		c := Default()
		mutate(&c)
		if err := c.Validate(); err != nil {
			t.Errorf("a reasonable configuration was rejected: %v", err)
		}
	}
}

func TestInsecureSkipVerifyCannotComeFromAFile(t *testing.T) {
	// Turning off certificate validation is allowed from the command line,
	// where the operator watches it happen, and refused from a file, where it
	// could be committed and forgotten. A config file that says
	// "skip TLS verification" is how an assessment ends up trusting whatever
	// answers on the wire without anyone knowing.
	c := Default()
	c.HTTP.InsecureSkipVerify = true
	err := c.Validate()
	if err == nil {
		t.Fatal("SECURITY: insecure_skip_verify was accepted as a configuration value")
	}
	if !strings.Contains(err.Error(), "insecure") {
		t.Errorf("the error should name the offending setting: %v", err)
	}

	// And the same setting written into a file must be rejected at load time,
	// not only when Validate happens to be called by a caller.
	dir := t.TempDir()
	p := write(t, dir, "c.yaml", "version: 1\nhttp:\n  insecure_skip_verify: true\n")
	if _, err := Load(p); err == nil {
		t.Fatal("SECURITY: a config file enabling insecure_skip_verify was accepted")
	}
}

// --- environment overrides --------------------------------------------------

func TestEnvOverrides(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "c.yaml", "version: 1\nlimits:\n  concurrency: 4\n")
	// Load once to prove the file alone gives the file's own value.
	base, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if base.Limits.Concurrency != 4 {
		t.Fatalf("the file value was not used: %d", base.Limits.Concurrency)
	}
	t.Setenv(EnvConcurrency, "9")
	t.Setenv(EnvPassiveOnly, "true")
	t.Setenv(EnvRateLimit, "2.5")
	overridden, err := Load(p)
	if err != nil {
		t.Fatalf("Load with env: %v", err)
	}
	if overridden.Limits.Concurrency != 9 {
		t.Errorf("BB_CONCURRENCY did not take effect: %d", overridden.Limits.Concurrency)
	}
	if !overridden.PassiveOnly {
		t.Error("BB_PASSIVE_ONLY did not take effect")
	}
	if overridden.Limits.RequestsPerSecond != 2.5 {
		t.Errorf("BB_RATE did not take effect: %v", overridden.Limits.RequestsPerSecond)
	}
}

func TestEnvOverrideOfLimitIsValidated(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "c.yaml", "version: 1\n")
	t.Setenv(EnvConcurrency, "-1")
	if _, err := Load(p); err == nil {
		t.Error("SECURITY: an invalid environment override was accepted")
	}
}

func TestEnvMalformedValueIsRejected(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "c.yaml", "version: 1\n")
	t.Setenv(EnvConcurrency, "lots")
	if _, err := Load(p); err == nil {
		t.Error("SECURITY: a non-numeric override was silently ignored")
	}
}

// --- profiles ---------------------------------------------------------------

func TestBuiltinProfiles(t *testing.T) {
	names := ProfileNames()
	if len(names) == 0 {
		t.Fatal("there are no built-in profiles")
	}
	seen := map[string]bool{}
	for _, n := range names {
		if seen[n] {
			t.Errorf("duplicate profile %q", n)
		}
		seen[n] = true
		p, err := LoadProfile(n)
		if err != nil {
			t.Errorf("profile %q did not load: %v", n, err)
			continue
		}
		if err := p.validate(); err != nil {
			t.Errorf("profile %q is invalid: %v", n, err)
		}
		if p.Name != n {
			t.Errorf("profile %q reports name %q", n, p.Name)
		}
	}
}

func TestPassiveProfileIsPassive(t *testing.T) {
	p, err := LoadProfile("passive")
	if err != nil {
		t.Skipf("no passive profile: %v", err)
	}
	if !p.Limits.PassiveOnly {
		t.Error("SECURITY: the passive profile does not force passive-only mode")
	}
	if p.Modules.Crawler {
		t.Error("SECURITY: the passive profile enables the crawler")
	}
}

func TestApplyProfile(t *testing.T) {
	p, err := LoadProfile("default")
	if err != nil {
		t.Fatal(err)
	}
	p.Limits.Concurrency = 3
	p.Limits.PassiveOnly = true
	p.Modules.Crawler = false
	c := Apply(Default(), p)
	if c.Limits.Concurrency != 3 {
		t.Errorf("concurrency = %d", c.Limits.Concurrency)
	}
	if !c.PassiveOnly {
		t.Error("passive-only was not applied")
	}
}

func TestApplyProfileKeepsScopeUnrelatedFields(t *testing.T) {
	p := Profile{Name: "empty"}
	c := Default()
	c.Database.Path = "/tmp/engagement.db"
	got := Apply(c, p)
	if got.Database.Path != "/tmp/engagement.db" {
		t.Errorf("applying a profile overwrote the database path: %q", got.Database.Path)
	}
}

func TestLoadProfileRejectsBadNames(t *testing.T) {
	for _, name := range []string{"", "../../etc/passwd", "a/b", "a\\b", "a b", "-flag"} {
		if _, err := LoadProfile(name); err == nil {
			t.Errorf("SECURITY: a profile name that is not a simple identifier was accepted: %q", name)
		}
	}
}

func TestLoadProfileFileRejectsMalformed(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "p.yaml", "name: x\nlimits:\n  concurrency: -5\n")
	if _, err := LoadProfileFile(p); err == nil {
		t.Error("an invalid profile file was accepted")
	}
	p2 := write(t, dir, "p2.yaml", "name: [unclosed\n")
	if _, err := LoadProfileFile(p2); err == nil {
		t.Error("a malformed profile file was accepted")
	}
}

func TestLoadProfileFileAppliesCorrectly(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "p.yaml", `
name: gentle
limits:
  concurrency: 1
  requests_per_second: 1
  passive_only: true
  max_depth: 1
modules:
  subdomains: true
  dns: false
  http: false
  crawler: false
`)
	prof, err := LoadProfileFile(p)
	if err != nil {
		t.Fatalf("LoadProfileFile: %v", err)
	}
	c := Apply(Default(), prof)
	if c.Limits.Concurrency != 1 || c.Limits.RequestsPerSecond != 1 {
		t.Errorf("limits = %+v", c.Limits)
	}
	if !c.PassiveOnly {
		t.Error("passive_only was not applied")
	}
	if c.Limits.MaxCrawlDepth != 1 {
		t.Errorf("max_crawl_depth = %d", c.Limits.MaxCrawlDepth)
	}
}

func TestPassiveOnlyProfileRefusesActiveModules(t *testing.T) {
	// "Passive only" is the promise the operator makes to a target, usually a
	// one they do not own. A profile that quietly re-enables the DNS resolver
	// breaks that promise, so the combination is refused rather than resolved
	// by precedence rules.
	dir := t.TempDir()
	p := write(t, dir, "p.yaml", `
name: gentle
passive_only: true
modules:
  dns: true
`)
	if _, err := LoadProfileFile(p); err == nil {
		t.Fatal("SECURITY: a passive_only profile enabling the active DNS module was accepted")
	}
}

func TestSaveWritesAnOwnerOnlyFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no POSIX mode bits; permissions are enforced by ACLs instead")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yaml")

	cfg := Default()
	if err := cfg.Save(p); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("SECURITY: the config file mode is %04o; it should be owner-only", perm)
	}

	// The round trip has to preserve what was written, including the secret
	// references, or Save is useless as an initial-config command.
	back, err := Load(p)
	if err != nil {
		t.Fatalf("Load after Save: %v", err)
	}
	if back.Limits.Concurrency != cfg.Limits.Concurrency {
		t.Errorf("concurrency did not survive the round trip: %d != %d", back.Limits.Concurrency, cfg.Limits.Concurrency)
	}
}

func TestSaveRefusesToClobberAnUnreadableDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "taken"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// Saving over a directory must fail cleanly rather than panic or truncate.
	if err := Default().Save(dir); err == nil {
		t.Fatal("Save over a directory should have failed")
	}
}

func TestProvidersWithSecrets(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "c.yaml", "version: 1\nsecrets:\n  shodan: A_KEY\n  censys: B_KEY\n")
	t.Setenv("A_KEY", "a-credential-long-enough")
	t.Setenv("B_KEY", "another-credential-long-enough")
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	got := c.ProvidersWithSecrets()
	if len(got) != 2 {
		t.Errorf("ProvidersWithSecrets = %v", got)
	}
}
