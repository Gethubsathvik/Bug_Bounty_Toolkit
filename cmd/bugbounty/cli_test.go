package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// runCLI executes the command tree with args and returns stdout, stderr and
// the error Cobra reported.
func runCLI(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	cmd := newRootCommand()
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs(args)
	err = cmd.Execute()
	return out.String(), errOut.String(), err
}

// goodScope is a well-formed scope file. The reference is a real URL because
// the loader insists on one: an engagement you cannot cite is not an
// engagement anyone can verify.
const goodScope = `version: 1
metadata:
  program: Test programme
  reference: "https://example.com/programme/scope-2026-01"
  operator: tester
  authorized_until: "2026-12-31"
scope:
  allowed:
    - example.com
    - "*.example.com"
  excluded:
    - internal.example.com
policy:
  passive_only: false
  max_rps: 5
  max_concurrency: 2
  respect_robots: true
  max_requests_per_run: 200
`

func writeScope(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scope.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// --- the central guarantee ----------------------------------------------------

func TestScanRefusesATargetOutsideTheScope(t *testing.T) {
	// Nothing in the CLI may widen scope for a single run. A typo in a
	// hostname must not become authorisation to test a stranger's domain.
	path := writeScope(t, goodScope)
	_, _, err := runCLI(t, "scan", "other-target.net", "--scope", path, "--dry-run", "--no-db")
	if err == nil {
		t.Fatal("SECURITY: a target outside the scope was accepted")
	}
	if !strings.Contains(err.Error(), "not covered by the scope") {
		t.Errorf("error = %v, want it to say the target is out of scope", err)
	}
}

func TestScanRefusesAnExcludedTarget(t *testing.T) {
	path := writeScope(t, goodScope)
	_, _, err := runCLI(t, "scan", "internal.example.com", "--scope", path, "--dry-run", "--no-db")
	if err == nil {
		t.Fatal("SECURITY: an excluded target was accepted")
	}
}

func TestScanRefusesWithoutAScopeFile(t *testing.T) {
	// A scan with no scope file would have no permitted target at all.
	_, _, err := runCLI(t, "scan", "example.com", "--dry-run", "--no-db")
	if err == nil {
		t.Fatal("a scan with no scope file was attempted")
	}
}

func TestScanRefusesWhenTheScopeAuthorisesNothing(t *testing.T) {
	path := writeScope(t, "version: 1\nscope:\n  allowed: []\n")
	_, _, err := runCLI(t, "scan", "example.com", "--scope", path, "--dry-run", "--no-db")
	if err == nil {
		t.Fatal("SECURITY: a scan ran with an empty scope")
	}
	if !strings.Contains(err.Error(), "no allowed targets") {
		t.Errorf("error = %v", err)
	}
}

func TestDryRunContactsNothingAndDescribesTheScope(t *testing.T) {
	path := writeScope(t, goodScope)
	stdout, _, err := runCLI(t, "scan", "example.com", "--scope", path, "--dry-run", "--no-db")
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	for _, want := range []string{"example.com", "internal.example.com", "dry run", "Nothing was sent"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the dry-run output does not mention %q:\n%s", want, stdout)
		}
	}
}

func TestPassiveOnlyDryRunSaysItWouldContactNothing(t *testing.T) {
	path := writeScope(t, goodScope)
	stdout, _, err := runCLI(t, "scan", "example.com", "--scope", path, "--passive-only", "--dry-run", "--no-db")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "would contact nothing") {
		t.Errorf("a passive dry run did not say it contacts nothing:\n%s", stdout)
	}
	if strings.Contains(stdout, "Nothing was sent") {
		t.Error("the passive branch reused the active wording")
	}
}

func TestInsecureIsAcceptedOnlyOnTheCommandLine(t *testing.T) {
	// The configuration loader refuses it so it cannot be committed; the flag
	// is how an operator opts in for a self-signed target, visibly.
	path := writeScope(t, goodScope)
	cfgDir := t.TempDir()
	cfgPath := filepath.Join(cfgDir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("version: 1\nhttp:\n  insecure_skip_verify: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := runCLI(t, "scan", "example.com", "--scope", path, "--config", cfgPath, "--dry-run", "--no-db")
	if err == nil {
		t.Fatal("SECURITY: a configuration file enabling insecure_skip_verify was accepted")
	}

	// The flag on its own is fine.
	_, _, err = runCLI(t, "scan", "example.com", "--scope", path, "--insecure", "--dry-run", "--no-db")
	if err != nil {
		t.Errorf("the --insecure flag was rejected: %v", err)
	}
}

func TestAnExclusionFileCanOnlyNarrow(t *testing.T) {
	// Pointing the exclusion file at a permissive file must remove targets,
	// never add them.
	scopePath := writeScope(t, goodScope)
	excludePath := writeScope(t, "version: 1\nscope:\n  allowed:\n    - attacker.example\n    - www.example.com\n")
	stdout, _, err := runCLI(t, "scan", "example.com", "--scope", scopePath, "--exclude", excludePath, "--dry-run", "--no-db")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "attacker.example") {
		t.Errorf("the exclusion file was not applied:\n%s", stdout)
	}
	_, _, err = runCLI(t, "scan", "www.example.com", "--scope", scopePath, "--exclude", excludePath, "--dry-run", "--no-db")
	if err == nil {
		t.Fatal("SECURITY: a target listed in the exclusion file was still scannable")
	}
}

// --- scope inspection --------------------------------------------------------

func TestScopeCheckReportsTheEffectivePolicy(t *testing.T) {
	// The check must show the limits that will actually apply, including any
	// clamped by a hard ceiling, because that is the whole point of running it
	// before an engagement.
	path := writeScope(t, goodScope)
	stdout, _, err := runCLI(t, "scope", "check", path)
	if err != nil {
		t.Fatalf("scope check: %v", err)
	}
	for _, want := range []string{
		"example.com", "internal.example.com", "Test programme",
		"requests/second:", "concurrency:", "respects robots:",
		"authorised until:", "2026-12-31",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the output does not mention %q:\n%s", want, stdout)
		}
	}
	// The file asks for 5 rps, and 5 is under the ceiling, so it survives.
	if !strings.Contains(stdout, "5.0") {
		t.Errorf("the effective rate limit was not reported:\n%s", stdout)
	}
	// Cloud metadata is off and must say so, so nobody assumes it is available.
	if !strings.Contains(stdout, "cloud metadata:") || !strings.Contains(stdout, "false") {
		t.Errorf("the cloud metadata switch was not reported as off:\n%s", stdout)
	}
}

func TestScopeCheckClampsRatherThanTrustingTheFile(t *testing.T) {
	// A file asking for an absurd rate is reported at the value that will
	// actually be used, not the value it asked for.
	path := writeScope(t, `version: 1
scope:
  allowed:
    - example.com
policy:
  max_rps: 100000
  max_concurrency: 5000
`)
	stdout, _, err := runCLI(t, "scope", "check", path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "100.0") {
		t.Errorf("the rate limit was not clamped to the ceiling:\n%s", stdout)
	}
	if strings.Contains(stdout, "100000") {
		t.Errorf("SECURITY: the file's unlimited rate survived the clamp:\n%s", stdout)
	}
	if !strings.Contains(stdout, "200") {
		t.Errorf("concurrency was not clamped to the ceiling:\n%s", stdout)
	}
}

func TestScopeCheckWarnsWhenAFileAsksForMetadataAccess(t *testing.T) {
	path := writeScope(t, `version: 1
scope:
  allowed:
    - example.com
policy:
  allow_cloud_metadata: true
`)
	stdout, stderr, err := runCLI(t, "scope", "check", path)
	if err != nil {
		t.Fatal(err)
	}
	// The warning belongs on stderr so it cannot pollute a piped summary.
	if !strings.Contains(stderr, "allow_cloud_metadata was ignored") {
		t.Errorf("the ignored metadata request was not surfaced:\n%s\n%s", stdout, stderr)
	}
	if !strings.Contains(stdout, "cloud metadata:") || !strings.Contains(stdout, "false") {
		t.Errorf("metadata was not reported as off:\n%s", stdout)
	}
}

func TestScopeCheckFailsOnAnEmptyScope(t *testing.T) {
	path := writeScope(t, "version: 1\nscope:\n  allowed: []\n")
	_, _, err := runCLI(t, "scope", "check", path)
	if err == nil {
		t.Error("a scope file authorising nothing passed its check")
	}
}

func TestScopeCheckFailsOnAMalformedFile(t *testing.T) {
	path := writeScope(t, "scope:\n  allowed:\n   - a\n  bad indentation: [\n")
	if _, _, err := runCLI(t, "scope", "check", path); err == nil {
		t.Error("a malformed scope file passed its check")
	}
}

func TestScopeCheckWritesASummary(t *testing.T) {
	path := writeScope(t, goodScope)
	out := filepath.Join(t.TempDir(), "summary.md")
	if _, _, err := runCLI(t, "scope", "check", path, "-O", out); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("the summary was not written: %v", err)
	}
	if !strings.Contains(string(body), "# Authorised scope") {
		t.Errorf("summary:\n%s", body)
	}
}

func TestScopeExplain(t *testing.T) {
	path := writeScope(t, goodScope)
	stdout, _, err := runCLI(t, "scope", "explain", "www.example.com", "--scope", path)
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	if !strings.Contains(stdout, "allowed:") || !strings.Contains(stdout, "true") {
		t.Errorf("explain output:\n%s", stdout)
	}

	_, _, err = runCLI(t, "scope", "explain", "other-target.net", "--scope", path)
	if err == nil {
		t.Error("explain reported an out-of-scope host as permitted")
	}

	_, _, err = runCLI(t, "scope", "explain", "internal.example.com", "--scope", path)
	if err == nil {
		t.Error("explain reported an excluded host as permitted")
	}
}

// --- other commands ----------------------------------------------------------

func TestRulesListsEveryRule(t *testing.T) {
	stdout, _, err := runCLI(t, "rules")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "SEVERITY") || !strings.Contains(stdout, "MANUAL") {
		t.Errorf("the rules table has no header:\n%s", stdout)
	}
	if !strings.Contains(stdout, "http-missing-hsts") {
		t.Errorf("a known rule is missing from the list:\n%s", stdout)
	}
	// A rule needing a human must be identifiable in the listing, not only in
	// the output.
	if !strings.Contains(stdout, "yes") {
		t.Errorf("no rule is marked as requiring manual verification:\n%s", stdout)
	}
}

func TestVersionAndHelp(t *testing.T) {
	stdout, _, err := runCLI(t, "version")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "bugbounty") {
		t.Errorf("version output = %q", stdout)
	}

	stdout, _, err = runCLI(t, "--help")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"scan", "scope", "report", "rules", "config"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("help does not mention %q", want)
		}
	}
}

func TestBareInvocationIsInert(t *testing.T) {
	// Running the binary with no arguments must not scan anything.
	stdout, _, err := runCLI(t)
	if err != nil {
		t.Fatalf("bare invocation errored: %v", err)
	}
	if !strings.Contains(stdout, "Usage") && !strings.Contains(stdout, "Available Commands") {
		t.Errorf("bare invocation did not print help:\n%s", stdout)
	}
}

func TestUnknownFormatIsRejected(t *testing.T) {
	if _, _, err := runCLI(t, "report", "--format", "postscript", "--config", writeConfig(t)); err == nil {
		t.Error("an unknown report format was accepted")
	}
}

func TestConfigInitWritesAnOwnerOnlyFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no POSIX mode bits")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	stdout, _, err := runCLI(t, "config", "init", path)
	if err != nil {
		t.Fatalf("config init: %v", err)
	}
	if !strings.Contains(stdout, "wrote") {
		t.Errorf("init output = %q", stdout)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("SECURITY: the config file mode is %04o, want owner-only", perm)
	}
}

func TestConfigInitRefusesToClobber(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runCLI(t, "config", "init", path); err == nil {
		t.Error("init overwrote an existing file without --force")
	}
	if _, _, err := runCLI(t, "config", "init", path, "--force"); err != nil {
		t.Errorf("--force was rejected: %v", err)
	}
}

func TestConfigShowNeverPrintsACredential(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := "version: 1\nsecrets:\n  shodan: BUGBOUNTY_SHODAN_API_KEY\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BUGBOUNTY_SHODAN_API_KEY", "super-secret-credential-value")

	stdout, _, err := runCLI(t, "config", "show", "--config", path)
	if err != nil {
		t.Fatalf("config show: %v", err)
	}
	if strings.Contains(stdout, "super-secret-credential-value") {
		t.Errorf("SECURITY: the credential was printed:\n%s", stdout)
	}
	// Naming the provider is useful and safe; its value is not.
	if !strings.Contains(stdout, "shodan") {
		t.Errorf("the resolved provider is not listed:\n%s", stdout)
	}
}

func writeConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
