package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/bbtoolkit/bugbounty/internal/scope"
)

// Profile is a named set of limits, module toggles and template policy that a
// pipeline run adopts. Individual settings can always be overridden on the
// command line, which is why the CLI applies the profile first and the flags
// second.
type Profile struct {
	Name           string         `yaml:"name"`
	Notes          string         `yaml:"notes"`
	Limits         LimitSet       `yaml:"limits"`
	Modules        Modules        `yaml:"modules"`
	TemplatePolicy TemplatePolicy `yaml:"template_policy"`
	Crawl          CrawlConfig    `yaml:"crawl"`
	HTTP           HTTPConfig     `yaml:"http"`
}

// LimitSet is the profile's operational budget.
type LimitSet struct {
	RequestsPerSecond float64        `yaml:"requests_per_second"`
	Concurrency       int            `yaml:"concurrency"`
	Timeout           scope.Duration `yaml:"timeout"`
	MaxPages          int            `yaml:"max_pages"`
	MaxResponseSize   int64          `yaml:"max_response_size"`
	MaxDepth          int            `yaml:"max_depth"`
	MaxRequestsPerRun int            `yaml:"max_requests_per_run"`
	Retries           int            `yaml:"retries"`
	PassiveOnly       bool           `yaml:"passive_only"`
}

// Modules toggles the pipeline stages.
type Modules struct {
	Subdomains  bool `yaml:"subdomains"`
	DNS         bool `yaml:"dns"`
	HTTP        bool `yaml:"http"`
	Fingerprint bool `yaml:"fingerprint"`
	Crawler     bool `yaml:"crawler"`
	Templates   bool `yaml:"templates"`
	Correlate   bool `yaml:"correlate"`
	Report      bool `yaml:"report"`
}

// TemplatePolicy restricts which template classes may run.
type TemplatePolicy struct {
	AllowedClasses []string `yaml:"allowed_classes"`
	MaxSeverity    string   `yaml:"max_severity"`
	AllowManual    bool     `yaml:"allow_manual_verification_templates"`
}

// BuiltinProfiles returns the profiles shipped with the toolkit. They are
// compiled in so that a fresh install works with no extra files.
func BuiltinProfiles() map[string]Profile {
	p := Profile{
		Name:  "passive",
		Notes: "No active network operations whatsoever. Only third-party data sources and analysis of data already collected.",
		Limits: LimitSet{
			RequestsPerSecond: 1, Concurrency: 2, Timeout: scope.Duration(10 * time.Second),
			MaxPages: 0, MaxResponseSize: 1 << 20, MaxDepth: 0, MaxRequestsPerRun: 200, Retries: 0, PassiveOnly: true,
		},
		Modules:        Modules{Subdomains: true, DNS: false, HTTP: false, Fingerprint: false, Crawler: false, Templates: false, Correlate: true, Report: true},
		TemplatePolicy: TemplatePolicy{AllowedClasses: []string{"passive"}, MaxSeverity: "informational"},
	}
	c := Profile{
		Name:  "conservative",
		Notes: "Low rate, small blast radius. Suitable for production targets and unknown third-party infrastructure.",
		Limits: LimitSet{
			RequestsPerSecond: 2, Concurrency: 5, Timeout: scope.Duration(10 * time.Second),
			MaxPages: 1000, MaxResponseSize: 5 << 20, MaxDepth: 5, MaxRequestsPerRun: 5000, Retries: 1,
		},
		Modules:        Modules{Subdomains: true, DNS: true, HTTP: true, Fingerprint: true, Crawler: true, Templates: true, Correlate: true, Report: true},
		TemplatePolicy: TemplatePolicy{AllowedClasses: []string{"passive", "safe-active"}, MaxSeverity: "high"},
	}
	s := Profile{
		Name:  "standard",
		Notes: "A moderate rate for an engagement where the operator controls the target infrastructure.",
		Limits: LimitSet{
			RequestsPerSecond: 10, Concurrency: 15, Timeout: scope.Duration(10 * time.Second),
			MaxPages: 5000, MaxResponseSize: 8 << 20, MaxDepth: 8, MaxRequestsPerRun: 50000, Retries: 2,
		},
		Modules:        Modules{Subdomains: true, DNS: true, HTTP: true, Fingerprint: true, Crawler: true, Templates: true, Correlate: true, Report: true},
		TemplatePolicy: TemplatePolicy{AllowedClasses: []string{"passive", "safe-active"}, MaxSeverity: "critical"},
	}
	b := Profile{
		Name:  "bugbounty",
		Notes: "Standard rate plus manual-verification templates, which only ever produce checklists.",
		Limits: LimitSet{
			RequestsPerSecond: 5, Concurrency: 10, Timeout: scope.Duration(10 * time.Second),
			MaxPages: 3000, MaxResponseSize: 8 << 20, MaxDepth: 6, MaxRequestsPerRun: 20000, Retries: 2,
		},
		Modules:        Modules{Subdomains: true, DNS: true, HTTP: true, Fingerprint: true, Crawler: true, Templates: true, Correlate: true, Report: true},
		TemplatePolicy: TemplatePolicy{AllowedClasses: []string{"passive", "safe-active", "manual-verification"}, MaxSeverity: "critical", AllowManual: true},
	}
	// "thorough" is accepted as an alias of "standard" so that a natural flag
	// does not error out.
	return map[string]Profile{
		"passive": p, "conservative": c, "standard": s, "bugbounty": b,
		"default": c, "thorough": s,
	}
}

// ProfileDir returns the directory searched for user profile files.
func ProfileDir() string {
	return filepath.Join(HomeDir(), "profiles")
}

// LoadProfile resolves a profile by name, preferring a user file in the
// profile directory and falling back to the built-ins.
func LoadProfile(name string) (Profile, error) {
	if name == "" {
		return Profile{}, fmt.Errorf("profile name is empty")
	}
	key := strings.ToLower(strings.TrimSpace(name))
	if !validProfileName(key) {
		return Profile{}, fmt.Errorf("invalid profile name %q", name)
	}
	p := filepath.Join(ProfileDir(), key+".yaml")
	if _, err := os.Stat(p); err == nil {
		return LoadProfileFile(p)
	}
	if prof, ok := BuiltinProfiles()[key]; ok {
		return prof, nil
	}
	// Allow a direct path.
	if strings.ContainsAny(name, "/\\") {
		return LoadProfileFile(name)
	}
	return Profile{}, fmt.Errorf("unknown profile %q; available: %s", name, strings.Join(ProfileNames(), ", "))
}

func validProfileName(n string) bool {
	if n == "" || len(n) > 64 {
		return false
	}
	for _, r := range n {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// ProfileNames returns the built-in profile names, sorted.
func ProfileNames() []string {
	names := []string{"bugbounty", "conservative", "passive", "standard"}
	return names
}

// LoadProfileFile reads a profile from disk in strict mode.
func LoadProfileFile(path string) (Profile, error) {
	f, err := os.Open(path)
	if err != nil {
		return Profile{}, fmt.Errorf("opening profile: %w", err)
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	var p Profile
	if err := dec.Decode(&p); err != nil {
		return Profile{}, fmt.Errorf("%s: %w", path, err)
	}
	if p.Name == "" {
		p.Name = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	return p, p.validate()
}

func (p Profile) validate() error {
	if p.Limits.Concurrency < 0 {
		return fmt.Errorf("limits.concurrency must not be negative")
	}
	if p.Limits.RequestsPerSecond < 0 {
		return fmt.Errorf("limits.requests_per_second must not be negative")
	}
	for _, c := range p.TemplatePolicy.AllowedClasses {
		switch c {
		case "passive", "safe-active", "manual-verification":
		default:
			return fmt.Errorf("template_policy.allowed_classes: unknown class %q", c)
		}
	}
	if p.Limits.PassiveOnly {
		for _, on := range []struct {
			name string
			val  bool
		}{{"http", p.Modules.HTTP}, {"crawler", p.Modules.Crawler}, {"dns", p.Modules.DNS}} {
			if on.val {
				return fmt.Errorf("profile %q is passive_only but enables the active module %q", p.Name, on.name)
			}
		}
	}
	return nil
}

// Apply overlays the profile onto a configuration. Only non-zero profile values
// take effect, so a partial profile file behaves as an overlay rather than a
// replacement.
func Apply(c Config, p Profile) Config {
	if p.Limits.RequestsPerSecond > 0 {
		c.Limits.RequestsPerSecond = p.Limits.RequestsPerSecond
	}
	if p.Limits.Concurrency > 0 {
		c.Limits.Concurrency = p.Limits.Concurrency
	}
	if p.Limits.Timeout > 0 {
		c.HTTP.Timeout = p.Limits.Timeout
	}
	if p.Limits.MaxPages > 0 {
		c.Limits.MaxPagesPerTarget = p.Limits.MaxPages
	}
	if p.Limits.MaxResponseSize > 0 {
		c.HTTP.MaxResponseBytes = p.Limits.MaxResponseSize
	}
	if p.Limits.MaxDepth > 0 {
		c.Limits.MaxCrawlDepth = p.Limits.MaxDepth
	}
	if p.Limits.MaxRequestsPerRun > 0 {
		c.Limits.MaxRequestsPerRun = p.Limits.MaxRequestsPerRun
	}
	if p.Limits.Retries > 0 {
		c.HTTP.Retries = p.Limits.Retries
	}
	if p.Limits.PassiveOnly {
		c.PassiveOnly = true
	}
	if len(p.TemplatePolicy.AllowedClasses) > 0 {
		c.Templates.AllowedClasses = p.TemplatePolicy.AllowedClasses
	}
	if p.Crawl.MaxParameters > 0 {
		c.Crawl.MaxParameters = p.Crawl.MaxParameters
	}
	if p.Crawl.Concurrency > 0 {
		c.Crawl.Concurrency = p.Crawl.Concurrency
	}
	if p.Crawl.RateLimit > 0 {
		c.Crawl.RateLimit = p.Crawl.RateLimit
	}
	if p.Crawl.Timeout > 0 {
		c.Crawl.Timeout = p.Crawl.Timeout
	}
	return c
}
