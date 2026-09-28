// Package config loads the toolkit's user configuration and pipeline profiles.
//
// Secrets are never stored in the configuration file: the file may only name
// the environment variable that holds a credential, and the value is read at
// the moment it is needed and never written to a log, a report or the
// database.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/bbtoolkit/bugbounty/internal/scope"
)

// Environment variable names. These are part of the documented interface.
const (
	EnvConfig      = "BUGBOUNTY_CONFIG"
	EnvDatabase    = "BUGBOUNTY_DB"
	EnvHTTPTimeout = "BUGBOUNTY_HTTP_TIMEOUT"
	EnvRateLimit   = "BUGBOUNTY_RATE_LIMIT"
	EnvConcurrency = "BUGBOUNTY_CONCURRENCY"
	EnvPassiveOnly = "BUGBOUNTY_PASSIVE_ONLY"
	EnvOutputDir   = "BUGBOUNTY_OUTPUT"
	EnvHome        = "BUGBOUNTY_HOME"
	EnvNoColor     = "NO_COLOR"
)

// Config is the user configuration document.
type Config struct {
	Version int `yaml:"version"`
	// PassiveOnly is the global switch that forbids every active network
	// operation. It can be set here or with --passive-only.
	PassiveOnly bool `yaml:"passive_only"`

	Database  DatabaseConfig `yaml:"database"`
	Output    OutputConfig   `yaml:"output"`
	HTTP      HTTPConfig     `yaml:"http"`
	Limits    LimitsConfig   `yaml:"limits"`
	Log       LogConfig      `yaml:"log"`
	DNS       DNSConfig      `yaml:"dns"`
	Crawl     CrawlConfig    `yaml:"crawl"`
	Passive   PassiveConfig  `yaml:"passive"`
	Templates TemplateConfig `yaml:"templates"`
	// Secrets maps a provider name to the NAME of the environment variable
	// that holds its credential. A literal value here is rejected at load.
	Secrets map[string]string `yaml:"secrets"`

	// Path records where this config was loaded from.
	Path string `yaml:"-"`
}

// DatabaseConfig points at the SQLite file.
type DatabaseConfig struct {
	Path string `yaml:"path"`
	// BusyTimeoutMillis controls SQLite lock contention.
	BusyTimeoutMillis int `yaml:"busy_timeout_ms"`
	// WAL enables write-ahead logging for better concurrent reads.
	WAL bool `yaml:"wal"`
}

// OutputConfig controls result output.
type OutputConfig struct {
	Dir   string `yaml:"dir"`
	Theme string `yaml:"theme"`
}

// HTTPConfig controls the hardened HTTP client.
type HTTPConfig struct {
	Timeout            scope.Duration `yaml:"timeout"`
	Retries            int            `yaml:"retries"`
	UserAgent          string         `yaml:"user_agent"`
	MaxResponseBytes   int64          `yaml:"max_response_bytes"`
	FollowRedirects    *bool          `yaml:"follow_redirects"`
	MaxRedirects       int            `yaml:"max_redirects"`
	InsecureSkipVerify bool           `yaml:"insecure_skip_verify"`
	Proxy              string         `yaml:"proxy"`
	// MaxIdleConnsPerHost bounds connection reuse.
	MaxIdleConnsPerHost int `yaml:"max_idle_conns_per_host"`
}

// LimitsConfig bounds the whole run.
type LimitsConfig struct {
	RequestsPerSecond float64        `yaml:"requests_per_second"`
	Concurrency       int            `yaml:"concurrency"`
	MaxRequestsPerRun int            `yaml:"max_requests_per_run"`
	MaxCrawlDepth     int            `yaml:"max_crawl_depth"`
	MaxPagesPerTarget int            `yaml:"max_pages_per_target"`
	MaxParameters     int            `yaml:"max_parameters"`
	MaxEndpoints      int            `yaml:"max_endpoints"`
	MaxSubdomains     int            `yaml:"max_subdomains"`
	DNSTimeout        scope.Duration `yaml:"dns_timeout"`
}

// LogConfig controls logging.
type LogConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	File   string `yaml:"file"`
}

// DNSConfig controls the resolver.
type DNSConfig struct {
	// Resolvers, when set, are used instead of the system resolver. Each
	// entry must be host:port. They are passed to the resolver verbatim after
	// validation.
	Resolvers []string       `yaml:"resolvers"`
	Timeout   scope.Duration `yaml:"timeout"`
	// RecursiveZones are the zones treated as in-scope for NS/SOA lookups.
	RecursiveZones []string `yaml:"recursive_zones"`
}

// CrawlConfig bounds the crawler.
type CrawlConfig struct {
	Depth           int            `yaml:"depth"`
	MaxPages        int            `yaml:"max_pages"`
	MaxResponseSize int64          `yaml:"max_response_size"`
	MaxParameters   int            `yaml:"max_parameters"`
	Concurrency     int            `yaml:"concurrency"`
	RateLimit       float64        `yaml:"rate_limit"`
	Timeout         scope.Duration `yaml:"timeout"`
	KnownFiles      []string       `yaml:"known_files"`
}

// PassiveConfig controls passive providers.
type PassiveConfig struct {
	Providers []string       `yaml:"providers"`
	CacheDir  string         `yaml:"cache_dir"`
	CacheTTL  scope.Duration `yaml:"cache_ttl"`
	Timeout   scope.Duration `yaml:"timeout"`
	Settings  map[string]any `yaml:"settings"`
}

// TemplateConfig controls the detection template engine.
type TemplateConfig struct {
	Dir                   string         `yaml:"dir"`
	AllowedClasses        []string       `yaml:"allowed_classes"`
	MaxRegexTime          scope.Duration `yaml:"max_regex_time"`
	MaxMatchesPerTemplate int            `yaml:"max_matches_per_template"`
	AllowCustomTemplates  bool           `yaml:"allow_custom_templates"`
}

// Default returns a conservative configuration.
func Default() Config {
	follow := true
	respectRobots := true
	_ = respectRobots
	return Config{
		Version: 1,
		Database: DatabaseConfig{
			Path:              "engagement.db",
			BusyTimeoutMillis: 5000,
			WAL:               true,
		},
		Output: OutputConfig{Dir: "results"},
		HTTP: HTTPConfig{
			Timeout:             scope.Duration(10 * time.Second),
			Retries:             1,
			UserAgent:           "bugbounty-toolkit/1.0 (+authorized-security-testing)",
			MaxResponseBytes:    5 << 20,
			FollowRedirects:     &follow,
			MaxRedirects:        10,
			InsecureSkipVerify:  false,
			MaxIdleConnsPerHost: 16,
		},
		Limits: LimitsConfig{
			RequestsPerSecond: 2,
			Concurrency:       5,
			MaxRequestsPerRun: 5000,
			MaxCrawlDepth:     5,
			MaxPagesPerTarget: 1000,
			MaxParameters:     500,
			MaxEndpoints:      2000,
			MaxSubdomains:     5000,
			DNSTimeout:        scope.Duration(5 * time.Second),
		},
		Log: LogConfig{Level: "info", Format: "json"},
		DNS: DNSConfig{Timeout: scope.Duration(5 * time.Second)},
		Crawl: CrawlConfig{
			Depth:           3,
			MaxPages:        500,
			MaxResponseSize: 5 << 20,
			MaxParameters:   300,
			Concurrency:     5,
			RateLimit:       2,
			Timeout:         scope.Duration(10 * time.Second),
			KnownFiles:      []string{"/.well-known/security.txt", "/robots.txt", "/sitemap.xml"},
		},
		Passive: PassiveConfig{
			Providers: []string{},
			CacheDir:  ".cache",
			CacheTTL:  scope.Duration(24 * time.Hour),
			Timeout:   scope.Duration(20 * time.Second),
			Settings:  map[string]any{},
		},
		Templates: TemplateConfig{
			Dir:                   "templates",
			AllowedClasses:        []string{"passive", "safe-active"},
			MaxRegexTime:          scope.Duration(2 * time.Second),
			MaxMatchesPerTemplate: 50,
			AllowCustomTemplates:  false,
		},
		Secrets: map[string]string{},
	}
}

// HomeDir resolves the toolkit's home directory.
func HomeDir() string {
	if h := os.Getenv(EnvHome); h != "" {
		return h
	}
	if runtime.GOOS == "windows" {
		if d, err := os.UserConfigDir(); err == nil {
			return filepath.Join(d, "bugbounty")
		}
		return filepath.Join(os.Getenv("USERPROFILE"), ".config", "bugbounty")
	}
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "bugbounty")
	}
	return filepath.Join(os.Getenv("HOME"), ".config", "bugbounty")
}

// DefaultConfigPath returns the default config file path.
func DefaultConfigPath() string {
	if p := os.Getenv(EnvConfig); p != "" {
		return p
	}
	return filepath.Join(HomeDir(), "config.yaml")
}

// ErrNotFound is returned when no config file exists.
type ErrNotFound struct{ Path string }

func (e *ErrNotFound) Error() string { return "no configuration file at " + e.Path }

// Load reads the configuration from path, or the default path when empty.
// A missing file is not an error: defaults are returned instead.
func Load(path string) (Config, error) {
	if path == "" {
		path = DefaultConfigPath()
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			cfg := Default()
			cfg.Path = path
			if envErr := applyEnv(&cfg); envErr != nil {
				return cfg, envErr
			}
			return cfg, &ErrNotFound{Path: path}
		}
		return Config{}, err
	}
	defer f.Close()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	cfg := Default()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("%s: %w", path, err)
	}
	cfg.Path = path
	if err := cfg.Validate(); err != nil {
		return cfg, fmt.Errorf("%s: %w", path, err)
	}
	if err := applyEnv(&cfg); err != nil {
		return cfg, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// Save writes the configuration to path as owner-only YAML.
//
// The file is created with mode 0600 and written through a temporary file in
// the same directory, then renamed. A configuration names the environment
// variables holding credentials, and it also holds the engagement scope; an
// accidentally world-readable copy of either is a problem worth the extra
// syscalls. A rename also means a crash mid-write cannot leave a truncated
// config behind, which matters because a half-written scope file could
// silently narrow or widen an engagement.
func (c Config) Save(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("config: no path given to save to")
	}
	if err := c.Validate(); err != nil {
		return fmt.Errorf("config: refusing to save an invalid configuration: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("config: %s: %w", path, err)
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&c); err != nil {
		return fmt.Errorf("config: %s: %w", path, err)
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("config: %s: %w", path, err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*.yaml")
	if err != nil {
		return fmt.Errorf("config: %s: %w", path, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := tmp.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		tmp.Close()
		return fmt.Errorf("config: %s: %w", tmpName, err)
	}
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		tmp.Close()
		return fmt.Errorf("config: %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("config: %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("config: %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("config: %s: %w", path, err)
	}
	return nil
}

// Validate enforces the configuration invariants that make the toolkit safe.
func (c *Config) Validate() error {
	if err := c.validateSecrets(); err != nil {
		return err
	}
	if c.Limits.RequestsPerSecond < 0 {
		return fmt.Errorf("limits.requests_per_second must not be negative")
	}
	if c.Limits.Concurrency < 1 {
		return fmt.Errorf("limits.concurrency must be at least 1")
	}
	if c.HTTP.Timeout.D() <= 0 {
		return fmt.Errorf("http.timeout must be greater than zero")
	}
	if c.HTTP.MaxResponseBytes <= 0 {
		return fmt.Errorf("http.max_response_bytes must be greater than zero")
	}
	if c.HTTP.InsecureSkipVerify {
		// This is allowed but never silent: callers must pass -insecure on the
		// command line too, so that TLS validation cannot be turned off by a
		// stray file.
		return fmt.Errorf("http.insecure_skip_verify cannot be set in a configuration file; pass --insecure on the command line so the operator sees it")
	}
	if c.HTTP.Proxy != "" {
		if !strings.Contains(c.HTTP.Proxy, "://") {
			return fmt.Errorf("http.proxy must include a scheme, for example http://127.0.0.1:8080")
		}
	}
	for _, r := range c.DNS.Resolvers {
		if _, _, err := splitHostPort(r); err != nil {
			return fmt.Errorf("dns.resolvers: %w", err)
		}
	}
	for _, t := range c.Templates.AllowedClasses {
		switch t {
		case "passive", "safe-active", "manual-verification":
		default:
			return fmt.Errorf("templates.allowed_classes: %q is not a known template class", t)
		}
	}
	// Remaining bounds. Each of these is a value that silently changes how hard
	// the toolkit presses or how much it keeps, so a nonsensical one is a
	// configuration error rather than something to clamp quietly.
	if c.HTTP.MaxRedirects < 0 || c.HTTP.MaxRedirects > 20 {
		return fmt.Errorf("http.max_redirects must be between 0 and 20, got %d", c.HTTP.MaxRedirects)
	}
	if c.HTTP.Retries < 0 || c.HTTP.Retries > 5 {
		return fmt.Errorf("http.retries must be between 0 and 5, got %d", c.HTTP.Retries)
	}
	if c.Limits.Concurrency > 512 {
		return fmt.Errorf("limits.concurrency of %d is implausible and would be abusive to a target", c.Limits.Concurrency)
	}
	if c.Limits.MaxCrawlDepth < 0 {
		return fmt.Errorf("limits.max_crawl_depth must not be negative, got %d", c.Limits.MaxCrawlDepth)
	}
	if c.Limits.MaxPagesPerTarget < 0 {
		return fmt.Errorf("limits.max_pages_per_target must not be negative, got %d", c.Limits.MaxPagesPerTarget)
	}
	if c.Limits.MaxRequestsPerRun < 0 {
		return fmt.Errorf("limits.max_requests_per_run must not be negative, got %d", c.Limits.MaxRequestsPerRun)
	}
	if strings.TrimSpace(c.Database.Path) == "" {
		return errors.New("database.path must be set")
	}
	if strings.ContainsAny(c.Database.Path, "\x00\n\r") {
		return errors.New("database.path contains a control character")
	}
	switch c.Log.Format {
	case "", "text", "json":
	default:
		return fmt.Errorf("log.format must be text or json, got %q", c.Log.Format)
	}
	switch c.Log.Level {
	case "", "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log.level must be debug, info, warn or error, got %q", c.Log.Level)
	}
	return nil
}

// validateSecrets refuses a config that appears to contain a literal
// credential rather than an environment variable name.
func (c *Config) validateSecrets() error { return c.checkSecretShape() }

func splitHostPort(s string) (string, string, error) {
	i := strings.LastIndex(s, ":")
	if i <= 0 || i == len(s)-1 {
		return "", "", fmt.Errorf("%q is not host:port", s)
	}
	return s[:i], s[i+1:], nil
}

// applyEnv overlays environment variables, which always win over the file so
// that CI can adjust limits without editing tracked configuration.
//
// A malformed or out-of-range override is an error rather than a silent
// no-op. These are the knobs that decide how hard the toolkit presses against
// a target, so an operator who sets BB_CONCURRENCY must not be able to end up
// running with the file's value while believing theirs applied.
func applyEnv(c *Config) error {
	if v := os.Getenv(EnvDatabase); v != "" {
		c.Database.Path = v
	}
	if v := os.Getenv(EnvHTTPTimeout); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("%s: %q is not a duration: %w", EnvHTTPTimeout, v, err)
		}
		if d <= 0 {
			return fmt.Errorf("%s: %q must be greater than zero", EnvHTTPTimeout, v)
		}
		c.HTTP.Timeout = scope.Duration(d)
	}
	if v := os.Getenv(EnvRateLimit); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return fmt.Errorf("%s: %q is not a number: %w", EnvRateLimit, v, err)
		}
		if f < 0 {
			return fmt.Errorf("%s: %q must not be negative", EnvRateLimit, v)
		}
		c.Limits.RequestsPerSecond = f
	}
	if v := os.Getenv(EnvConcurrency); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("%s: %q is not an integer: %w", EnvConcurrency, v, err)
		}
		if n < 1 {
			return fmt.Errorf("%s: %q must be at least 1", EnvConcurrency, v)
		}
		c.Limits.Concurrency = n
	}
	if v := os.Getenv(EnvOutputDir); v != "" {
		c.Output.Dir = v
	}
	if v := os.Getenv(EnvPassiveOnly); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("%s: %q is not a boolean: %w", EnvPassiveOnly, v, err)
		}
		c.PassiveOnly = b
	}
	return nil
}

// Secret resolves a provider credential from the environment. It returns an
// empty string when the operator has not configured one, which every provider
// treats as "run without authentication".
//
// A resolved value too short to be a credential is reported as absent rather
// than handed to a provider: sending a three-character string as an API key
// produces a confusing 401 from the third party, whereas failing here names
// the actual problem.
func (c Config) Secret(provider string) (string, bool) {
	name, ok := c.secretEnvName(provider)
	if !ok || name == "" {
		return "", false
	}
	v := strings.TrimSpace(os.Getenv(name))
	if len(v) < MinSecretLength {
		return "", false
	}
	return v, true
}

// secretEnvName looks a provider up case-insensitively. Provider names come
// from user configuration and from plugin registrations written by different
// people, so "Shodan" and "shodan" have to mean the same thing or a
// credential silently fails to resolve.
func (c Config) secretEnvName(provider string) (string, bool) {
	if name, ok := c.Secrets[provider]; ok {
		return name, true
	}
	for k, v := range c.Secrets {
		if strings.EqualFold(k, provider) {
			return v, true
		}
	}
	return "", false
}

// ProvidersWithSecrets lists the providers that currently have a credential
// available, for status output. The credential itself is never exposed.
func (c Config) ProvidersWithSecrets() []string {
	var out []string
	for p := range c.Secrets {
		if v, ok := c.Secret(p); ok && v != "" {
			out = append(out, p)
		}
	}
	return out
}
