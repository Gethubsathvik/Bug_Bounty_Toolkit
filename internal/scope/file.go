package scope

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// FileVersion is the schema version this build understands.
const FileVersion = 1

// File is the on-disk scope definition.
type File struct {
	Version  int          `yaml:"version"`
	Metadata Metadata     `yaml:"metadata"`
	Scope    ScopeSection `yaml:"scope"`
	Policy   Policy       `yaml:"policy"`
	// Sources lists the passive providers the operator has enabled and any
	// non-secret provider settings. API keys are NEVER stored here: they come
	// from the environment (see internal/config).
	Sources SourcesSection `yaml:"sources"`
}

// Metadata is purely informational and is copied into reports.
type Metadata struct {
	Program   string `yaml:"program"`
	Reference string `yaml:"reference"`
	Notes     string `yaml:"notes"`
	Operator  string `yaml:"operator"`
	// AuthorizedUntil, when set, is surfaced in reports as a reminder. The
	// toolkit does not enforce a calendar deadline; that is the operator's
	// responsibility.
	AuthorizedUntil string `yaml:"authorized_until"`
}

// ScopeSection holds the allow and deny lists.
type ScopeSection struct {
	Allowed  []string `yaml:"allowed"`
	Excluded []string `yaml:"excluded"`
}

// SourcesSection configures passive providers.
type SourcesSection struct {
	Enabled  []string       `yaml:"enabled"`
	Disabled []string       `yaml:"disabled"`
	Options  map[string]any `yaml:"options"`
}

// ErrEmptyScope is returned when a scope file exists but allows nothing.
var ErrEmptyScope = errors.New("scope file contains no allowed targets")

// LoadFile reads and validates a scope file from disk.
func LoadFile(path string) (*Engine, *File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("opening scope file: %w", err)
	}
	defer f.Close()
	eng, file, err := Load(f)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	eng.SetSourcePath(path)
	return eng, file, nil
}

// Load parses a scope definition. The YAML decoder runs in strict mode so that
// a misspelled key is an error rather than a silently ignored safety setting.
func Load(r io.Reader) (*Engine, *File, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	var f File
	if err := dec.Decode(&f); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil, fmt.Errorf("scope file is empty")
		}
		return nil, nil, fmt.Errorf("parsing scope file: %w", err)
	}
	if f.Version == 0 {
		f.Version = FileVersion
	}
	if f.Version > FileVersion {
		return nil, nil, fmt.Errorf("scope file version %d is newer than this build (supports %d)", f.Version, FileVersion)
	}

	if len(f.Scope.Allowed) == 0 {
		return nil, nil, ErrEmptyScope
	}
	if err := validateReferences(f.Metadata.Reference); err != nil {
		return nil, &f, fmt.Errorf("metadata.reference: %w", err)
	}

	policy := mergePolicy(f.Policy)
	eng, err := New(f.Scope.Allowed, f.Scope.Excluded, policy)
	if err != nil {
		return nil, &f, err
	}
	if f.Policy.AllowCloudMetadata {
		// mergePolicy already forced the switch off. Say so, because an
		// operator who deliberately set the key needs to know it did nothing.
		eng.addWarning("policy.allow_cloud_metadata was ignored: the cloud metadata endpoint is never contacted")
	}
	return eng, &f, nil
}

// mergePolicy applies defaults to a partially specified policy and clamps
// values that would be unsafe.
func mergePolicy(p Policy) Policy {
	d := DefaultPolicy()
	out := d
	if p.MaxRPS > 0 {
		out.MaxRPS = p.MaxRPS
	}
	if p.MaxConcurrency > 0 {
		out.MaxConcurrency = p.MaxConcurrency
	}
	if p.RequestTimeout > 0 {
		out.RequestTimeout = p.RequestTimeout
	}
	if p.RespectRobots != nil {
		out.RespectRobots = p.RespectRobots
	}
	if p.MaxRequestsPerRun > 0 {
		out.MaxRequestsPerRun = p.MaxRequestsPerRun
	}
	if p.MaxResponseBytes > 0 {
		out.MaxResponseBytes = p.MaxResponseBytes
	}
	if p.MaxRedirects > 0 {
		out.MaxRedirects = p.MaxRedirects
	}
	if len(p.AllowedPorts) > 0 {
		cleaned := make([]int, 0, len(p.AllowedPorts))
		for _, port := range p.AllowedPorts {
			if port > 0 && port < 65536 {
				cleaned = append(cleaned, port)
			}
		}
		sort.Ints(cleaned)
		out.AllowedPorts = cleaned
	}
	// Cloud metadata access is a safety rail, not a preference, so it is
	// forced off here rather than taken from the file. A scope file that sets
	// the key is still accepted, because rejecting it would be a confusing
	// error for a key that looks like a harmless limit, but it has no effect:
	// reaching a cloud metadata endpoint is credential theft on any asset, and
	// no bug bounty authorises it.
	out.AllowCloudMetadata = false

	// Hard safety ceilings that no scope file can raise.
	const (
		maxRPSCeiling     = 100.0
		maxConcurrencyCap = 200
		maxResponseCap    = 64 << 20 // 64 MiB
	)
	if out.MaxRPS > maxRPSCeiling {
		out.MaxRPS = maxRPSCeiling
	}
	if out.MaxConcurrency > maxConcurrencyCap {
		out.MaxConcurrency = maxConcurrencyCap
	}
	if out.MaxResponseBytes > maxResponseCap {
		out.MaxResponseBytes = maxResponseCap
	}
	if out.MaxRedirects > 20 {
		out.MaxRedirects = 20
	}
	return out
}

func validateReferences(ref string) error {
	if ref == "" {
		return nil
	}
	if !strings.HasPrefix(ref, "https://") && !strings.HasPrefix(ref, "http://") {
		return errors.New("must be an http or https URL so a reader can verify the authorization")
	}
	if len(ref) > 2048 {
		return errors.New("is implausibly long")
	}
	return nil
}

// Summary is the machine-readable rendering used by `bugbounty scope show`.
type Summary struct {
	Source    string         `json:"source,omitempty"`
	Allowed   []string       `json:"allowed"`
	Excluded  []string       `json:"excluded"`
	Policy    Policy         `json:"policy"`
	Warnings  []string       `json:"warnings,omitempty"`
	Kinds     map[string]int `json:"rule_kinds"`
	DeniesAll bool           `json:"denies_all"`
}

// Summarize renders an engine for display and for report metadata.
func Summarize(e *Engine, f *File) Summary {
	allowed, excluded := e.Rules()
	s := Summary{
		Source:    e.SourcePath(),
		Policy:    e.Policy(),
		Warnings:  e.Warnings(),
		Kinds:     map[string]int{},
		DeniesAll: !e.HasAllowed(),
	}
	for _, r := range allowed {
		s.Allowed = append(s.Allowed, r.Raw)
		s.Kinds[string(r.Kind)]++
	}
	for _, r := range excluded {
		s.Excluded = append(s.Excluded, r.Raw)
		s.Kinds["excluded_"+string(r.Kind)]++
	}
	if f != nil {
		if len(s.Warnings) == 0 {
			_ = f
		}
	}
	return s
}
