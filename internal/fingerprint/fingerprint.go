// Package fingerprint identifies technologies and inspects response security
// posture from data that has already been collected.
//
// The signature set is data, not code: signatures.yaml is embedded in the
// binary and parsed at start-up with strict validation. Adding a technology
// means adding a YAML entry, and the engine rejects a signature that is too
// large, too ambiguous, or whose pattern could be slow against hostile input.
package fingerprint

import (
	_ "embed"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/bbtoolkit/bugbounty/pkg/models"
)

//go:embed signatures.yaml
var signatureYAML []byte

// Limits applied to every pattern so that a hostile response body cannot turn
// signature matching into a denial of service.
const (
	// MaxPatternLen bounds a single regular expression.
	MaxPatternLen = 512
	// MaxBodyScan bounds how much of a body is scanned per signature group.
	MaxBodyScan = 2 << 20
	// MaxSignatures bounds the signature set.
	MaxSignatures = 512
	// MaxMatches bounds how many technology hits one response can produce.
	MaxMatches = 32
)

// Weight expresses how much evidence a single match carries.
type Weight string

const (
	WeightLow    Weight = "low"
	WeightMedium Weight = "medium"
	WeightHigh   Weight = "high"
)

// Rule is one match condition inside a signature.
type Rule struct {
	Regex  string `yaml:"regex"`
	Weight Weight `yaml:"weight"`
}

// Signature is one technology fingerprint.
type Signature struct {
	Name       string              `yaml:"name"`
	Category   string              `yaml:"category"`
	Confidence string              `yaml:"confidence"`
	Headers    map[string][]string `yaml:"headers"`
	Cookies    map[string][]string `yaml:"cookies"`
	Body       []Rule              `yaml:"body"`

	compiledHeaders map[string][]*regexp.Regexp
	compiledCookies map[string][]*regexp.Regexp
	compiledBody    []compiledRule
}

type compiledRule struct {
	re     *regexp.Regexp
	weight Weight
}

// Set is the parsed, compiled signature database.
type Set struct {
	Version    int
	signatures []*Signature
	index      map[string][]*Signature
}

// Load parses the embedded signature database.
func Load() (*Set, error) { return Parse(signatureYAML) }

// LoadBytes parses a signature database supplied by the operator. It is only
// used when a config explicitly enables custom signatures.
func LoadBytes(b []byte) (*Set, error) { return Parse(b) }

// Parse validates and compiles a signature database.
func Parse(raw []byte) (*Set, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("fingerprint: signature database is empty")
	}
	if len(raw) > 1<<20 {
		return nil, fmt.Errorf("fingerprint: signature database is larger than 1 MiB")
	}
	var doc struct {
		Version      int          `yaml:"version"`
		Technologies []*Signature `yaml:"technologies"`
	}
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("fingerprint: parsing signatures: %w", err)
	}
	if doc.Version != 1 {
		return nil, fmt.Errorf("fingerprint: unsupported signature version %d", doc.Version)
	}
	if len(doc.Technologies) == 0 {
		return nil, fmt.Errorf("fingerprint: signature database contains no technologies")
	}
	if len(doc.Technologies) > MaxSignatures {
		return nil, fmt.Errorf("fingerprint: %d signatures exceeds the limit of %d", len(doc.Technologies), MaxSignatures)
	}

	s := &Set{Version: doc.Version, index: map[string][]*Signature{}}
	seen := map[string]bool{}
	for _, sig := range doc.Technologies {
		if strings.TrimSpace(sig.Name) == "" {
			return nil, fmt.Errorf("fingerprint: a signature has no name")
		}
		key := strings.ToLower(sig.Name)
		if seen[key] {
			return nil, fmt.Errorf("fingerprint: duplicate signature %q", sig.Name)
		}
		seen[key] = true
		if err := sig.compile(); err != nil {
			return nil, fmt.Errorf("fingerprint: signature %q: %w", sig.Name, err)
		}
		s.signatures = append(s.signatures, sig)
	}
	// Index by header and cookie name so matching is a map lookup rather than
	// a scan of every signature.
	for _, sig := range s.signatures {
		for h := range sig.Headers {
			s.index["h:"+strings.ToLower(h)] = append(s.index["h:"+strings.ToLower(h)], sig)
		}
		for c := range sig.Cookies {
			s.index["c:"+strings.ToLower(c)] = append(s.index["c:"+strings.ToLower(c)], sig)
		}
	}
	return s, nil
}

func (s *Signature) compile() error {
	if s.Confidence == "" {
		s.Confidence = string(models.ConfidenceMedium)
	}
	switch models.Confidence(s.Confidence) {
	case models.ConfidenceLow, models.ConfidenceMedium, models.ConfidenceHigh:
	default:
		return fmt.Errorf("invalid confidence %q", s.Confidence)
	}
	s.compiledHeaders = map[string][]*regexp.Regexp{}
	for name, pats := range s.Headers {
		// A dot means "this header is present at all", which is a common and
		// cheap signal; the value is not inspected.
		if len(pats) == 1 && pats[0] == "." {
			s.compiledHeaders[strings.ToLower(name)] = nil
			continue
		}
		compiled, err := compilePatterns(pats)
		if err != nil {
			return fmt.Errorf("header %q: %w", name, err)
		}
		s.compiledHeaders[strings.ToLower(name)] = compiled
	}
	s.compiledCookies = map[string][]*regexp.Regexp{}
	for name, pats := range s.Cookies {
		if len(pats) == 1 && pats[0] == "." {
			s.compiledCookies[strings.ToLower(name)] = nil
			continue
		}
		compiled, err := compilePatterns(pats)
		if err != nil {
			return fmt.Errorf("cookie %q: %w", name, err)
		}
		s.compiledCookies[strings.ToLower(name)] = compiled
	}
	for _, r := range s.Body {
		if r.Weight == "" {
			r.Weight = WeightMedium
		}
		if r.Weight != WeightLow && r.Weight != WeightMedium && r.Weight != WeightHigh {
			return fmt.Errorf("invalid weight %q", r.Weight)
		}
		re, err := compileOne(r.Regex)
		if err != nil {
			return err
		}
		s.compiledBody = append(s.compiledBody, compiledRule{re: re, weight: r.Weight})
	}
	if len(s.compiledHeaders) == 0 && len(s.compiledCookies) == 0 && len(s.compiledBody) == 0 {
		return fmt.Errorf("signature has no conditions and would match everything")
	}
	return nil
}

func compilePatterns(pats []string) ([]*regexp.Regexp, error) {
	out := make([]*regexp.Regexp, 0, len(pats))
	for _, p := range pats {
		re, err := compileOne(p)
		if err != nil {
			return nil, err
		}
		out = append(out, re)
	}
	return out, nil
}

func compileOne(pattern string) (*regexp.Regexp, error) {
	if pattern == "" {
		return nil, fmt.Errorf("empty pattern")
	}
	if len(pattern) > MaxPatternLen {
		return nil, fmt.Errorf("pattern is %d bytes, over the %d byte limit", len(pattern), MaxPatternLen)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid pattern %q: %w", truncate(pattern), err)
	}
	// Go's regexp is linear time, but an unanchored repeated group against a
	// multi-megabyte body is still measurable. Reject anything that could
	// degenerate rather than trying to detect it at run time.
	if strings.Count(pattern, ".*") > 3 {
		return nil, fmt.Errorf("pattern %q has too many unbounded repetitions", truncate(pattern))
	}
	return re, nil
}

func truncate(s string) string {
	if len(s) <= 60 {
		return s
	}
	return s[:60] + "..."
}

// Input is the already-collected response data to fingerprint.
type Input struct {
	URL         string
	Header      map[string][]string
	Body        []byte
	ContentType string
	Title       string
	// AssetNames are referenced file names observed in the body, used by
	// signatures that key on known asset paths.
	AssetNames []string
	// Server is the parsed Server header, exposed for reporting.
	Server string
}

// Hit is one fingerprint match.
type Hit struct {
	Name       string            `json:"name"`
	Category   string            `json:"category"`
	Version    string            `json:"version,omitempty"`
	Confidence models.Confidence `json:"confidence"`
	Evidence   string            `json:"evidence"`
	Source     string            `json:"source"`
}

// Match runs the signature set against a response. The returned hits are
// sorted by confidence then name so that output is deterministic.
func (s *Set) Match(in Input) []Hit {
	if s == nil || len(s.signatures) == 0 {
		return nil
	}
	// score accumulates evidence weight per signature so a single weak
	// low-weight match does not equal a high-weight generator tag.
	score := map[*Signature]int{}
	evidence := map[*Signature]string{}
	confidence := map[*Signature]models.Confidence{}
	order := []*Signature{}

	bump := func(sig *Signature, w Weight, why string) {
		if _, ok := score[sig]; !ok {
			order = append(order, sig)
			score[sig] = 0
			confidence[sig] = models.ConfidenceLow
		}
		score[sig] += weightValue(w)
		if why != "" && evidence[sig] == "" {
			evidence[sig] = why
		}
		// The effective confidence rises with accumulated evidence, capped by
		// what the signature itself claims.
		claimed := models.Confidence(sig.Confidence)
		level := models.ConfidenceLow
		switch {
		case score[sig] >= weightValue(WeightHigh)*2:
			level = models.ConfidenceHigh
		case score[sig] >= weightValue(WeightHigh):
			level = models.ConfidenceHigh
		case score[sig] >= weightValue(WeightMedium):
			level = models.ConfidenceMedium
		}
		if level.ConfidenceRank() > claimed.ConfidenceRank() {
			level = claimed
		}
		confidence[sig] = level
	}

	// Header signatures: only signatures that name a present header are even
	// considered. HTTP header names are case-insensitive, so the input map is
	// normalised once; indexing the caller's map directly would silently miss
	// every signature on a server that sends "Server" rather than "server".
	normalized := make(map[string][]string, len(in.Header))
	for name, vs := range in.Header {
		lk := strings.ToLower(name)
		normalized[lk] = append(normalized[lk], vs...)
	}
	for name := range normalized {
		for _, sig := range s.index["h:"+name] {
			pats := sig.compiledHeaders[name]
			if pats == nil {
				bump(sig, WeightHigh, "header "+name+" present")
				continue
			}
			for _, v := range normalized[name] {
				for _, re := range pats {
					if re.MatchString(v) {
						bump(sig, WeightHigh, "header "+name+": "+clip(v, 80))
						break
					}
				}
			}
		}
	}
	// Cookie-name signatures.
	for _, raw := range normalized["set-cookie"] {
		name := cookieName(raw)
		if name == "" {
			continue
		}
		for _, sig := range s.index["c:"+name] {
			pats := sig.compiledCookies[name]
			if pats == nil {
				bump(sig, WeightMedium, "cookie "+name)
				continue
			}
			for _, re := range pats {
				if re.MatchString(raw) {
					bump(sig, WeightHigh, "cookie "+name)
					break
				}
			}
		}
	}
	// Body signatures, scanned once over a bounded prefix.
	body := in.Body
	if len(body) > MaxBodyScan {
		body = body[:MaxBodyScan]
	}
	if len(body) > 0 {
		text := string(body)
		for _, sig := range s.signatures {
			for _, r := range sig.compiledBody {
				if r.re.MatchString(text) {
					bump(sig, r.weight, "body matches "+clip(r.re.String(), 60))
				}
			}
		}
	}

	hits := make([]Hit, 0, len(order))
	for _, sig := range order {
		if len(hits) >= MaxMatches {
			break
		}
		hits = append(hits, Hit{
			Name:       sig.Name,
			Category:   sig.Category,
			Version:    extractVersion(sig.Name, in),
			Confidence: confidence[sig],
			Evidence:   evidence[sig],
			Source:     "signature",
		})
	}
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].Confidence.ConfidenceRank() != hits[j].Confidence.ConfidenceRank() {
			return hits[i].Confidence.ConfidenceRank() > hits[j].Confidence.ConfidenceRank()
		}
		return hits[i].Name < hits[j].Name
	})
	return hits
}

func weightValue(w Weight) int {
	switch w {
	case WeightHigh:
		return 3
	case WeightMedium:
		return 2
	case WeightLow:
		return 1
	default:
		return 0
	}
}

func cookieName(setCookie string) string {
	s := strings.TrimSpace(setCookie)
	if i := strings.IndexByte(s, '='); i > 0 {
		return strings.ToLower(strings.TrimSpace(s[:i]))
	}
	return ""
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// versionPatterns extract a version adjacent to a technology name from the
// Server or X-Powered-By header, which is the only place a version is
// reliably exposed.
var versionPatterns = map[string]*regexp.Regexp{
	"default": regexp.MustCompile(`([A-Za-z][\w.+-]*?)[/ ]v?(\d+\.\d+(?:\.\d+)?)`),
}

// extractVersion pulls a version adjacent to a technology name out of the
// headers that reliably expose one. Header names are case-insensitive, so the
// lookups go through a normalised map rather than the caller's keys.
func extractVersion(tech string, in Input) string {
	pat := versionPatterns["default"]
	normalized := make(map[string][]string, len(in.Header))
	for name, vs := range in.Header {
		lk := strings.ToLower(name)
		normalized[lk] = append(normalized[lk], vs...)
	}
	for _, hdr := range []string{"server", "x-powered-by", "x-aspnet-version", "x-runtime"} {
		for _, v := range normalized[hdr] {
			for _, m := range pat.FindAllStringSubmatch(v, 8) {
				if strings.EqualFold(m[1], tech) {
					return m[2]
				}
			}
		}
	}
	return ""
}

// All returns every known signature name, for documentation and tests.
func (s *Set) All() []string {
	out := make([]string, 0, len(s.signatures))
	for _, sig := range s.signatures {
		out = append(out, sig.Name)
	}
	sort.Strings(out)
	return out
}

// Hit is also reported through the finding engine; this helper converts hits
// into the flat name list stored on a service record.
func Names(hits []Hit) []string {
	out := make([]string, 0, len(hits))
	for _, h := range hits {
		n := h.Name
		if h.Version != "" {
			n += " " + h.Version
		}
		out = append(out, n)
	}
	return out
}

var _ = time.Now
