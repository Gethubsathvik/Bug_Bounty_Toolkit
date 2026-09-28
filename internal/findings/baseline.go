package findings

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/bbtoolkit/bugbounty/internal/fingerprint"
)

// TechState is the operator's view of one product's support status.
type TechState struct {
	// Latest is the newest version considered current.
	Latest string
	// Outdated means the observed version is behind Latest.
	Outdated bool
	// EndOfLife means the product line receives no further fixes at all.
	EndOfLife bool
	// Reason is a human sentence explaining the state, carried into the
	// finding so the report never shows a bare flag with no explanation.
	Reason string
}

// Baseline is a table of known technology support states.
//
// It is supplied by the operator rather than baked into the toolkit, because
// "current" is a business decision: a five-year-old LTS release may be exactly
// the supported version for a piece of industrial firmware. A toolkit that
// decided on its own would produce confident nonsense.
type Baseline struct {
	states map[string]TechState
	// asset records which URL produced each fingerprint hit, so a finding can
	// name the host the technology was seen on.
	asset map[string]string
}

// EmptyBaseline returns a baseline that flags nothing.
func EmptyBaseline() *Baseline {
	return &Baseline{states: map[string]TechState{}, asset: map[string]string{}}
}

// NewBaseline builds a baseline from product name to support state.
func NewBaseline(states map[string]TechState) *Baseline {
	b := &Baseline{states: make(map[string]TechState, len(states)), asset: map[string]string{}}
	for k, v := range states {
		b.states[normalizeTechName(k)] = v
	}
	return b
}

// Lookup returns the recorded state for a product.
func (b *Baseline) Lookup(name string) (TechState, bool) {
	if b == nil || b.states == nil {
		return TechState{}, false
	}
	st, ok := b.states[normalizeTechName(name)]
	return st, ok
}

// Products lists the baseline's product names in sorted order.
func (b *Baseline) Products() []string {
	if b == nil {
		return nil
	}
	out := make([]string, 0, len(b.states))
	for k := range b.states {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// assetFor returns the URL a technology hit was observed on, if known.
func (b *Baseline) assetFor(hit fingerprint.Hit) string {
	if b == nil {
		return ""
	}
	return b.asset[normalizeTechName(hit.Name)]
}

// WithAssets returns a copy of the baseline that maps each product to the URL
// it was observed on.
func (b *Baseline) WithAssets(assets map[string]string) *Baseline {
	out := EmptyBaseline()
	if b != nil {
		for k, v := range b.states {
			out.states[k] = v
		}
	}
	for k, v := range assets {
		out.asset[normalizeTechName(k)] = v
	}
	return out
}

func normalizeTechName(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// CompareVersions orders dotted numeric versions. It returns -1, 0 or 1.
//
// It is deliberately simple and only understands dotted numbers, because that
// is what technology banners actually contain. Anything it cannot parse
// compares as equal, which makes a rule fall back to the operator's explicit
// EndOfLife flag rather than inventing an ordering.
func CompareVersions(a, b string) int {
	as, aok := parseNumericVersion(a)
	bs, bok := parseNumericVersion(b)
	if !aok || !bok {
		return 0
	}
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		av, bv := 0, 0
		if i < len(as) {
			av = as[i]
		}
		if i < len(bs) {
			bv = bs[i]
		}
		switch {
		case av < bv:
			return -1
		case av > bv:
			return 1
		}
	}
	return 0
}

// parseNumericVersion extracts leading dotted integers from a version string,
// tolerating a suffix such as "1.18.0-alpine".
func parseNumericVersion(v string) ([]int, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, false
	}
	var parts []int
	cur := strings.Builder{}
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
			cur.WriteRune(r)
		case r == '.':
			n, err := strconv.Atoi(cur.String())
			if err != nil {
				return nil, false
			}
			parts = append(parts, n)
			cur.Reset()
		default:
			// Anything else ends the numeric prefix.
			if cur.Len() > 0 {
				n, err := strconv.Atoi(cur.String())
				if err != nil {
					return nil, false
				}
				parts = append(parts, n)
			}
			if len(parts) == 0 {
				return nil, false
			}
			return parts, true
		}
	}
	if cur.Len() > 0 {
		n, err := strconv.Atoi(cur.String())
		if err != nil {
			return nil, false
		}
		parts = append(parts, n)
	}
	if len(parts) == 0 {
		return nil, false
	}
	return parts, true
}

// String renders a TechState for a report.
func (s TechState) String() string {
	switch {
	case s.Reason != "":
		return s.Reason
	case s.EndOfLife:
		return "no longer supported"
	case s.Outdated:
		return fmt.Sprintf("behind %s", s.Latest)
	default:
		return "current"
	}
}
