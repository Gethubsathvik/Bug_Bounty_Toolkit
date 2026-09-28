package scope

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// RuleKind classifies a scope rule.
type RuleKind string

const (
	// KindDomainExact matches exactly one hostname, never its subdomains.
	KindDomainExact RuleKind = "domain"
	// KindDomainWildcard matches any subdomain of Suffix at any depth.
	// It deliberately does NOT match the suffix itself: "*.example.com"
	// matches "a.example.com" and "a.b.example.com" but not "example.com".
	KindDomainWildcard RuleKind = "wildcard_domain"
	// KindURL restricts a host to a scheme, port and path prefix.
	KindURL RuleKind = "url"
	// KindIP matches exactly one address.
	KindIP RuleKind = "ip"
	// KindCIDR matches any address inside a prefix.
	KindCIDR RuleKind = "cidr"
)

// Rule is a compiled, canonicalized scope entry.
type Rule struct {
	Raw  string   `json:"raw"`
	Kind RuleKind `json:"kind"`
	// Host is the canonical hostname for domain/url rules.
	Host string `json:"host,omitempty"`
	// Suffix is the parent domain for wildcard rules.
	Suffix string `json:"suffix,omitempty"`
	// Schemas holds the lowercase allowed URL schemes for url rules.
	Schemas []string `json:"schemas,omitempty"`
	// Port is the required port for url rules (0 means "default or any").
	Port int `json:"port,omitempty"`
	// PathPrefix is the normalized path prefix for url rules.
	PathPrefix string       `json:"path_prefix,omitempty"`
	Addr       netip.Addr   `json:"addr,omitempty"`
	Prefix     netip.Prefix `json:"prefix,omitempty"`
}

func (r Rule) String() string { return r.Raw }

// IsExplicitNetworkRange reports whether the rule explicitly names an address
// or range (as opposed to a name that merely resolves there). Only such rules
// can authorize a connection to a special-purpose address.
func (r Rule) IsExplicitNetworkRange() bool {
	return r.Kind == KindIP || r.Kind == KindCIDR
}

// ParseRule compiles a single scope rule. Everything the rule could be
// ambiguous about is resolved here, once, at load time.
func ParseRule(raw string) (Rule, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return Rule{}, fmt.Errorf("%w: empty rule", ErrInvalidRule)
	}
	r := Rule{Raw: s}

	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return Rule{}, fmt.Errorf("%w %q: %v", ErrInvalidRule, s, err)
		}
		if u.Scheme == "" {
			return Rule{}, fmt.Errorf("%w %q: missing scheme", ErrInvalidRule, s)
		}
		scheme := strings.ToLower(u.Scheme)
		if scheme != "http" && scheme != "https" {
			return Rule{}, fmt.Errorf("%w %q: only http and https rules are supported (got %q)", ErrInvalidRule, s, u.Scheme)
		}
		if u.User != nil {
			return Rule{}, fmt.Errorf("%w %q: embedded credentials are not allowed in scope rules", ErrInvalidRule, s)
		}
		h, err := CanonicalizeDomain(u.Host)
		if err != nil {
			return Rule{}, fmt.Errorf("%w %q: %v", ErrInvalidRule, s, err)
		}
		if IsIPLiteral(h) {
			// "https://10.0.0.1/admin" is a legitimate way to scope a
			// specific internal service.
			r.Kind = KindURL
			r.Host = h
			r.Schemas = []string{scheme}
			if p := u.Port(); p != "" {
				port, err := strconv.Atoi(p)
				if err != nil || port < 1 || port > 65535 {
					return Rule{}, fmt.Errorf("%w %q: invalid port", ErrInvalidRule, s)
				}
				r.Port = port
			}
			r.PathPrefix, err = normalizePathPrefix(u.EscapedPath())
			if err != nil {
				return Rule{}, fmt.Errorf("%w %q: %v", ErrInvalidRule, s, err)
			}
			return r, nil
		}
		r.Kind = KindURL
		r.Host = h
		r.Schemas = []string{scheme}
		if p := u.Port(); p != "" {
			port, err := strconv.Atoi(p)
			if err != nil || port < 1 || port > 65535 {
				return Rule{}, fmt.Errorf("%w %q: invalid port", ErrInvalidRule, s)
			}
			r.Port = port
		}
		r.PathPrefix, err = normalizePathPrefix(u.EscapedPath())
		if err != nil {
			return Rule{}, fmt.Errorf("%w %q: %v", ErrInvalidRule, s, err)
		}
		return r, nil
	}

	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return Rule{}, fmt.Errorf("%w %q: not a valid CIDR: %v", ErrInvalidRule, s, err)
		}
		if p.Addr().Zone() != "" {
			return Rule{}, fmt.Errorf("%w %q: zone identifiers are not allowed", ErrInvalidRule, s)
		}
		if err := checkScopableAddr(p.Addr()); err != nil {
			return Rule{}, fmt.Errorf("%w %q: %v", ErrInvalidRule, s, err)
		}
		p = netip.PrefixFrom(normalizeAddr(p.Addr()), p.Bits()).Masked()
		r.Kind = KindCIDR
		r.Prefix = p
		return r, nil
	}

	// "1.2.3.4:8080" is a legitimate way to scope one service on one address.
	// It is rewritten into an http URL rule so the existing scheme/port/path
	// machinery applies, instead of failing host validation on the numeric
	// label of the dotted quad.
	if strings.Count(s, ":") == 1 {
		if left, right, ok := strings.Cut(s, ":"); ok && looksNumeric(right) {
			if _, err := netip.ParseAddr(left); err == nil {
				return ParseRule("http://" + s + "/")
			}
		}
	}

	// Bare host. Distinguish a wildcard pattern from a concrete name.
	if strings.Contains(s, "*") {
		if err := validateWildcardPattern(s); err != nil {
			return Rule{}, err
		}
		suffix, err := CanonicalizeDomain(s[2:])
		if err != nil {
			return Rule{}, fmt.Errorf("%w %q: %v", ErrInvalidRule, s, err)
		}
		if isPublicSuffix(suffix) {
			return Rule{}, fmt.Errorf("%w %q: refusing to wildcard a public suffix; this would place the entire internet in scope", ErrInvalidRule, s)
		}
		r.Kind = KindDomainWildcard
		r.Suffix = suffix
		return r, nil
	}

	h, err := CanonicalizeDomain(s)
	if err != nil {
		return Rule{}, fmt.Errorf("%w %q: %v", ErrInvalidRule, s, err)
	}
	if addr, ok := hostToAddr(h); ok {
		if err := checkScopableAddr(addr); err != nil {
			return Rule{}, fmt.Errorf("%w %q: %v", ErrInvalidRule, s, err)
		}
		r.Kind = KindIP
		r.Addr = addr
		return r, nil
	}
	r.Kind = KindDomainExact
	r.Host = h
	return r, nil
}

// checkScopableAddr rejects addresses that are never a legitimate target, no
// matter what the operator writes. A scope file is an authorization document;
// letting it name "this network" or a multicast group would turn a typo into an
// unbounded scan. Private, loopback and link-local ranges ARE allowed when
// named explicitly, because internal engagements are a real use case.
func checkScopableAddr(a netip.Addr) error {
	switch {
	case !a.IsValid():
		return fmt.Errorf("not a valid address")
	case a.IsUnspecified():
		return fmt.Errorf("the unspecified address is never a target")
	case a.IsMulticast():
		return fmt.Errorf("multicast addresses are never targets")
	case a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return fmt.Errorf("the limited broadcast address is never a target")
	}
	return nil
}

func validateWildcardPattern(s string) error {
	if !strings.HasPrefix(s, "*.") {
		return fmt.Errorf("%w %q: a wildcard is only allowed as the leftmost label, written as \"*.\"", ErrInvalidRule, s)
	}
	rest := s[2:]
	if rest == "" {
		return fmt.Errorf("%w %q: wildcard with no parent domain", ErrInvalidRule, s)
	}
	if strings.Contains(rest, "*") {
		return fmt.Errorf("%w %q: only a single leading wildcard label is supported", ErrInvalidRule, s)
	}
	if strings.HasPrefix(rest, ".") || strings.HasSuffix(rest, ".") {
		return fmt.Errorf("%w %q: malformed wildcard parent", ErrInvalidRule, s)
	}
	if !strings.Contains(rest, ".") {
		return fmt.Errorf("%w %q: wildcard parent must be a fully qualified domain", ErrInvalidRule, s)
	}
	if !looksASCII(s) {
		return fmt.Errorf("%w %q: wildcard patterns must be written in punycode to avoid encoding ambiguity", ErrInvalidRule, s)
	}
	return nil
}

func looksASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return false
		}
	}
	return true
}

// normalizePathPrefix canonicalizes a URL path for prefix comparison. It
// resolves dot segments without touching the filesystem and refuses paths that
// try to escape the root.
func normalizePathPrefix(p string) (string, error) {
	if p == "" {
		return "/", nil
	}
	if !strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("path must be absolute")
	}
	var out []string
	segs := strings.Split(strings.TrimPrefix(p, "/"), "/")
	for i, s := range segs {
		switch s {
		case ".":
			if i == len(segs)-1 {
				out = append(out, "")
			}
			continue
		case "..":
			if len(out) == 0 {
				return "", fmt.Errorf("path escapes the URL root")
			}
			out = out[:len(out)-1]
			continue
		case "":
			// Preserve a trailing slash, collapse interior duplicates.
			if i == len(segs)-1 {
				out = append(out, "")
			}
			continue
		default:
			out = append(out, s)
		}
	}
	return "/" + strings.Join(out, "/"), nil
}

// pathWithin reports whether a request path is inside a rule's prefix.
// Both the escaped and the percent-decoded forms are checked, because a server
// will usually decode and the gateway in front of it usually will not: a
// scope check that only looked at one of the two could be bypassed with %2e%2e
// or with an encoded slash.
func pathWithin(reqEscaped, prefix string) bool {
	if prefix == "" || prefix == "/" {
		return true
	}
	normEsc, err := normalizePathPrefix(reqEscaped)
	if err != nil {
		return false
	}
	if !prefixMatch(normEsc, prefix) {
		return false
	}
	decoded, derr := decodePath(normEsc)
	if derr == nil {
		nd, nerr := normalizePathPrefix(decoded)
		if nerr != nil {
			return false
		}
		if !prefixMatch(nd, prefix) {
			return false
		}
	}
	// A second decode pass catches double encoding.
	if decoded2, err2 := decodePath(decoded); err2 == nil && decoded2 != decoded {
		nd, nerr := normalizePathPrefix(decoded2)
		if nerr != nil {
			return false
		}
		if !prefixMatch(nd, prefix) {
			return false
		}
	}
	return true
}

// pathTouches reports whether a request path reaches into a rule's prefix under
// any plausible decoding, and treats a path it cannot normalize as reaching in.
//
// This is the mirror image of pathWithin, and the mirror is the point.
// pathWithin answers the question an allowance asks -- "may I fetch this?" --
// where the tool has to prove the request is inside the prefix, so an
// unreadable path fails closed and the request is refused.
//
// An exclusion asks the opposite question -- "must I not fetch this?" -- and
// there the conservative direction reverses. A rule excluding
// "https://example.com/admin-internal" says do not fetch anything under
// /admin-internal. A path that cannot be normalized unambiguously, such as
// /admin-internal/%2e%2e/%2e%2e/secret, might resolve to anything, so it is
// treated as reaching into the subtree rather than as proof that it does not.
// Reading an unreadable exclusion as "nothing is excluded" would turn a typo
// into a licence to fetch the very subtree the operator withheld.
func pathTouches(reqEscaped, prefix string) bool {
	if prefix == "" || prefix == "/" {
		return true
	}
	current := reqEscaped
	// Three rounds cover the escaped form, one decode and a double decode,
	// which is as far as the allowance check goes.
	for i := 0; i < 3; i++ {
		norm, err := normalizePathPrefix(current)
		if err != nil {
			// The path escapes the URL root once resolved, so it cannot be
			// shown to stay outside the excluded subtree.
			return true
		}
		if prefixMatch(norm, prefix) {
			return true
		}
		decoded, derr := decodePath(norm)
		if derr != nil || decoded == current {
			return false
		}
		current = decoded
	}
	return false
}

// decodePath percent-decodes a path.
func decodePath(p string) (string, error) {
	u, err := url.PathUnescape(p)
	if err != nil {
		return "", err
	}
	return u, nil
}

// prefixMatch implements segment-aware prefix matching: "/api" matches "/api"
// and "/api/v1" but not "/apixyz".
func prefixMatch(p, prefix string) bool {
	if p == prefix {
		return true
	}
	if !strings.HasPrefix(p, prefix) {
		return false
	}
	if strings.HasSuffix(prefix, "/") {
		return true
	}
	return len(p) > len(prefix) && p[len(prefix)] == '/'
}
