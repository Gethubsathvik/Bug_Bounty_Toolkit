package scope

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
)

// Canonicalization is the trust boundary for every name the toolkit touches.
// Two rules govern it:
//
//  1. Canonicalization must be *injective* — two different inputs must never
//     canonicalize to the same string. Otherwise an attacker could register a
//     lookalike domain that matches an in-scope rule. Punycode encoding (not
//     character folding) is used for that reason: U+00DF encodes to "xn--zca"
//     rather than being folded to "ss".
//  2. Anything that cannot be canonicalized unambiguously is rejected, never
//     guessed at.

var (
	// idnaProfile is strict and non-transitional. StrictDomainName rejects
	// underscores and other non-LDH characters; BidiRule rejects mixed
	// right-to-left/left-to-right labels, a common homograph technique.
	idnaProfile = idna.New(
		idna.MapForLookup(),
		idna.StrictDomainName(true),
		idna.Transitional(false),
		idna.ValidateLabels(true),
		idna.BidiRule(),
	)
)

const (
	maxHostLen    = 253
	maxLabelLen   = 63
	asciiTLDChars = "abcdefghijklmnopqrstuvwxyz0123456789-"
)

// CanonicalizeDomain converts an arbitrary host string into its canonical
// ASCII form. It accepts IP literals and returns their normalized textual
// representation.
func CanonicalizeDomain(in string) (string, error) {
	h := strings.TrimSpace(in)
	if h == "" {
		return "", fmt.Errorf("%w: empty host", ErrInvalidHost)
	}
	// Strip a URL scheme if the caller passed a full URL.
	if i := strings.Index(h, "://"); i >= 0 {
		u, err := url.Parse(h)
		if err != nil {
			return "", fmt.Errorf("%w: %v", ErrInvalidHost, err)
		}
		h = u.Host
	}
	// Strip userinfo.
	if i := strings.LastIndex(h, "@"); i >= 0 {
		h = h[i+1:]
	}
	// Strip brackets from IPv6 literals.
	if strings.HasPrefix(h, "[") {
		end := strings.Index(h, "]")
		if end < 0 {
			return "", fmt.Errorf("%w: unbalanced IPv6 brackets", ErrInvalidHost)
		}
		h = h[1:end]
	}
	if addr, err := netip.ParseAddr(h); err == nil {
		return addrString(addr)
	}
	// Strip the port. Only a single colon-separated all-numeric suffix counts
	// as a port, which keeps bare IPv6 literals (many colons, no brackets)
	// intact.
	if i := strings.LastIndex(h, ":"); i >= 0 {
		port := h[i+1:]
		if !strings.Contains(port, ":") && looksNumeric(port) {
			p, err := strconv.Atoi(port)
			if err != nil || p < 1 || p > 65535 {
				return "", fmt.Errorf("%w: port %q is out of range", ErrInvalidHost, port)
			}
			h = h[:i]
		}
	}

	// Trailing dot (fully-qualified form) is stripped; the two forms are the
	// same name and must not be able to escape a scope rule.
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		return "", fmt.Errorf("%w: empty host", ErrInvalidHost)
	}
	// The port may have been part of the literal ("1.2.3.4:8080"), so the
	// address is re-examined after the port is removed.
	if addr, err := netip.ParseAddr(h); err == nil {
		return addrString(addr)
	}

	// Reject anything with a wildcard or non-DNS character before IDNA, so that
	// a rule pattern is never mistaken for a concrete host.
	if strings.ContainsAny(h, " \t\n\r/\\?#*") {
		return "", fmt.Errorf("%w: illegal character in host", ErrInvalidHost)
	}
	if len(h) > maxHostLen {
		return "", fmt.Errorf("%w: host longer than %d bytes", ErrInvalidHost, maxHostLen)
	}

	lower := strings.ToLower(h)
	// DNS names that use underscores must bypass IDNA. IDNA is a domain-name
	// profile and rejects "_" outright, which would make _dmarc, _domainkey and
	// every other underscore name unresolvable, unscopeable and uncheckable.
	// Those labels are ordinary in DNS (RFC 1123 permits them and DKIM, DMARC
	// and SPF validation all depend on them), so they are validated directly
	// against the LDH-plus-underscore grammar instead.
	if isUnderscoreName(lower) {
		if err := validateUnderscoreName(lower); err != nil {
			return "", err
		}
		return lower, nil
	}
	ascii, err := idnaProfile.ToASCII(lower)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidHost, err)
	}
	if err := validateASCIIName(ascii); err != nil {
		return "", err
	}
	return ascii, nil
}

// isUnderscoreName reports whether a name uses the DNS service-record
// convention of a label beginning with an underscore, which is what
// _dmarc, _domainkey and _25._tcp look like. An underscore in the middle of an
// ordinary label is a typo or an attack, not a service record, and is still
// rejected.
func isUnderscoreName(h string) bool {
	for _, l := range strings.Split(h, ".") {
		if strings.HasPrefix(l, "_") {
			return true
		}
	}
	return false
}

// validateUnderscoreName applies the same structural checks as
// validateASCIIName, with a leading "_" added to the legal label characters.
// Wildcards, control characters and mid-label underscores stay rejected.
func validateUnderscoreName(h string) error {
	if h == "" {
		return fmt.Errorf("%w: empty host", ErrInvalidHost)
	}
	if len(h) > maxHostLen {
		return fmt.Errorf("%w: host longer than %d bytes", ErrInvalidHost, maxHostLen)
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if l == "" {
			return fmt.Errorf("%w: empty label in %q", ErrInvalidHost, h)
		}
		if len(l) > 63 {
			return fmt.Errorf("%w: label %q longer than 63 bytes", ErrInvalidHost, l)
		}
		if strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return fmt.Errorf("%w: label %q starts or ends with a hyphen", ErrInvalidHost, l)
		}
		// The exemption exists for "_dmarc" and friends, so a label must carry
		// at least one character beyond the underscore. A label that is just
		// "_" is not a service record, it is a name nobody can publish, and
		// accepting it would put a meaningless entry in an authorisation list.
		if strings.HasPrefix(l, "_") && len(l) == 1 {
			return fmt.Errorf("%w: label %q is an underscore with no name", ErrInvalidHost, l)
		}
		for i, r := range l {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			case r == '-':
			case r == '_' && i == 0:
			default:
				return fmt.Errorf("%w: illegal character %q in label %q", ErrInvalidHost, r, l)
			}
		}
	}
	return nil
}

func looksNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// addrString renders a validated, normalized address. Zone identifiers are
// rejected outright: "fe80::1%eth0" and "fe80::1%eth1" are the same address
// with two different textual forms, and allowing both would let one spelling of
// a target pass a check that the other spelling fails.
func addrString(a netip.Addr) (string, error) {
	if a.Zone() != "" {
		return "", fmt.Errorf("%w: zone identifiers are not allowed in scope targets", ErrInvalidHost)
	}
	n := normalizeAddr(a)
	if !n.IsValid() {
		return "", fmt.Errorf("%w: unresolvable address", ErrInvalidHost)
	}
	return n.String(), nil
}

// normalizeAddr canonicalizes an address: IPv4-mapped IPv6 is unmapped so that
// ::ffff:127.0.0.1 and 127.0.0.1 cannot be told apart.
func normalizeAddr(a netip.Addr) netip.Addr {
	if a.Zone() != "" {
		return netip.Addr{}
	}
	return a.Unmap()
}

// ParseAddrStrict parses an address and normalizes it. Unlike netip.ParseAddr
// it never returns an IPv4-mapped IPv6 address and never accepts zones.
func ParseAddrStrict(in string) (netip.Addr, error) {
	s := strings.TrimSpace(in)
	if s == "" {
		return netip.Addr{}, fmt.Errorf("%w: empty address", ErrInvalidAddr)
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		s = s[1 : len(s)-1]
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%w: %v", ErrInvalidAddr, err)
	}
	if a.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("%w: zone identifiers are not allowed", ErrInvalidAddr)
	}
	na := normalizeAddr(a)
	if !na.IsValid() {
		return netip.Addr{}, fmt.Errorf("%w: unresolvable address", ErrInvalidAddr)
	}
	return na, nil
}

// validateASCIIName enforces RFC 1123 LDH rules on the punycoded form.
func validateASCIIName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: empty host", ErrInvalidHost)
	}
	if len(name) > maxHostLen {
		return fmt.Errorf("%w: host too long", ErrInvalidHost)
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return fmt.Errorf("%w: %q is not a fully qualified name", ErrInvalidHost, name)
	}
	for i, l := range labels {
		if l == "" {
			return fmt.Errorf("%w: empty label in %q", ErrInvalidHost, name)
		}
		if len(l) > maxLabelLen {
			return fmt.Errorf("%w: label %q longer than %d", ErrInvalidHost, l, maxLabelLen)
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return fmt.Errorf("%w: label %q starts or ends with a hyphen", ErrInvalidHost, l)
		}
		for j := 0; j < len(l); j++ {
			c := l[j]
			if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' {
				continue
			}
			if c == '.' || c == '*' || c == '_' || c > unicode.MaxASCII {
				return fmt.Errorf("%w: illegal byte %q in label %q", ErrInvalidHost, c, l)
			}
			return fmt.Errorf("%w: illegal byte %q in label %q", ErrInvalidHost, c, l)
		}
		if i == len(labels)-1 {
			tld := l
			// An all-numeric last label is never a real public suffix. It is
			// almost always a mistyped IPv4 address ("999.999.999.999"), and
			// accepting it would let a typo silently become a scoped name.
			if looksNumeric(tld) {
				return fmt.Errorf("%w: %q has a numeric top-level label, which is almost always a malformed address", ErrInvalidHost, name)
			}
			if len(tld) < 2 {
				return fmt.Errorf("%w: implausible TLD %q", ErrInvalidHost, tld)
			}
			for j := 0; j < len(tld); j++ {
				if !strings.ContainsRune(asciiTLDChars, rune(tld[j])) {
					return fmt.Errorf("%w: illegal TLD %q", ErrInvalidHost, tld)
				}
			}
		}
	}
	return nil
}

// IsIPLiteral reports whether the canonical host is an IP address.
func IsIPLiteral(host string) bool {
	_, err := netip.ParseAddr(host)
	return err == nil
}

// hostToAddr converts a canonical host to an address, if it is one.
func hostToAddr(host string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return normalizeAddr(a), true
}

// sameHostOrSubdomain reports whether child == parent or child ends with
// "."+parent. Both arguments must already be canonical.
func sameHostOrSubdomain(child, parent string) bool {
	if child == parent {
		return true
	}
	return len(child) > len(parent) &&
		strings.HasSuffix(child, parent) &&
		child[len(child)-len(parent)-1] == '.'
}
