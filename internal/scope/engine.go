// Package scope is the mandatory security boundary of the toolkit.
//
// Every network-enabled module must ask the Engine for a Decision before it
// performs I/O. The Engine is intentionally conservative:
//
//   - An empty or missing allowed list denies everything.
//   - Exclusions always win over allowances.
//   - Wildcards never match their own parent and can never wildcard a public
//     suffix.
//   - Special-purpose addresses (loopback, link-local, metadata, multicast,
//     reserved) are denied unless an explicit IP/CIDR rule names them; the
//     cloud metadata range additionally requires an explicit opt-in.
//   - Names are canonicalized through IDNA/punycode so that lookalike
//     domains cannot masquerade as in-scope.
package scope

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"sync"
)

// Decision is the result of a scope evaluation.
type Decision struct {
	// Allowed is the only field callers should branch on.
	Allowed bool `json:"allowed"`
	// Rule is the raw rule text that produced the decision.
	Rule string `json:"rule,omitempty"`
	// Reason is a human-readable explanation, safe to log.
	Reason string `json:"reason,omitempty"`
	// Host is the canonical host that was evaluated.
	Host string `json:"host,omitempty"`
	// IsIP reports whether Host was an IP literal.
	IsIP bool `json:"is_ip,omitempty"`
	// ExplicitRange reports whether the deciding rule named an address or
	// range directly (as opposed to a name that resolves there).
	ExplicitRange bool `json:"explicit_range,omitempty"`
}

func allow(rule Rule, host string, reason string) Decision {
	return Decision{Allowed: true, Rule: rule.Raw, Host: host, Reason: reason,
		IsIP: rule.Kind == KindIP || rule.Kind == KindCIDR, ExplicitRange: rule.IsExplicitNetworkRange()}
}

func deny(reason string) Decision {
	return Decision{Allowed: false, Reason: reason}
}

// Policy carries the operational limits and switches from the scope file. It
// lives here because the scheduler reads it while evaluating plugins.
type Policy struct {
	PassiveOnly        bool     `yaml:"passive_only" json:"passive_only"`
	MaxRPS             float64  `yaml:"max_rps" json:"max_rps"`
	MaxConcurrency     int      `yaml:"max_concurrency" json:"max_concurrency"`
	RequestTimeout     Duration `yaml:"request_timeout" json:"request_timeout"`
	RespectRobots      *bool    `yaml:"respect_robots" json:"respect_robots"`
	MaxRequestsPerRun  int      `yaml:"max_requests_per_run" json:"max_requests_per_run"`
	AllowedPorts       []int    `yaml:"allowed_ports" json:"allowed_ports"`
	AllowCloudMetadata bool     `yaml:"allow_cloud_metadata" json:"allow_cloud_metadata"`
	// MaxResponseBytes bounds any single HTTP response read into memory.
	MaxResponseBytes int64 `yaml:"max_response_bytes" json:"max_response_bytes"`
	// MaxRedirects bounds a single redirect chain.
	MaxRedirects int `yaml:"max_redirects" json:"max_redirects"`
}

// DefaultPolicy returns the conservative defaults applied when a scope file
// omits values. Everything here errs towards doing less.
func DefaultPolicy() Policy {
	respect := true
	return Policy{
		PassiveOnly:        false,
		MaxRPS:             2,
		MaxConcurrency:     5,
		RequestTimeout:     Duration(10_000_000_000), // 10s
		RespectRobots:      &respect,
		MaxRequestsPerRun:  5000,
		AllowedPorts:       []int{80, 443},
		AllowCloudMetadata: false,
		MaxResponseBytes:   5 << 20, // 5 MiB
		MaxRedirects:       10,
	}
}

// RobotsEnabled reports the effective robots.txt setting.
func (p Policy) RobotsEnabled() bool {
	if p.RespectRobots == nil {
		return true
	}
	return *p.RespectRobots
}

// Engine evaluates scope. It is safe for concurrent use.
type Engine struct {
	mu          sync.RWMutex
	allowed     []Rule
	excluded    []Rule
	policy      Policy
	warnings    []string
	sourcePath  string
	allowMeta   bool
	allowedPort map[int]struct{}
}

// New compiles an engine from raw rule text. Exclusions are optional; when nil
// the caller is assumed to have explicitly passed an empty (not "all") list.
func New(allowed, excluded []string, policy Policy) (*Engine, error) {
	e := &Engine{
		policy:      policy,
		sourcePath:  "",
		allowMeta:   policy.AllowCloudMetadata,
		allowedPort: map[int]struct{}{},
	}
	for _, p := range policy.AllowedPorts {
		if p > 0 && p < 65536 {
			e.allowedPort[p] = struct{}{}
		}
	}
	if len(e.allowedPort) == 0 {
		e.allowedPort[80] = struct{}{}
		e.allowedPort[443] = struct{}{}
	}
	for _, raw := range allowed {
		r, err := ParseRule(raw)
		if err != nil {
			return nil, err
		}
		e.allowed = append(e.allowed, r)
	}
	for _, raw := range excluded {
		r, err := ParseRule(raw)
		if err != nil {
			return nil, err
		}
		e.excluded = append(e.excluded, r)
	}
	e.validate()
	return e, nil
}

func (e *Engine) validate() {
	e.warnings = nil
	if len(e.allowed) == 0 {
		e.warnings = append(e.warnings, "allowed list is empty: every target will be denied")
	}
	if e.policy.MaxRPS > 0 && e.policy.MaxRPS > 20 {
		e.warnings = append(e.warnings, fmt.Sprintf("max_rps %.1f is unusually high for a bug bounty engagement", e.policy.MaxRPS))
	}
	if e.policy.MaxConcurrency > 50 {
		e.warnings = append(e.warnings, fmt.Sprintf("max_concurrency %d is unusually high", e.policy.MaxConcurrency))
	}
	if e.policy.AllowCloudMetadata {
		e.warnings = append(e.warnings, "allow_cloud_metadata is enabled: link-local addresses may be requested")
	}
	if !e.policy.RobotsEnabled() {
		e.warnings = append(e.warnings, "respect_robots is disabled: the crawler will request disallowed paths")
	}
	// Detect a rule that is entirely shadowed by an exclusion.
	for _, a := range e.allowed {
		for _, x := range e.excluded {
			if x.Raw == a.Raw {
				e.warnings = append(e.warnings, fmt.Sprintf("rule %q is also excluded and can never match", a.Raw))
			}
		}
	}
}

// NewDenyAll returns an engine that denies everything. It is what the CLI uses
// when no scope file was supplied, so that a missing configuration fails
// closed rather than open.
func NewDenyAll() *Engine {
	e, _ := New(nil, nil, DefaultPolicy())
	e.warnings = append(e.warnings, "no scope configured: all network operations are denied")
	return e
}

// Policy returns a copy of the policy.
func (e *Engine) Policy() Policy {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.policy
}

// WithPolicy returns a shallow copy of the engine with an updated policy. The
// rules are shared (they are immutable after compilation).
func (e *Engine) WithPolicy(p Policy) *Engine {
	e.mu.RLock()
	defer e.mu.RUnlock()
	c := &Engine{allowed: e.allowed, excluded: e.excluded, policy: p, warnings: e.warnings, sourcePath: e.sourcePath, allowMeta: p.AllowCloudMetadata}
	c.allowedPort = map[int]struct{}{}
	for _, p := range p.AllowedPorts {
		if p > 0 && p < 65536 {
			c.allowedPort[p] = struct{}{}
		}
	}
	if len(c.allowedPort) == 0 {
		c.allowedPort[80] = struct{}{}
		c.allowedPort[443] = struct{}{}
	}
	return c
}

// SourcePath reports the file the scope was loaded from, if any.
func (e *Engine) SourcePath() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.sourcePath
}

// SetSourcePath records the origin of the scope for reporting.
func (e *Engine) SetSourcePath(p string) {
	e.mu.Lock()
	e.sourcePath = p
	e.mu.Unlock()
}

// Rules returns copies of the allowed and excluded rules.
func (e *Engine) Rules() (allowed, excluded []Rule) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]Rule(nil), e.allowed...), append([]Rule(nil), e.excluded...)
}

func (e *Engine) addWarning(format string, args ...any) {
	e.warnings = append(e.warnings, fmt.Sprintf(format, args...))
}

// Warnings returns scope sanity warnings.
func (e *Engine) Warnings() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]string(nil), e.warnings...)
}

// HasAllowed reports whether any allowed rule exists.
func (e *Engine) HasAllowed() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.allowed) > 0
}

// passiveOnly gates active network work.
func (e *Engine) passiveOnly() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.policy.PassiveOnly
}

// PassiveOnly reports the effective passive-only setting.
func (e *Engine) PassiveOnly() bool { return e.passiveOnly() }

// RequireActive returns ErrNoScope-safe error when the engine forbids active
// network work. Every active module calls this first.
func (e *Engine) RequireActive() error {
	if e.passiveOnly() {
		return ErrPassiveOnly
	}
	if !e.HasAllowed() {
		return ErrNoScope
	}
	return nil
}

// ErrPassiveOnly is returned when active work is attempted in passive-only mode.
var ErrPassiveOnly = fmt.Errorf("scope: passive-only mode forbids active network operations")

// CheckHost evaluates a bare hostname or IP literal.
func (e *Engine) CheckHost(raw string) Decision {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.checkHostLocked(raw)
}

func (e *Engine) checkHostLocked(raw string) Decision {
	if len(e.allowed) == 0 {
		return deny("no allowed rules configured")
	}
	host, err := CanonicalizeDomain(raw)
	if err != nil {
		return deny("unparseable host: " + err.Error())
	}
	if addr, ok := hostToAddr(host); ok {
		return e.checkAddrLocked(addr, 0)
	}
	for _, r := range e.excluded {
		if ruleMatchesHost(r, host, true) {
			return deny("excluded by rule " + r.Raw)
		}
	}
	for _, r := range e.allowed {
		if ruleMatchesHost(r, host, false) {
			return allow(r, host, "host matched rule "+r.Raw)
		}
	}
	return deny("no allowed rule matches " + host)
}

// CheckAddr evaluates an IP address (for example, a resolved address before a
// connection is made to it).
func (e *Engine) CheckAddr(addr netip.Addr) Decision {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if !addr.IsValid() {
		return deny("invalid address")
	}
	return e.checkAddrLocked(addr.Unmap(), 0)
}

// checkAddrLocked evaluates an address. A rule that names the address counts as
// an explicit authorization whether it is written as an IP, a CIDR or an
// http://address:port/ URL rule, because in every one of those forms the
// operator wrote the address down.
//
// port is the port the caller intends to use, or 0 when it is not yet known.
func (e *Engine) checkAddrLocked(addr netip.Addr, port int) Decision {
	if len(e.allowed) == 0 {
		return deny("no allowed rules configured")
	}
	asText := addr.String()
	portOK := func(r Rule) bool {
		return r.Kind != KindURL || r.Port == 0 || port == 0 || r.Port == port
	}

	// Exclusions are evaluated first so an excluded range can never be reached
	// even if another rule would allow it.
	for _, r := range e.excluded {
		switch r.Kind {
		case KindIP:
			if r.Addr == addr {
				return deny("excluded by rule " + r.Raw)
			}
		case KindCIDR:
			if r.Prefix.Contains(addr) {
				return deny("excluded by rule " + r.Raw)
			}
		case KindURL:
			if r.Host == asText {
				return deny("excluded by rule " + r.Raw)
			}
		}
	}

	var matched *Rule
	for i := range e.allowed {
		r := e.allowed[i]
		switch r.Kind {
		case KindIP:
			if r.Addr == addr {
				matched = &e.allowed[i]
			}
		case KindCIDR:
			if r.Prefix.Contains(addr) {
				matched = &e.allowed[i]
			}
		case KindURL:
			if r.Host == asText && portOK(r) {
				matched = &e.allowed[i]
			}
		}
		if matched != nil {
			break
		}
	}
	if matched == nil {
		return deny(fmt.Sprintf("address %s is not covered by any allowed IP, CIDR or URL rule", asText))
	}
	if special, why := specialPurpose(addr); special {
		if !matched.IsExplicitNetworkRange() && matched.Kind != KindURL {
			return deny(fmt.Sprintf("%s: %s requires an explicit IP, CIDR or URL rule", addr, why))
		}
		if isCloudMetadata(addr) && !e.allowMeta {
			return deny(fmt.Sprintf("%s is the cloud instance metadata address, which is never contacted; it carries instance credentials and no programme authorises it", addr))
		}
	}
	return allow(*matched, asText, "address matched rule "+matched.Raw)
}

// CheckURL evaluates a full URL: scheme, host, port and path.
//
// The read lock is held for the same reason it is held by every other public
// check: the crawler and the HTTP client call this from several goroutines at
// once, and the engine advertises itself as safe for concurrent use. The helpers
// it calls below are the *Locked variants, so taking the lock here cannot
// deadlock on the non-reentrant RWMutex.
func (e *Engine) CheckURL(u *url.URL) Decision {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if u == nil {
		return deny("nil url")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return deny("scheme " + scheme + " is not permitted; only http and https")
	}
	if u.User != nil {
		return deny("URLs with embedded credentials are rejected")
	}
	host := u.Hostname()
	if host == "" {
		return deny("URL has no host")
	}
	if portStr := u.Port(); portStr != "" {
		port, err := parsePort(portStr)
		if err != nil {
			return deny("invalid port: " + err.Error())
		}
		if !e.portAllowedLocked(scheme, port) {
			return deny(fmt.Sprintf("port %d is not in the permitted port set", port))
		}
		if addr, ok := hostToAddr(strings.ToLower(host)); ok {
			// An address literal is judged on the address itself, with the port
			// known so that a URL rule naming a specific service is honoured.
			return e.checkAddrLocked(addr, port)
		}
	}
	// Host-level check first so an out-of-scope host is rejected even when a
	// URL rule would otherwise match on prefix alone.
	hd := e.checkHostLocked(host)
	if !hd.Allowed {
		return hd
	}
	// A path-scoped exclusion withdraws the part of the host it names, not the
	// whole host. It is enforced here, against the same hardened path matching
	// used for allowances, rather than by the host check: withdrawing the host
	// outright silently takes an authorised target out of scope, which is how
	// "https://example.com/admin-internal" in a scope file used to make
	// example.com itself unscannable.
	for _, r := range e.excluded {
		if r.Kind != KindURL || r.Host != hd.Host {
			continue
		}
		if schemeIn(r.Schemas, scheme) && (r.Port == 0 || portOf(u) == r.Port) &&
			pathTouches(u.EscapedPath(), r.PathPrefix) {
			return deny("excluded by rule " + r.Raw)
		}
	}
	// A URL rule can further restrict scheme/port/path. If any allowed URL
	// rule targets this host, the request must satisfy it.
	hasURLRule := false
	matchedURL := false
	for _, r := range e.allowed {
		if r.Kind != KindURL || r.Host != hd.Host {
			continue
		}
		hasURLRule = true
		if schemeIn(r.Schemas, scheme) && (r.Port == 0 || portOf(u) == r.Port) &&
			pathWithin(u.EscapedPath(), r.PathPrefix) {
			matchedURL = true
			break
		}
	}
	if hasURLRule && !matchedURL {
		return deny("host is in scope but this scheme/port/path is not covered by a URL rule")
	}
	if !hasURLRule && !hd.ExplicitRange {
		// A host matched by a plain domain rule is fine for either scheme.
		return hd
	}
	return hd
}

func (e *Engine) portAllowedLocked(scheme string, port int) bool {
	if _, ok := e.allowedPort[port]; ok {
		return true
	}
	// Default ports for the two permitted schemes are always allowed.
	if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
		return true
	}
	// A URL rule naming the port is an explicit authorization.
	for _, r := range e.allowed {
		if r.Kind == KindURL && r.Port == port {
			return true
		}
	}
	return false
}

func schemeIn(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func portOf(u *url.URL) int {
	p, err := parsePort(u.Port())
	if err != nil {
		return 0
	}
	return p
}

func parsePort(s string) (int, error) {
	if s == "" {
		return 0, nil
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("non-numeric port %q", s)
		}
		n = n*10 + int(s[i]-'0')
		if n > 65535 {
			return 0, fmt.Errorf("port %q out of range", s)
		}
	}
	if n == 0 {
		return 0, fmt.Errorf("port 0 is not valid")
	}
	return n, nil
}

// CheckResolvedAddr decides whether the toolkit may open a connection to addr
// on behalf of host, where host has already been admitted by a domain or URL
// rule.
//
// This is the DNS-rebinding defence. A hostname can resolve to a public address
// at validation time and to 127.0.0.1 a moment later; checking the name once
// and then letting the system resolver decide where to connect leaves that
// window open. The transport therefore resolves explicitly, passes every
// candidate through this function, and dials only an address it approved.
//
// The rule is: a name in scope authorizes reaching *public* addresses, but not
// special-purpose ones. Reaching loopback, link-local, the cloud metadata
// service or a private range still requires an explicit IP or CIDR rule naming
// the range, and the metadata range additionally requires the documented
// opt-in.
func (e *Engine) CheckResolvedAddr(host string, addr netip.Addr) Decision {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if !addr.IsValid() {
		return deny("invalid address")
	}
	a := addr.Unmap()

	// An explicit exclusion always wins, exactly as it does for a direct
	// target. This is what stops a scoped hostname from being used as a proxy
	// to an excluded internal range.
	asText := a.String()
	for _, r := range e.excluded {
		switch r.Kind {
		case KindIP:
			if r.Addr == a {
				return deny("address excluded by rule " + r.Raw)
			}
		case KindCIDR:
			if r.Prefix.Contains(a) {
				return deny("address excluded by rule " + r.Raw)
			}
		case KindURL:
			if r.Host == asText {
				return deny("address excluded by rule " + r.Raw)
			}
		}
	}

	// A rule counts as covering the address when it names the address itself,
	// whether as an IP, a CIDR or an http://address:port/ URL rule.
	covered := false
	for _, r := range e.allowed {
		switch r.Kind {
		case KindIP:
			covered = r.Addr == a
		case KindCIDR:
			covered = r.Prefix.Contains(a)
		case KindURL:
			covered = r.Host == asText
		}
		if covered {
			break
		}
	}

	if special, why := specialPurpose(a); special {
		if !covered {
			return deny(fmt.Sprintf("%s resolves to %s (%s); an explicit IP or CIDR rule is required", host, a, why))
		}
		if isCloudMetadata(a) && !e.allowMeta {
			return deny(fmt.Sprintf("%s resolves to the cloud metadata address, which is never contacted; it carries instance credentials and no programme authorises it", a))
		}
		return allow(Rule{Raw: "explicit range rule", Kind: KindCIDR}, a.String(), "address covered by an explicit network rule")
	}

	if !covered {
		// Public address reached through a host that scope already admitted.
		return allow(Rule{Raw: "host rule", Kind: KindDomainExact}, a.String(), "public address behind in-scope host "+host)
	}
	return allow(Rule{Raw: "explicit range rule", Kind: KindCIDR}, a.String(), "address covered by an explicit network rule")
}

// ResolveAndCheck is the convenience form used by the HTTP transport and the
// DNS module: it filters a full answer set down to the addresses the toolkit is
// willing to contact.
func (e *Engine) ResolveAndCheck(host string, addrs []netip.Addr) (allowed []netip.Addr, denied []Decision) {
	for _, a := range addrs {
		if d := e.CheckResolvedAddr(host, a); d.Allowed {
			allowed = append(allowed, a.Unmap())
		} else {
			denied = append(denied, d)
		}
	}
	return allowed, denied
}

// ruleMatchesHost reports whether a rule admits a canonical hostname.
//
// exclude widens an exact-domain rule to cover its subdomains. Exclusions and
// allowances are deliberately asymmetric: "api.example.com" in the allow list
// admits exactly that one name, while "internal.example.com" in the exclude
// list withdraws the whole subtree beneath it. Without that widening, a
// subdomain of an excluded host would be reachable simply by picking a deeper
// name, which is a scope-evasion primitive rather than a convenience.
func ruleMatchesHost(r Rule, host string, exclude bool) bool {
	switch r.Kind {
	case KindDomainExact:
		if exclude {
			return sameHostOrSubdomain(host, r.Host)
		}
		return r.Host == host
	case KindDomainWildcard:
		// Deliberately requires a strict subdomain relationship so that
		// "*.example.com" cannot match "example.com" and "evil-example.com".
		return sameHostOrSubdomain(host, r.Suffix) && host != r.Suffix
	case KindURL:
		if exclude {
			// A URL exclusion is scoped to the scheme, port and path prefix it
			// names, and is enforced in CheckURL against the request itself.
			// Applying it here would withdraw the entire host instead, which is
			// broader than what the rule says and makes an authorised target
			// unscannable. An operator who means to remove a whole host writes a
			// plain domain exclusion, which still takes the entire subtree.
			return false
		}
		// An allowance admits the host; CheckURL then narrows it by scheme, port
		// and path.
		return r.Host == host
	default:
		return false
	}
}

// specialPurpose reports whether an address is in a range that should not be
// contacted by default.
func specialPurpose(a netip.Addr) (bool, string) {
	if a.IsLoopback() {
		return true, "loopback addresses are not contactable targets"
	}
	if a.IsUnspecified() {
		return true, "the unspecified address is not a target"
	}
	if a.IsMulticast() {
		return true, "multicast addresses are not targets"
	}
	if a.IsLinkLocalUnicast() {
		return true, "link-local addresses reach the local network and the cloud metadata service"
	}
	if a.IsLinkLocalMulticast() {
		return true, "link-local multicast is not a target"
	}
	if a.IsInterfaceLocalMulticast() {
		return true, "interface-local multicast is not a target"
	}
	for _, p := range specialPrefixes {
		if p.Contains(a) {
			return true, p.String() + " is a reserved or private range"
		}
	}
	return false, ""
}

var specialPrefixes = func() []netip.Prefix {
	cidrs := []string{
		"0.0.0.0/8",          // "this network"
		"10.0.0.0/8",         // RFC 1918 private
		"100.64.0.0/10",      // carrier-grade NAT
		"169.254.0.0/16",     // RFC 3927 link local, also where cloud metadata lives
		"172.16.0.0/12",      // RFC 1918 private
		"192.0.0.0/24",       // IETF protocol assignments
		"192.0.2.0/24",       // TEST-NET-1
		"192.168.0.0/16",     // RFC 1918 private
		"198.18.0.0/15",      // benchmarking
		"198.51.100.0/24",    // TEST-NET-2
		"203.0.113.0/24",     // TEST-NET-3
		"224.0.0.0/4",        // multicast
		"240.0.0.0/4",        // reserved
		"255.255.255.255/32", // limited broadcast
		"::/128",             // unspecified
		"64:ff9b::/96",       // NAT64
		"100::/64",           // discard-only
		"2001:db8::/32",      // documentation
		"2002::/16",          // 6to4 (can encapsulate arbitrary IPv4)
		"fc00::/7",           // unique local
		"fe80::/10",          // link local
		"ff00::/8",           // multicast
	}
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			panic("scope: bad built-in prefix " + c)
		}
		out = append(out, p)
	}
	return out
}()

// isCloudMetadata reports whether an address is a well-known cloud instance
// metadata service endpoint.
func isCloudMetadata(a netip.Addr) bool {
	for _, p := range metadataPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

var metadataPrefixes = func() []netip.Prefix {
	cidrs := []string{"169.254.169.254/32", "169.254.170.2/32", "fd00:ec2::254/128"}
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err == nil {
			out = append(out, p)
		}
	}
	return out
}()

// IsCloudMetadataAddr is the exported form used by the HTTP transport so it
// can refuse cloud metadata endpoints even when a resolver lies about them.
func IsCloudMetadataAddr(a netip.Addr) bool { return isCloudMetadata(a.Unmap()) }

// HostInScope is the convenience form used widely by the modules.
func (e *Engine) HostInScope(host string) bool { return e.CheckHost(host).Allowed }

// URLInScope is the convenience form used by the HTTP client and crawler.
func (e *Engine) URLInScope(u *url.URL) bool { return e.CheckURL(u).Allowed }

// String renders a compact, log-safe summary of the engine.
func (e *Engine) String() string {
	a, x := e.Rules()
	s := fmt.Sprintf("scope{allowed:%d excluded:%d passive_only:%t}", len(a), len(x), e.passiveOnly())
	for _, r := range a {
		s += "\n  + " + r.Raw
	}
	for _, r := range x {
		s += "\n  - " + r.Raw
	}
	return s
}
