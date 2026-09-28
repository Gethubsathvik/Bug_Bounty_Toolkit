// Package dns collects DNS records for in-scope names and reports
// configuration conditions worth a human's attention.
//
// Nothing here claims a vulnerability. A dangling CNAME, for example, produces
// a finding titled "possible dangling DNS" with a manual verification
// checklist, because whether the provider would actually hand the name over is
// something only the operator can check.
package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/bbtoolkit/bugbounty/internal/scope"
	"github.com/bbtoolkit/bugbounty/pkg/models"
)

// Resolver is the DNS interface, satisfied by *net.Resolver.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
}

// MaxRecordsPerType bounds how many records of one type are kept from a single
// answer. A zone that returns tens of thousands of records of one type is
// either broken or hostile, and neither is a reason to hold them all.
const MaxRecordsPerType = 256

// ResolverConfig configures the resolver.
type ResolverConfig struct {
	// Servers, when non-empty, are used instead of the system configuration.
	// Each must be host:port and is validated before use.
	Servers []string
	Timeout time.Duration
	// CacheTTL bounds how long an answer is reused. A cache avoids hammering
	// authoritative servers with the same question across modules.
	CacheTTL time.Duration
}

// Collector gathers DNS data under a scope.
type Collector struct {
	scope      *scope.Engine
	resolver   Resolver
	cfg        ResolverConfig
	cache      *cache
	roundRobin atomic.Uint64
}

// NewCollector builds a collector. A nil resolver falls back to the system one.
func NewCollector(sc *scope.Engine, r Resolver, cfg ResolverConfig) (*Collector, error) {
	if sc == nil {
		return nil, errors.New("dns: a scope engine is required")
	}
	if r == nil {
		r = net.DefaultResolver
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	switch {
	case cfg.CacheTTL < 0:
		// Negative is the only way to say "no cache". Zero means "use the
		// default", which keeps a zero-valued config useful.
		cfg.CacheTTL = 0
	case cfg.CacheTTL == 0:
		cfg.CacheTTL = 5 * time.Minute
	}
	for _, s := range cfg.Servers {
		if _, _, err := validateResolverServer(s); err != nil {
			return nil, fmt.Errorf("dns: invalid resolver %q: %w", s, err)
		}
	}
	c := &Collector{scope: sc, resolver: r, cfg: cfg, cache: newCache(cfg.CacheTTL)}
	if len(cfg.Servers) > 0 {
		c.resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				// Round-robin over the configured servers. Dial is passed the
				// address Go wanted, not the server list, so the rotation is
				// driven here and the requested server address is ignored.
				d := &net.Dialer{Timeout: cfg.Timeout}
				var errs []error
				for _, s := range c.nextServers() {
					conn, err := d.DialContext(ctx, network, s)
					if err == nil {
						return conn, nil
					}
					errs = append(errs, err)
				}
				return nil, errors.Join(errs...)
			},
		}
	}
	return c, nil
}

func (c *Collector) nextServers() []string {
	n := len(c.cfg.Servers)
	if n == 0 {
		return nil
	}
	start := int(c.roundRobin.Add(1)) % n
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, c.cfg.Servers[(start+i)%n])
	}
	return out
}

// validateResolverServer checks a configured resolver address strictly.
//
// net.SplitHostPort alone is not enough: it accepts a bare IPv6 literal with
// several colons and a non-numeric port, and passing either to the dialer
// produces a confusing failure at scan time rather than at load time. A
// resolver is operator-supplied configuration, so a mistake in it should stop
// the run instead of silently yielding no records.
func validateResolverServer(s string) (host, port string, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", errors.New("empty resolver address")
	}
	host, port, err = net.SplitHostPort(s)
	if err != nil {
		return "", "", fmt.Errorf("%q is not host:port: %w", s, err)
	}
	if host == "" {
		return "", "", fmt.Errorf("%q has no host", s)
	}
	if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		host = a.String()
	} else if !isPlausibleHostname(host) {
		return "", "", fmt.Errorf("%q has an invalid host", s)
	}
	// Only the DNS transports this module actually uses.
	switch port {
	case "53", "853", "5353":
		return host, port, nil
	}
	return "", "", fmt.Errorf("%q uses port %s, which is not a DNS port", s, port)
}

// isPlausibleHostname rejects resolver hosts that could never be dialled.
func isPlausibleHostname(h string) bool {
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	for _, r := range h {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-' || r == '.' || r == '_':
		default:
			return false
		}
	}
	return true
}

// Collect gathers the requested record types for a hostname. The name must
// already be in scope: the collector re-checks anyway, because it may be called
// from a plugin that was handed an attacker-controlled name.
func (c *Collector) Collect(ctx context.Context, name string, types []models.RecordType) (models.DNSResult, error) {
	host, err := scope.CanonicalizeDomain(name)
	if err != nil {
		return models.DNSResult{}, fmt.Errorf("dns: %w", err)
	}
	if d := c.scope.CheckHost(host); !d.Allowed {
		return models.DNSResult{}, fmt.Errorf("%w: %s (%s)", scope.ErrTargetDenied, host, d.Reason)
	}
	if len(types) == 0 {
		types = models.AllRecordTypes
	}
	res := models.DNSResult{Name: host, Observed: time.Now().UTC()}

	for _, t := range types {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		default:
		}
		recs, cut, err := c.lookup(ctx, host, t)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", t, err))
			continue
		}
		if cut {
			res.Truncated = true
		}
		res.Records = append(res.Records, recs...)
	}

	// The address list on a result is the set the toolkit is willing to connect
	// to, not merely what the name resolved to. A public name that resolves to
	// 127.0.0.1 or to a cloud metadata address is exactly the shape of a
	// rebinding attack, and a downstream module that trusted IPs would follow
	// it. The raw record is still kept, because "this name points inside the
	// network" is itself a useful observation, but it is marked unconnectable
	// and never lands in IPs.
	seenIP := map[netip.Addr]struct{}{}
	for _, r := range res.Records {
		switch r.Type {
		case models.RecordA, models.RecordAAAA:
			addr, err := netip.ParseAddr(r.Value)
			if err != nil {
				continue
			}
			addr = addr.Unmap()
			if _, dup := seenIP[addr]; dup {
				continue
			}
			seenIP[addr] = struct{}{}
			if d := c.scope.CheckResolvedAddr(res.Name, addr); !d.Allowed {
				res.Unconnectable = append(res.Unconnectable, addr.String())
				res.Errors = append(res.Errors,
					fmt.Sprintf("%s resolves to %s which is not connectable: %s", res.Name, addr, d.Reason))
				continue
			}
			res.IPs = append(res.IPs, addr)
		case models.RecordCNAME:
			res.CNAMEs = append(res.CNAMEs, strings.TrimSuffix(r.Value, "."))
		}
	}
	sort.Slice(res.IPs, func(i, j int) bool { return res.IPs[i].Less(res.IPs[j]) })
	sort.Strings(res.Unconnectable)
	res.Resolved = len(res.IPs) > 0
	res.Dangling = isDanglingCandidate(res)
	if len(res.CNAMEs) > 0 && !res.Resolved {
		// A name that only has a CNAME and no address is the classic dangling
		// pattern. This is a candidate, never a conclusion.
		res.Dangling = true
	}
	return res, nil
}

func isDanglingCandidate(res models.DNSResult) bool {
	if res.Resolved || len(res.CNAMEs) == 0 {
		return false
	}
	return true
}

func (c *Collector) lookup(ctx context.Context, host string, t models.RecordType) ([]models.DNSRecord, bool, error) {
	// Every lookup goes through the cache. A crawl asks the same questions of
	// the same authoritative servers once per module otherwise, which burns the
	// request budget and is impolite for no gain.
	key := string(t) + "|" + host
	if recs, ok := c.cache.get(key); ok {
		out := make([]models.DNSRecord, 0, len(recs))
		for _, r := range recs {
			out = append(out, models.DNSRecord{
				Name: r.name, Type: t, Value: r.value, Source: "cache", Observed: time.Now().UTC(),
			})
		}
		return out, false, nil
	}

	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	now := time.Now().UTC()
	emit := func(value string) models.DNSRecord {
		return models.DNSRecord{Name: host, Type: t, Value: value, Source: "resolver", Observed: now}
	}
	// remember caches the answer in the flat form the cache stores.
	remember := func(recs []models.DNSRecord) {
		flat := make([]dnsRecord, 0, len(recs))
		for _, r := range recs {
			flat = append(flat, dnsRecord{name: r.Name, typeName: string(t), value: r.Value})
		}
		c.cache.put(key, flat)
	}
	// bounded truncates a hostile answer and reports the cut. A zone that
	// returns fifty thousand A records is either broken or hostile, and neither
	// is a reason to allocate for all of them.
	bounded := func(recs []models.DNSRecord) ([]models.DNSRecord, bool, error) {
		cut := false
		if len(recs) > MaxRecordsPerType {
			recs = recs[:MaxRecordsPerType]
			cut = true
		}
		remember(recs)
		return recs, cut, nil
	}
	nilErr := func() ([]models.DNSRecord, bool, error) {
		remember(nil)
		return nil, false, nil
	}
	nx := func(err error) ([]models.DNSRecord, bool, error) {
		if isNotFound(err) {
			return nilErr()
		}
		return nil, false, err
	}

	switch t {
	case models.RecordA, models.RecordAAAA:
		network := "ip4"
		if t == models.RecordAAAA {
			network = "ip6"
		}
		addrs, err := c.resolver.LookupNetIP(ctx, network, host)
		if err != nil {
			return nx(err)
		}
		// Bound before building the record slice as well as after, so the
		// intermediate allocation stays small too. The cut is remembered
		// because slicing here hides the overflow from bounded().
		cut := false
		if len(addrs) > MaxRecordsPerType {
			addrs = addrs[:MaxRecordsPerType]
			cut = true
		}
		out := make([]models.DNSRecord, 0, len(addrs))
		for _, a := range addrs {
			// Record what the name resolves to, including addresses scope
			// would refuse to connect to: the fact that a public name resolves
			// to a private address is itself an observation worth keeping.
			// Collect decides which of these are connectable.
			out = append(out, emit(a.Unmap().String()))
		}
		recs, more, err := bounded(out)
		return recs, cut || more, err

	case models.RecordCNAME:
		cname, err := c.resolver.LookupCNAME(ctx, host)
		if err != nil {
			return nx(err)
		}
		cname = strings.TrimSuffix(strings.ToLower(cname), ".")
		if cname == "" || cname == host {
			return nilErr()
		}
		return bounded([]models.DNSRecord{emit(cname)})

	case models.RecordMX:
		mxs, err := c.resolver.LookupMX(ctx, host)
		if err != nil {
			return nx(err)
		}
		out := make([]models.DNSRecord, 0, len(mxs))
		for _, mx := range mxs {
			r := emit(strings.TrimSuffix(mx.Host, "."))
			r.Priority = uint16(mx.Pref)
			out = append(out, r)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Priority < out[j].Priority })
		return bounded(out)

	case models.RecordNS:
		nss, err := c.resolver.LookupNS(ctx, host)
		if err != nil {
			return nx(err)
		}
		out := make([]models.DNSRecord, 0, len(nss))
		for _, ns := range nss {
			out = append(out, emit(strings.TrimSuffix(ns.Host, ".")))
		}
		return bounded(out)

	case models.RecordTXT:
		txts, err := c.resolver.LookupTXT(ctx, host)
		if err != nil {
			return nx(err)
		}
		out := make([]models.DNSRecord, 0, len(txts))
		for _, txt := range txts {
			// A single TXT record may be a long concatenated string. It is
			// bounded so a hostile zone cannot exhaust memory.
			if len(txt) > 4096 {
				txt = txt[:4096]
			}
			out = append(out, emit(txt))
		}
		return bounded(out)

	case models.RecordCAA:
		// CAA and SOA need a resolver that speaks the pseudo-types directly,
		// which net.Resolver does not expose. Reporting none is honest; inventing
		// a posture from nothing is not.
		return nilErr()

	case models.RecordSOA:
		return nilErr()

	default:
		return nil, false, fmt.Errorf("dns: unsupported record type %q", t)
	}
}

func isNotFound(err error) bool {
	var de *net.DNSError
	if errors.As(err, &de) {
		return de.IsNotFound || de.IsTimeout
	}
	return false
}

// SecurityPosture summarizes the security-relevant records of a zone.
//
// The DMARC and DKIM selectors are zone-wide names rather than apex records,
// so they are looked up explicitly instead of being inferred from the apex
// answer, which would silently report "missing" for a domain that does publish
// them.
func (c *Collector) SecurityPosture(ctx context.Context, zone string) (models.SecurityPosture, error) {
	host, err := scope.CanonicalizeDomain(zone)
	if err != nil {
		return models.SecurityPosture{}, err
	}
	if d := c.scope.CheckHost(host); !d.Allowed {
		return models.SecurityPosture{}, fmt.Errorf("%w: %s", scope.ErrTargetDenied, host)
	}
	res, err := c.Collect(ctx, host, []models.RecordType{
		models.RecordTXT, models.RecordMX, models.RecordNS, models.RecordCAA, models.RecordSOA,
	})
	if err != nil {
		return models.SecurityPosture{}, err
	}
	p := models.SecurityPosture{}
	for _, r := range res.Records {
		switch {
		case r.Type == models.RecordMX:
			p.HasMX = true
		case r.Type == models.RecordTXT:
			upper := strings.ToUpper(r.Value)
			switch {
			case strings.Contains(upper, "V=SPF1"):
				p.HasSPF = true
			}
		case r.Type == models.RecordCAA:
			p.HasCAA = true
		case r.Type == models.RecordSOA:
			if strings.Contains(strings.ToUpper(r.Value), "DNSKEY") {
				p.HasDNSSEC = true
			}
		}
	}
	// _dmarc and a conventional DKIM selector are separate names. They are
	// only queried when they are themselves in scope, which a wildcard
	// exclusion may have removed; the posture then reports them as unknown
	// rather than absent.
	if dmarc, ok := c.lookupIfInScope(ctx, "_dmarc."+host, models.RecordTXT); ok {
		for _, r := range dmarc {
			if strings.Contains(strings.ToUpper(r.Value), "V=DMARC1") {
				p.HasDMARC = true
			}
		}
	}
	// One common selector is enough to establish that DKIM is in use; a full
	// inventory would need a selector scan, which is active work and is left to
	// the operator.
	for _, sel := range []string{"default", "google", "selector1", "selector2", "k1", "mail"} {
		if recs, ok := c.lookupIfInScope(ctx, sel+"._domainkey."+host, models.RecordTXT); ok && len(recs) > 0 {
			p.HasDKIMHint = true
			break
		}
	}
	if !p.HasSPF {
		p.Notes = append(p.Notes, "no v=spf1 record was observed at the apex")
	}
	if !p.HasDMARC {
		p.Notes = append(p.Notes, "no v=DMARC1 record was observed at _dmarc")
	}
	if !p.HasCAA {
		p.Notes = append(p.Notes, "no CAA record was observed, so no CA is constrained for this name")
	}
	return p, nil
}

// lookupIfInScope resolves a name only when scope admits it, so a wildcard
// exclusion of a zone does not turn the posture check into an out-of-scope
// query.
func (c *Collector) lookupIfInScope(ctx context.Context, name string, t models.RecordType) ([]models.DNSRecord, bool) {
	host, err := scope.CanonicalizeDomain(name)
	if err != nil {
		return nil, false
	}
	if d := c.scope.CheckHost(host); !d.Allowed {
		return nil, false
	}
	recs, _, err := c.lookup(ctx, host, t)
	if err != nil {
		return nil, false
	}
	return recs, true
}
