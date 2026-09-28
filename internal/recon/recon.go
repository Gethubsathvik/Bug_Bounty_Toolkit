// Package recon discovers in-scope assets from sources that do not touch the
// target: certificate transparency logs, passive DNS, and provider APIs.
//
// Everything here is attacker-influenced data. A certificate log will happily
// return a name that was never registered, a provider will return a record it
// inferred from a wildcard, and a misconfigured zone can put arbitrary bytes
// in a TXT record. So every name that enters this package is treated as
// hostile: it is length-bounded, canonicalized, checked against the scope
// engine, and recorded with the confidence of the source that produced it
// rather than as a fact.
package recon

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bbtoolkit/bugbounty/internal/scope"
	"github.com/bbtoolkit/bugbounty/pkg/models"
)

// Defaults that bound a passive sweep. Passive sources are cheap for us and
// expensive for them, and an unbounded enumeration is how a tool ends up
// pulling a million rows out of a free API key.
const (
	DefaultMaxNames       = 2000
	DefaultMaxPerSource   = 1000
	DefaultSourceTimeout  = 2 * time.Minute
	DefaultTotalTimeout   = 10 * time.Minute
	MaxNameLength         = 253
	MaxNamesPerSeedSource = 5000
	DefaultConcurrency    = 4
)

// ErrNoScope is returned when a collector is built without a scope engine.
// A recon tool with no scope is an indiscriminate scanner, so this is fatal
// rather than a warning.
var ErrNoScope = errors.New("recon: a scope engine is required")

// ErrNoSources is returned when a collector is built with nothing to query.
var ErrNoSources = errors.New("recon: no passive sources are configured")

// Asset is one discovered name plus the provenance that produced it.
type Asset struct {
	// Name is the canonicalized host name, lower case with a trailing dot
	// removed. It has already passed the scope engine.
	Name string
	// Kind is what the source believes the name resolves to.
	Kind string
	// Source names the source that produced this record.
	Source string
	// Confidence reflects how much the source's method proves. A name read
	// from a certificate's subject alternative names is weaker evidence of
	// existing than one confirmed by a live record, and a reviewer has to be
	// able to see that difference.
	Confidence models.Confidence
	// FirstSeen is when this source first reported the name.
	FirstSeen time.Time
	// Records carries any structured data the source returned, already
	// redacted.
	Records map[string]string
}

// Name kinds reported by sources.
const (
	KindSubdomain = "subdomain"
	KindApex      = "apex"
	KindEmail     = "email_address"
	KindIP        = "ip_address"
	KindHostname  = "hostname"
)

// Source enumerates candidate names for a seed domain. Implementations must
// respect ctx and must never contact anything inside the engagement scope;
// passive means passive.
type Source interface {
	// Name identifies the source in findings and reports.
	Name() string
	// Enumerate returns candidate names for a seed. It may return partial
	// results alongside an error.
	Enumerate(ctx context.Context, seed string) ([]Record, error)
	// Available reports whether the source is usable right now. A source
	// needing a missing credential reports false rather than failing.
	Available() error
}

// Record is one row from a passive source, before scope filtering.
type Record struct {
	// Name is the raw host, domain or address the source reported.
	Name string
	// Kind is what the source thinks it found.
	Kind string
	// Confidence is the source's own confidence, if it expresses one.
	Confidence models.Confidence
	// Data carries structured detail, which is redacted before use.
	Data map[string]string
	// Observed is when the source says it last saw the record.
	Observed time.Time
}

// Options configures a Collector.
type Options struct {
	// MaxNames bounds the total number of assets returned.
	MaxNames int
	// MaxPerSource bounds what one source may contribute, so a single chatty
	// source cannot crowd out the others.
	MaxPerSource int
	// SourceTimeout bounds one source's whole enumeration.
	SourceTimeout time.Duration
	// TotalTimeout bounds the whole run.
	TotalTimeout time.Duration
	// Concurrency bounds how many sources run at once.
	Concurrency int
	// Now is the injected clock, so output is deterministic under test.
	Now time.Time
}

func (o Options) withDefaults() Options {
	if o.MaxNames <= 0 {
		o.MaxNames = DefaultMaxNames
	}
	if o.MaxPerSource <= 0 {
		o.MaxPerSource = DefaultMaxPerSource
	}
	if o.SourceTimeout <= 0 {
		o.SourceTimeout = DefaultSourceTimeout
	}
	if o.TotalTimeout <= 0 {
		o.TotalTimeout = DefaultTotalTimeout
	}
	if o.Concurrency <= 0 {
		o.Concurrency = DefaultConcurrency
	}
	return o
}

// Collector runs passive sources against a seed domain.
type Collector struct {
	scope   *scope.Engine
	sources []Source
	opts    Options
}

// NewCollector builds a collector. The scope engine is mandatory.
func NewCollector(sc *scope.Engine, sources []Source, opts Options) (*Collector, error) {
	if sc == nil {
		return nil, ErrNoScope
	}
	usable := make([]Source, 0, len(sources))
	for _, s := range sources {
		if err := sourceAvailable(s); err != nil {
			// An unavailable source is skipped, not fatal. A missing
			// credential for one provider should not stop the sources that do
			// work, and the caller learns about it through Result.Skipped.
			continue
		}
		usable = append(usable, s)
	}
	if len(usable) == 0 {
		return nil, ErrNoSources
	}
	return &Collector{scope: sc, sources: usable, opts: opts.withDefaults()}, nil
}

// SourceNames lists the configured sources in sorted order.
func (c *Collector) SourceNames() []string {
	out := make([]string, 0, len(c.sources))
	for _, s := range c.sources {
		out = append(out, s.Name())
	}
	sort.Strings(out)
	return out
}

// Result is the outcome of one collection run.
type Result struct {
	// Seed is the domain that was queried.
	Seed string
	// Assets are in-scope, deduplicated names, sorted for stable output.
	Assets []Asset
	// Rejected counts rows discarded because they failed canonicalization or
	// fell outside scope. A high count against a small input usually means
	// the source returned junk, which is worth surfacing.
	Rejected int
	// Skipped names sources that were unavailable, with the reason.
	Skipped map[string]string
	// Errs holds per-source failures. Collection continues past them, because
	// one provider being down should not discard another provider's results.
	Errs []error
	// Elapsed is the wall time the run took.
	Elapsed time.Duration
	// Truncated is true when MaxNames cut the results short.
	Truncated bool
}

// sourceAvailable asks a source whether it is usable, treating a panic as
// "not usable".
//
// Source implementations are supplied by plugins and configuration, and an
// interface holding a nil pointer is not itself nil. Calling straight through
// would take the whole run down on a source that was never really configured,
// which is a poor way for a collection to fail.
func sourceAvailable(s Source) (err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("recon: source availability check panicked: %v", rec)
		}
	}()
	if s == nil {
		return errors.New("recon: nil source")
	}
	return s.Available()
}

// runSource enumerates one source, converting a panic into an error so a
// misbehaving plugin cannot destroy the results of the others.
func runSource(ctx context.Context, s Source, seed string, max int) (records []Record, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("source %s panicked: %v", s.Name(), rec)
			records = nil
		}
	}()
	records, err = s.Enumerate(ctx, seed)
	if max > 0 && len(records) > max {
		records = records[:max]
	}
	return records, err
}

// Collect enumerates every configured source for a seed and returns the
// in-scope names.
//
// Sources run concurrently and independently: a timeout or error on one does
// not cancel the others, and a cancelled context stops all of them.
func (c *Collector) Collect(ctx context.Context, seed string) (*Result, error) {
	seed, err := normalizeSeed(seed)
	if err != nil {
		return nil, err
	}

	now := c.opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	start := time.Now()

	runCtx, cancel := context.WithTimeout(ctx, c.opts.TotalTimeout)
	defer cancel()

	res := &Result{Seed: seed, Skipped: map[string]string{}}

	type sourceOutcome struct {
		name    string
		records []Record
		err     error
	}
	outcomes := make(chan sourceOutcome, len(c.sources))

	var wg sync.WaitGroup
	sem := make(chan struct{}, c.opts.Concurrency)
	for _, src := range c.sources {
		wg.Add(1)
		go func(s Source) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-runCtx.Done():
				outcomes <- sourceOutcome{name: s.Name(), err: runCtx.Err()}
				return
			}

			sctx, scancel := context.WithTimeout(runCtx, c.opts.SourceTimeout)
			defer scancel()
			recs, err := runSource(sctx, s, seed, c.opts.MaxPerSource)
			outcomes <- sourceOutcome{name: s.Name(), records: recs, err: err}
		}(src)
	}
	wg.Wait()
	close(outcomes)

	// A name seen by several sources is a stronger observation than one seen
	// once, so sources are merged rather than concatenated.
	merged := map[string]*Asset{}
	for out := range outcomes {
		if out.err != nil && !errors.Is(out.err, context.Canceled) {
			res.Errs = append(res.Errs, fmt.Errorf("source %s: %w", out.name, out.err))
		}
		for _, rec := range out.records {
			asset, ok := c.accept(rec, out.name, now)
			if !ok {
				res.Rejected++
				continue
			}
			existing, dup := merged[asset.Name]
			if !dup {
				cp := asset
				merged[asset.Name] = &cp
				continue
			}
			mergeAsset(existing, asset)
		}
	}

	assets := make([]Asset, 0, len(merged))
	for _, a := range merged {
		assets = append(assets, *a)
	}
	// Highest confidence first, then name, so the strongest lead is at the top
	// and the output is stable across runs.
	sort.SliceStable(assets, func(i, j int) bool {
		if assets[i].Confidence.ConfidenceRank() != assets[j].Confidence.ConfidenceRank() {
			return assets[i].Confidence.ConfidenceRank() > assets[j].Confidence.ConfidenceRank()
		}
		if assets[i].Source != assets[j].Source {
			return assets[i].Source < assets[j].Source
		}
		return assets[i].Name < assets[j].Name
	})
	if len(assets) > c.opts.MaxNames {
		assets = assets[:c.opts.MaxNames]
		res.Truncated = true
	}
	res.Assets = assets
	res.Elapsed = time.Since(start)
	return res, nil
}

// accept decides whether one raw record becomes an asset. This is the only
// place untrusted source data enters the result set.
func (c *Collector) accept(rec Record, sourceName string, now time.Time) (Asset, bool) {
	name, kind, ok := classify(rec.Name, rec.Kind)
	if !ok {
		return Asset{}, false
	}
	// Scope is checked on the canonical form, so a name that only looked
	// in scope through some exotic encoding is rejected here.
	if !c.scope.HostInScope(name) && kind != KindEmail {
		return Asset{}, false
	}

	conf := rec.Confidence
	if !conf.Valid() {
		conf = defaultConfidence(kind)
	}
	observed := rec.Observed
	if observed.IsZero() {
		observed = now
	}
	return Asset{
		Name:       name,
		Kind:       kind,
		Source:     sourceName,
		Confidence: conf,
		FirstSeen:  observed,
		Records:    rec.Data,
	}, true
}

// mergeAsset folds a second sighting of the same name into the first.
//
// Confidence rises only to the maximum either source claimed. A name that ten
// sources all derive from the same wildcard certificate is still one weak
// observation, and treating repetition as proof is exactly the mistake that
// produces phantom subdomains in a report.
func mergeAsset(dst *Asset, src Asset) {
	if src.Confidence.ConfidenceRank() > dst.Confidence.ConfidenceRank() {
		dst.Confidence = src.Confidence
	}
	if src.FirstSeen.Before(dst.FirstSeen) {
		dst.FirstSeen = src.FirstSeen
	}
	if src.Source != dst.Source {
		dst.Source = dst.Source + "," + src.Source
	}
	if len(dst.Records) == 0 {
		dst.Records = src.Records
	}
}

// defaultConfidence is what a source gets when it expresses none of its own.
// Certificate logs sit at medium rather than high because a SAN proves a name
// was requested, not that the name currently resolves.
func defaultConfidence(kind string) models.Confidence {
	switch kind {
	case KindApex, KindSubdomain:
		return models.ConfidenceMedium
	default:
		return models.ConfidenceLow
	}
}

// classify canonicalizes one raw name and rejects anything unusable.
//
// Everything a source returns is treated as hostile input: it may be an IP
// literal, a URL, a wildcard, an email address, a fifty-kilobyte string, or
// something containing control characters.
func classify(raw, kind string) (name, resolvedKind string, ok bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > MaxNameLength {
		return "", "", false
	}
	// Control characters have no place in a hostname and are a reliable sign
	// of a malformed or deliberately hostile record.
	if strings.ContainsAny(raw, "\x00\n\r\t ") {
		return "", "", false
	}
	raw = strings.ToLower(strings.TrimSuffix(raw, "."))
	if raw == "" {
		return "", "", false
	}

	// An email address is a legitimate passive find in its own right, and
	// reporting it is more useful than discarding it.
	if at := strings.Index(raw, "@"); at > 0 {
		local, domain := raw[:at], raw[at+1:]
		if domain == "" || len(local) > 64 {
			return "", "", false
		}
		return domain, KindEmail, true
	}

	// Sources that return URLs rather than hosts.
	if strings.Contains(raw, "://") {
		return "", "", false
	}
	// A leading wildcard is a certificate pattern, not a resolvable name.
	raw = strings.TrimPrefix(raw, "*.")
	if raw == "" {
		return "", "", false
	}

	if isIPv4Literal(raw) {
		return raw, KindIP, true
	}

	// A bare IPv6 literal in a record is only trustworthy in its bracketed
	// form; the bare form is ambiguous with a hostname.
	if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		return raw[1 : len(raw)-1], KindIP, true
	}

	if !plausibleHostname(raw) {
		return "", "", false
	}
	if kind == KindApex || kind == KindIP {
		resolvedKind = kind
	} else {
		resolvedKind = KindSubdomain
	}
	return raw, resolvedKind, true
}

// normalizeSeed validates the domain the whole run is centred on.
func normalizeSeed(seed string) (string, error) {
	seed = strings.TrimSpace(strings.ToLower(seed))
	seed = strings.TrimSuffix(seed, ".")
	if seed == "" {
		return "", errors.New("recon: no seed domain given")
	}
	if isIPv4Literal(seed) {
		return "", errors.New("recon: passive enumeration needs a domain, not an address")
	}
	if !plausibleHostname(seed) {
		return "", fmt.Errorf("recon: %q is not a usable seed domain", seed)
	}
	return seed, nil
}

func plausibleHostname(h string) bool {
	if h == "" || len(h) > MaxNameLength {
		return false
	}
	// A leading or trailing dot, or a double dot, is a malformed name.
	if strings.HasPrefix(h, ".") || strings.HasSuffix(h, ".") || strings.Contains(h, "..") {
		return false
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return false
		}
		if strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			switch {
			case c >= 'a' && c <= 'z':
			case c >= '0' && c <= '9':
			case c == '-' || c == '_':
			default:
				return false
			}
		}
	}
	// The public suffix has to be alphabetic, which rejects an IP address
	// that reached here and a name with a numeric TLD.
	tld := labels[len(labels)-1]
	if tld == "" {
		return false
	}
	for i := 0; i < len(tld); i++ {
		if tld[i] < 'a' || tld[i] > 'z' {
			return false
		}
	}
	return true
}

func isIPv4Literal(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		for i := 0; i < len(p); i++ {
			if p[i] < '0' || p[i] > '9' {
				return false
			}
		}
	}
	return true
}

// ToObservations converts assets into the normalized observations the storage
// layer and the finding engine consume.
func ToObservations(seed string, assets []Asset) []models.Observation {
	out := make([]models.Observation, 0, len(assets))
	for _, a := range assets {
		o := models.Observation{
			Type:       "subdomain",
			Asset:      a.Name,
			Source:     a.Source,
			Data:       a.Records,
			Timestamp:  a.FirstSeen,
			Confidence: a.Confidence,
		}
		if a.Kind != "" {
			if o.Data == nil {
				o.Data = map[string]string{}
			}
			o.Data["kind"] = a.Kind
		}
		out = append(out, o)
	}
	return out
}
