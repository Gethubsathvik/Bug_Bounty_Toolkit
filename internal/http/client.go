// Package httpclient is the only way the toolkit performs HTTP requests.
//
// Every request passes through six independent controls:
//
//  1. Scope. CheckURL runs before the request is built, again inside the
//     transport, and again on every redirect hop.
//  2. DNS rebinding. The transport resolves the name itself, filters every
//     candidate address through the scope engine, and dials only an address it
//     approved. A name that resolves to a public address at check time and to
//     127.0.0.1 a millisecond later never gets connected to.
//  3. Rate and budget. One limiter is shared process-wide.
//  4. Method allowlist. Only GET, HEAD and OPTIONS are permitted by default, so
//     no module can accidentally issue a state-changing request.
//  5. Bounded responses. Bodies are read through a hard byte limit and the
//     overflow is reported rather than allocated.
//  6. Header hygiene. Credentials are stripped from outbound headers and
//     sensitive response headers are never retained.
package httpclient

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/bbtoolkit/bugbounty/internal/ratelimit"
	"github.com/bbtoolkit/bugbounty/internal/redact"
	"github.com/bbtoolkit/bugbounty/internal/scope"
)

// ErrOutOfScope is returned when a target fails the scope engine.
var ErrOutOfScope = errors.New("httpclient: target is out of scope")

// ErrBodyTooLarge is returned when a response exceeds the configured limit and
// truncation was not permitted.
var ErrBodyTooLarge = errors.New("httpclient: response body exceeds the configured limit")

// ErrMethodNotAllowed is returned for a method outside the allowlist.
var ErrMethodNotAllowed = errors.New("httpclient: method not allowed")

// SafeMethods is the default outbound method allowlist. Every member is
// idempotent and none of them changes server state by design.
var SafeMethods = []string{http.MethodGet, http.MethodHead, http.MethodOptions}

// Config configures the client.
type Config struct {
	Timeout             time.Duration
	Retries             int
	UserAgent           string
	MaxResponseBytes    int64
	FollowRedirects     *bool
	MaxRedirects        int
	InsecureSkipVerify  bool
	Proxy               string
	MaxIdleConnsPerHost int
	// ExtraMethods widens the allowlist. It exists for explicitly
	// non-destructive methods an operator needs; body-carrying methods are
	// still rejected unless AllowRequestBody is also set.
	ExtraMethods     []string
	AllowRequestBody bool
	DialTimeout      time.Duration
	TLSTimeout       time.Duration
	// MaxHeaderBytes bounds the response header block, a cheap memory
	// exhaustion vector against the client.
	MaxHeaderBytes int
}

// DefaultConfig returns conservative defaults.
func DefaultConfig() Config {
	follow := true
	return Config{
		Timeout:             10 * time.Second,
		Retries:             1,
		UserAgent:           "bugbounty-toolkit/1.0",
		MaxResponseBytes:    5 << 20,
		FollowRedirects:     &follow,
		MaxRedirects:        10,
		InsecureSkipVerify:  false,
		MaxIdleConnsPerHost: 16,
		DialTimeout:         5 * time.Second,
		TLSTimeout:          5 * time.Second,
		MaxHeaderBytes:      1 << 20,
	}
}

// Redirect is a single hop in a redirect chain.
type Redirect struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Status   int    `json:"status"`
	Location string `json:"location,omitempty"`
	InScope  bool   `json:"in_scope"`
	// Blocked records that the hop was refused by the scope engine. The chain
	// stops there and the response is not followed further.
	Blocked bool   `json:"blocked,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// TLSInfo is non-secret TLS metadata. No key material and no certificate blob
// is retained.
type TLSInfo struct {
	Version     string    `json:"version"`
	CipherSuite string    `json:"cipher_suite,omitempty"`
	Subject     string    `json:"subject,omitempty"`
	Issuer      string    `json:"issuer,omitempty"`
	Serial      string    `json:"serial_number,omitempty"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Expired     bool      `json:"expired"`
	SelfSigned  bool      `json:"self_signed"`
	SANs        []string  `json:"sans,omitempty"`
	WildcardSAN bool      `json:"wildcard_san"`
	ALPN        string    `json:"alpn,omitempty"`
	Fingerprint string    `json:"fingerprint_sha256,omitempty"`
}

// Response is the bounded, normalized result of one request.
type Response struct {
	URL           string              `json:"url"`
	FinalURL      string              `json:"final_url,omitempty"`
	Method        string              `json:"method,omitempty"`
	StatusCode    int                 `json:"status_code"`
	Status        string              `json:"status,omitempty"`
	Header        map[string][]string `json:"header,omitempty"`
	Body          []byte              `json:"-"`
	BodyTruncated bool                `json:"body_truncated,omitempty"`
	ContentType   string              `json:"content_type,omitempty"`
	ContentLength int64               `json:"content_length"`
	Title         string              `json:"title,omitempty"`
	BodyHash      string              `json:"body_hash,omitempty"`
	HeaderHash    string              `json:"header_hash,omitempty"`
	Redirects     []Redirect          `json:"redirects,omitempty"`
	Elapsed       time.Duration       `json:"elapsed,omitempty"`
	TLS           *TLSInfo            `json:"tls,omitempty"`
	Protocol      string              `json:"protocol,omitempty"`
	IPs           []string            `json:"ips,omitempty"`
	Timestamp     time.Time           `json:"timestamp"`
	ScopeRule     string              `json:"scope_rule,omitempty"`
	// Error carries a non-fatal note, for example that a redirect chain was
	// cut short by the scope engine.
	Note string `json:"note,omitempty"`
}

// Resolver is the DNS interface the transport depends on. *net.Resolver
// satisfies it; tests substitute their own implementation to model a hostile or
// rebinding resolver.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
}

// Client performs scope-checked, rate-limited HTTP requests.
type Client struct {
	cfg      Config
	scope    *scope.Engine
	limiter  *ratelimit.Limiter
	hc       *http.Client
	resolver Resolver
	allowed  map[string]struct{}
	follow   bool
	// dialled remembers which address was actually used per host, so a
	// response can report the IP that served it.
	dialled sync.Map
}

// New builds a client. The scope engine is mandatory: a nil engine is a
// programming error and is reported, not silently ignored.
func New(cfg Config, sc *scope.Engine, lim *ratelimit.Limiter, resolver Resolver) (*Client, error) {
	if sc == nil {
		return nil, errors.New("httpclient: a scope engine is required")
	}
	if lim == nil {
		lim = ratelimit.New(0, 1, 0)
	}
	applyDefaults(&cfg)

	allowed := map[string]struct{}{}
	for _, m := range append(append([]string{}, SafeMethods...), cfg.ExtraMethods...) {
		if m = strings.ToUpper(strings.TrimSpace(m)); m != "" {
			allowed[m] = struct{}{}
		}
	}

	c := &Client{
		cfg:      cfg,
		scope:    sc,
		limiter:  lim,
		resolver: resolver,
		allowed:  allowed,
		follow:   cfg.FollowRedirects == nil || *cfg.FollowRedirects,
	}

	transport := &http.Transport{
		DialContext:           c.dialContext,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   cfg.MaxIdleConnsPerHost,
		MaxConnsPerHost:       cfg.MaxIdleConnsPerHost * 2,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   cfg.TLSTimeout,
		ResponseHeaderTimeout: cfg.Timeout,
		ExpectContinueTimeout: time.Second,
		ForceAttemptHTTP2:     true,
		// TLS is validated unless the operator explicitly disabled it on the
		// command line. A run with verification off is recorded in metadata so
		// its results are never mistaken for a clean TLS posture.
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // explicit operator opt-in
			MinVersion:         tls.VersionTLS12,
		},
		MaxResponseHeaderBytes: int64(cfg.MaxHeaderBytes),
	}
	if cfg.Proxy != "" {
		pu, err := url.Parse(cfg.Proxy)
		if err != nil {
			return nil, fmt.Errorf("httpclient: invalid proxy %q: %w", cfg.Proxy, err)
		}
		// A plaintext proxy would terminate TLS and could rewrite the Host
		// header, which would void the address pinning below. Only TLS and
		// SOCKS proxies are accepted.
		switch strings.ToLower(pu.Scheme) {
		case "https", "socks5", "socks5h":
		default:
			return nil, errors.New("httpclient: only https, socks5 or socks5h proxies are supported so that address pinning is preserved")
		}
		transport.Proxy = http.ProxyURL(pu)
	}

	c.hc = &http.Client{
		Transport:     transport,
		Timeout:       cfg.Timeout,
		CheckRedirect: c.checkRedirect,
	}
	return c, nil
}

func applyDefaults(cfg *Config) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.MaxResponseBytes <= 0 {
		cfg.MaxResponseBytes = 5 << 20
	}
	if cfg.MaxRedirects <= 0 {
		cfg.MaxRedirects = 10
	}
	if cfg.MaxHeaderBytes <= 0 {
		cfg.MaxHeaderBytes = 1 << 20
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 5 * time.Second
	}
	if cfg.TLSTimeout <= 0 {
		cfg.TLSTimeout = 5 * time.Second
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "bugbounty-toolkit/1.0"
	}
	if cfg.Retries < 0 {
		cfg.Retries = 0
	}
}

// Scope exposes the engine so callers can double-check before navigating.
func (c *Client) Scope() *scope.Engine { return c.scope }

// Config returns the effective configuration.
func (c *Client) Config() Config { return c.cfg }

// Limiter exposes the shared rate limiter so a module holding a long-lived slot
// (the crawler) can charge individual requests against the same budget.
func (c *Client) Limiter() *ratelimit.Limiter { return c.limiter }

// Resolver returns the resolver in use, which the DNS module shares.
func (c *Client) Resolver() Resolver { return c.resolver }

// hopKey is the context key under which a per-request redirect recorder lives.
type hopKey struct{}

// hops collects the redirect chain of a single request.
type hops struct {
	mu   sync.Mutex
	list []Redirect
	note string
}

func (h *hops) add(r Redirect) {
	h.mu.Lock()
	h.list = append(h.list, r)
	h.mu.Unlock()
}

func (h *hops) setNote(s string) {
	h.mu.Lock()
	if h.note == "" {
		h.note = s
	}
	h.mu.Unlock()
}

func (h *hops) snapshot() ([]Redirect, string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]Redirect, len(h.list))
	copy(out, h.list)
	return out, h.note
}

func hopsFrom(ctx context.Context) *hops {
	if v, ok := ctx.Value(hopKey{}).(*hops); ok {
		return v
	}
	return &hops{}
}

// checkRedirect enforces the scope boundary on every hop. Returning an error
// stops the chain; the caller still receives the last in-scope response and the
// full record of where the chain was cut.
func (c *Client) checkRedirect(req *http.Request, via []*http.Request) error {
	h := hopsFrom(req.Context())
	if len(via) >= c.cfg.MaxRedirects {
		err := fmt.Errorf("httpclient: stopped after %d redirects", c.cfg.MaxRedirects)
		h.add(Redirect{From: prevURL(via), To: req.URL.String(), Location: req.URL.String(), Blocked: true, Reason: err.Error()})
		h.setNote(err.Error())
		return err
	}
	d := c.scope.CheckURL(req.URL)
	if !d.Allowed {
		reason := fmt.Sprintf("redirect destination out of scope: %s", d.Reason)
		h.add(Redirect{From: prevURL(via), To: req.URL.String(), Location: req.URL.String(), Blocked: true, Reason: reason})
		h.setNote(reason)
		return fmt.Errorf("%w: redirect to %s denied: %s", ErrOutOfScope, redact.URL(req.URL.String()), d.Reason)
	}
	// Never carry credentials to a different host. The Go client already drops
	// Authorization on a host change; the rest is explicit here.
	if len(via) > 0 && !sameHost(via[len(via)-1].URL, req.URL) {
		for _, h := range []string{"Cookie", "Authorization", "Proxy-Authorization", "X-Api-Key", "X-Auth-Token"} {
			req.Header.Del(h)
		}
	}
	if v := req.Header.Get("User-Agent"); v == "" {
		req.Header.Set("User-Agent", c.cfg.UserAgent)
	}
	return nil
}

func prevURL(via []*http.Request) string {
	if len(via) == 0 {
		return ""
	}
	return via[len(via)-1].URL.String()
}

func sameHost(a, b *url.URL) bool {
	return strings.EqualFold(a.Hostname(), b.Hostname())
}

// dialContext is the SSRF and rebinding chokepoint.
func (c *Client) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("httpclient: bad dial address %q: %w", addr, err)
	}
	// Defence in depth: the request URL was already checked, but the dialer is
	// the last place a name becomes a connection, so it checks again.
	if d := c.scope.CheckHost(host); !d.Allowed {
		return nil, fmt.Errorf("%w: %s (%s)", ErrOutOfScope, host, d.Reason)
	}
	if err := c.scope.RequireActive(); err != nil {
		return nil, err
	}

	dialer := &net.Dialer{Timeout: c.cfg.DialTimeout, KeepAlive: 30 * time.Second}

	if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		if d := c.scope.CheckResolvedAddr(host, ip); !d.Allowed {
			return nil, fmt.Errorf("%w: %s (%s)", ErrOutOfScope, ip, d.Reason)
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}

	ips, err := c.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	permitted, denied := c.scope.ResolveAndCheck(host, ips)
	if len(permitted) == 0 {
		if len(denied) > 0 {
			return nil, fmt.Errorf("%w: %s resolved only to addresses scope rejects (%s)", ErrOutOfScope, host, denied[0].Reason)
		}
		return nil, fmt.Errorf("httpclient: %s did not resolve to any address", host)
	}

	var errs []error
	for _, ip := range permitted {
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			// Record the address actually used so the response can report the
			// IP that served it.
			c.dialled.Store(host, ip)
			return conn, nil
		}
		errs = append(errs, err)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, fmt.Errorf("httpclient: connecting to %s: %w", host, errors.Join(errs...))
}

func (c *Client) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	r := c.resolver
	if r == nil {
		r = net.DefaultResolver
	}
	ips, err := r.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("httpclient: resolving %s: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("httpclient: %s has no address records", host)
	}
	return ips, nil
}

// Request describes one outbound request.
type Request struct {
	URL     string
	Method  string
	Headers map[string]string
	// Body is only usable when Config.AllowRequestBody is set, which requires
	// an explicit operator decision.
	Body io.Reader
	// TruncateBody returns a truncated body instead of failing when the
	// response exceeds the limit. The crawler wants truncation; the HTTP probe
	// module wants an explicit error.
	TruncateBody bool
	// NoFollowRedirects disables redirect following for this request.
	NoFollowRedirects bool
}

// Do performs one request, applying every control. It never returns a body
// larger than Config.MaxResponseBytes.
func (c *Client) Do(ctx context.Context, req Request) (*Response, error) {
	if err := c.scope.RequireActive(); err != nil {
		return nil, err
	}
	u, err := url.Parse(strings.TrimSpace(req.URL))
	if err != nil {
		return nil, fmt.Errorf("httpclient: parsing %q: %w", req.URL, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("httpclient: %q is not an absolute URL", req.URL)
	}
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodGet
	}
	if _, ok := c.allowed[method]; !ok {
		return nil, fmt.Errorf("%w: %s (allowed: %s)", ErrMethodNotAllowed, method,
			strings.Join(sortedMethods(c.allowed), ", "))
	}
	if req.Body != nil && !c.cfg.AllowRequestBody {
		return nil, fmt.Errorf("%w: %s with a request body is not permitted", ErrMethodNotAllowed, method)
	}
	if d := c.scope.CheckURL(u); !d.Allowed {
		return nil, fmt.Errorf("%w: %s (%s)", ErrOutOfScope, redact.URL(u.String()), d.Reason)
	}

	attempts := c.cfg.Retries + 1
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff(attempt - 1)):
			}
		}
		var resp *Response
		err := c.limiter.Do(ctx, func(ctx context.Context) error {
			var e error
			resp, e = c.attempt(ctx, u, method, req)
			return e
		})
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if !retryable(err) {
			break
		}
	}
	return nil, lastErr
}

func backoff(i int) time.Duration {
	d := time.Duration(250*(i+1)) * time.Millisecond
	if d > 2*time.Second {
		d = 2 * time.Second
	}
	return d
}

// retryable classifies transient failures. A scope denial, a method rejection
// and a budget exhaustion are never retried.
func retryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrOutOfScope) || errors.Is(err, ErrMethodNotAllowed) ||
		errors.Is(err, ratelimit.ErrBudgetExhausted) || errors.Is(err, ratelimit.ErrClosed) ||
		errors.Is(err, context.Canceled) {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	msg := err.Error()
	for _, frag := range []string{"connection reset", "broken pipe", "unexpected EOF",
		"server closed idle connection", "i/o timeout", "TLS handshake timeout"} {
		if strings.Contains(msg, frag) {
			return true
		}
	}
	return false
}

func sortedMethods(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (c *Client) attempt(ctx context.Context, u *url.URL, method string, req Request) (*Response, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()

	rec := &hops{}
	ctx = context.WithValue(ctx, hopKey{}, rec)

	var bodyReader io.Reader
	if req.Body != nil {
		bodyReader = io.LimitReader(req.Body, 64<<10)
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, u.String(), bodyReader)
	if err != nil {
		return nil, fmt.Errorf("httpclient: building request: %w", err)
	}
	for k, v := range req.Headers {
		if redact.IsSensitiveKey(k) {
			// Credentials are never sourced from remote content, and a header
			// discovered on a crawled page must not be replayed.
			continue
		}
		httpReq.Header.Set(k, redact.Sanitize(v))
	}
	httpReq.Header.Set("User-Agent", c.cfg.UserAgent)
	// Identity encoding keeps Content-Length honest and avoids the client
	// silently decompressing an unbounded payload.
	httpReq.Header.Set("Accept-Encoding", "identity")

	client := *c.hc
	if req.NoFollowRedirects || !c.follow {
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}

	start := time.Now()
	resp, err := client.Do(httpReq)
	if err != nil {
		// A redirect the scope engine refused still leaves a usable response in
		// some cases; record the chain and report the denial.
		if rec2, _ := rec.snapshot(); len(rec2) > 0 && errors.Is(err, ErrOutOfScope) {
			return nil, fmt.Errorf("%s (chain: %s)", sanitizeErr(err).Error(), renderChain(rec2))
		}
		return nil, sanitizeErr(err)
	}
	defer func() {
		// Drain a bounded amount so the connection can be reused, then close.
		_, _ = io.CopyN(io.Discard, resp.Body, 8192)
		_ = resp.Body.Close()
	}()

	body, truncated, readErr := readBounded(resp.Body, c.cfg.MaxResponseBytes)
	if readErr != nil && !errors.Is(readErr, ErrBodyTooLarge) {
		return nil, readErr
	}
	if errors.Is(readErr, ErrBodyTooLarge) && !req.TruncateBody {
		return nil, fmt.Errorf("%w: %s returned more than %d bytes", ErrBodyTooLarge, redact.URL(u.String()), c.cfg.MaxResponseBytes)
	}

	chain, note := rec.snapshot()
	// The initial hop (the requested URL) is always recorded so the chain is
	// self-describing even when nothing redirected.
	if resp.Request != nil && resp.Request.URL.String() != u.String() && len(chain) == 0 {
		chain = append(chain, Redirect{From: u.String(), To: resp.Request.URL.String(), InScope: true})
	}

	out := &Response{
		URL:           u.String(),
		FinalURL:      resp.Request.URL.String(),
		Method:        method,
		StatusCode:    resp.StatusCode,
		Status:        resp.Status,
		Header:        redact.Headers(resp.Header),
		Body:          body,
		BodyTruncated: truncated,
		ContentType:   resp.Header.Get("Content-Type"),
		ContentLength: resp.ContentLength,
		Elapsed:       time.Since(start),
		Protocol:      resp.Proto,
		Timestamp:     time.Now().UTC(),
		Redirects:     chain,
		Note:          note,
	}
	out.BodyHash = hashBytes(body)
	out.HeaderHash = hashHeader(resp.Header)
	out.Title = ExtractTitle(body, resp.Header.Get("Content-Type"))
	if resp.TLS != nil {
		out.TLS = parseTLS(resp.TLS)
	}
	if v, ok := c.dialled.Load(u.Hostname()); ok {
		if ip, ok := v.(netip.Addr); ok {
			out.IPs = []string{ip.String()}
		}
	}
	if d := c.scope.CheckURL(resp.Request.URL); d.Allowed {
		out.ScopeRule = d.Rule
	}
	return out, nil
}

func renderChain(chain []Redirect) string {
	parts := make([]string, 0, len(chain))
	for _, r := range chain {
		state := "followed"
		if r.Blocked {
			state = "blocked: " + r.Reason
		}
		parts = append(parts, fmt.Sprintf("%s -> %s (%s)", redact.URL(r.From), redact.URL(r.To), state))
	}
	return strings.Join(parts, " -> ")
}

// readBounded reads at most limit bytes and reports whether more were
// available, without ever allocating the overflow.
func readBounded(r io.Reader, limit int64) ([]byte, bool, error) {
	if limit <= 0 {
		limit = 5 << 20
	}
	buf, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return buf, false, err
	}
	if int64(len(buf)) > limit {
		return buf[:limit], true, ErrBodyTooLarge
	}
	return buf, false, nil
}

func hashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// hashHeader hashes the non-sensitive response headers so two services can be
// compared without retaining header values that may be sensitive.
func hashHeader(h http.Header) string {
	keys := make([]string, 0, len(h))
	for k := range h {
		if redact.IsSensitiveKey(k) {
			continue
		}
		keys = append(keys, strings.ToLower(k))
	}
	sort.Strings(keys)
	h2 := sha256.New()
	for _, k := range keys {
		h2.Write([]byte(k))
		h2.Write([]byte{0})
		for _, v := range h[k] {
			h2.Write([]byte(redact.Sanitize(v)))
			h2.Write([]byte{0})
		}
	}
	return hex.EncodeToString(h2.Sum(nil))
}

func parseTLS(cs *tls.ConnectionState) *TLSInfo {
	out := &TLSInfo{Version: versionName(cs.Version), CipherSuite: tls.CipherSuiteName(cs.CipherSuite)}
	if len(cs.PeerCertificates) > 0 {
		leaf := cs.PeerCertificates[0]
		out.Subject = leaf.Subject.String()
		out.Issuer = leaf.Issuer.String()
		out.Serial = leaf.SerialNumber.String()
		out.NotBefore = leaf.NotBefore
		out.NotAfter = leaf.NotAfter
		out.Expired = time.Now().After(leaf.NotAfter)
		out.SelfSigned = leaf.Subject.String() == leaf.Issuer.String()
		sum := sha256.Sum256(leaf.Raw)
		out.Fingerprint = hex.EncodeToString(sum[:])
		for _, name := range leaf.DNSNames {
			out.SANs = append(out.SANs, name)
			if strings.HasPrefix(name, "*.") {
				out.WildcardSAN = true
			}
		}
	}
	out.ALPN = cs.NegotiatedProtocol
	return out
}

func versionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown(0x%04x)", v)
	}
}

// sanitizeErr strips raw text out of an error message before it is logged.
func sanitizeErr(err error) error {
	if err == nil {
		return nil
	}
	return errors.New(redact.Sanitize(redact.Text(err.Error())))
}

// PublicSuffix is a small helper used by the passive modules so a public
// suffix is never mistaken for a registrable domain. It reports false when the
// host has no known public suffix, which is the normal case for internal names.
func PublicSuffix(host string) (string, bool) { return publicsuffix.PublicSuffix(host) }
