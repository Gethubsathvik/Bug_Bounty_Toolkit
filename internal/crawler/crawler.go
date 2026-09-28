// Package crawler is a bounded, scope-enforced crawler.
//
// Its invariants, each of which has a test:
//
//   - A URL is scope-checked before it is requested, on every redirect, and
//     before it is enqueued. A link is never followed because it was found on
//     a page; it is followed because scope admits it.
//   - Every budget (depth, pages, response bytes, parameters, endpoints) is
//     checked before work is admitted, so a hostile site cannot make the
//     crawler run unbounded.
//   - URLs are normalized before deduplication, so /a//b, /a/./b and /a%2Fb
//     cannot be used to visit the same page a thousand times.
//   - Only GET and HEAD are issued. No form is ever submitted.
//   - robots.txt is honoured when policy says so, and the decision is made
//     per path.
package crawler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bbtoolkit/bugbounty/internal/http"
	"github.com/bbtoolkit/bugbounty/internal/robots"
	"github.com/bbtoolkit/bugbounty/internal/scope"
	"github.com/bbtoolkit/bugbounty/pkg/models"
)

// Config bounds a crawl.
type Config struct {
	MaxDepth        int
	MaxPages        int
	MaxConcurrency  int
	MaxResponseSize int64
	MaxParameters   int
	MaxEndpoints    int
	RateLimit       float64
	Timeout         time.Duration
	// ParseJS enables endpoint extraction from JavaScript bodies.
	ParseJS bool
	// ParseForms enables form field extraction. Forms are recorded, never
	// submitted.
	ParseForms bool
	// ParseParameters enables query and path parameter collection.
	ParseParameters bool
	FollowRedirects bool
	// KnownFiles are explicitly configured harmless metadata paths to probe.
	KnownFiles      []string
	CheckSitemap    bool
	CheckRobots     bool
	BreadthFirst    bool
	AllowSubdomains bool
}

// DefaultConfig returns conservative crawler defaults.
func DefaultConfig() Config {
	return Config{
		MaxDepth:        3,
		MaxPages:        500,
		MaxConcurrency:  5,
		MaxResponseSize: 5 << 20,
		MaxParameters:   300,
		MaxEndpoints:    2000,
		RateLimit:       2,
		Timeout:         10 * time.Second,
		ParseJS:         true,
		ParseForms:      true,
		ParseParameters: true,
		FollowRedirects: true,
		CheckSitemap:    true,
		CheckRobots:     true,
		BreadthFirst:    true,
	}
}

// Result is the outcome of a crawl.
type Result struct {
	Seed            string
	Pages           []models.HTTPSvc
	Endpoints       []models.Endpoint
	Parameters      []models.Parameter
	OutOfScope      int
	BlockedByRobots int
	Errors          []string
	Truncated       bool
	Reason          string
	StartedAt       time.Time
	FinishedAt      time.Time
}

// Crawler walks a site within budget.
type Crawler struct {
	cfg    Config
	client *httpclient.Client
	scope  *scope.Engine
	robots *robots.Store

	mu            sync.Mutex
	seen          map[string]struct{}
	endpointsSeen []models.Endpoint
	paramsSeen    []models.Parameter
	pagesSeen     []models.HTTPSvc
	errsSeen      []string

	pages      atomic.Int64
	endpoints  atomic.Int64
	parameters atomic.Int64
	bytesRead  atomic.Int64
	outOfScope atomic.Int64
	blocked    atomic.Int64
	truncated  atomic.Bool
}

// New builds a crawler.
func New(cfg Config, client *httpclient.Client, sc *scope.Engine, rs *robots.Store) (*Crawler, error) {
	if client == nil {
		return nil, errors.New("crawler: an HTTP client is required")
	}
	if sc == nil {
		return nil, errors.New("crawler: a scope engine is required")
	}
	if cfg.MaxDepth <= 0 {
		cfg.MaxDepth = 1
	}
	if cfg.MaxPages <= 0 {
		cfg.MaxPages = 100
	}
	if cfg.MaxConcurrency <= 0 {
		cfg.MaxConcurrency = 1
	}
	if cfg.MaxResponseSize <= 0 {
		cfg.MaxResponseSize = 5 << 20
	}
	if cfg.MaxParameters <= 0 {
		cfg.MaxParameters = 100
	}
	if cfg.MaxEndpoints <= 0 {
		cfg.MaxEndpoints = 500
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	return &Crawler{
		cfg:    cfg,
		client: client,
		scope:  sc,
		robots: rs,
		seen:   map[string]struct{}{},
	}, nil
}

// item is one unit of frontier work.
type item struct {
	url   *url.URL
	depth int
	kind  models.EndpointKind
}

// Crawl walks from a seed URL and returns everything discovered.
func (c *Crawler) Crawl(ctx context.Context, seed string) (*Result, error) {
	if err := c.scope.RequireActive(); err != nil {
		return nil, err
	}
	start, err := NormalizeURL(seed, http.MethodGet)
	if err != nil {
		return nil, fmt.Errorf("crawler: seed %q: %w", seed, err)
	}
	if d := c.scope.CheckURL(start); !d.Allowed {
		return nil, fmt.Errorf("%w: seed %s (%s)", scope.ErrTargetDenied, seed, d.Reason)
	}

	res := &Result{Seed: start.String(), StartedAt: time.Now().UTC()}
	// A crawl is one logical unit of work against a target, so it holds a
	// single concurrency slot for its lifetime.
	if err := c.client.Limiter().AcquireSlot(ctx); err != nil {
		return nil, err
	}
	defer c.client.Limiter().ReleaseSlot()

	queue := newQueue()
	c.markSeen(start.String())
	queue.push(item{url: start, depth: 0})

	// Well-known discovery paths are queued as ordinary work so they share the
	// same budget and the same scope checks.
	if c.cfg.CheckRobots {
		queue.push(item{url: joinPath(start, "/robots.txt"), depth: 0, kind: models.EndpointRobots})
	}
	if c.cfg.CheckSitemap {
		queue.push(item{url: joinPath(start, "/sitemap.xml"), depth: 0, kind: models.EndpointSitemap})
	}
	for _, k := range c.cfg.KnownFiles {
		queue.push(item{url: joinPath(start, k), depth: 0})
	}

	// Breadth-first drains the whole current depth before descending; depth-first
	// pushes children to the front so a single path is followed as far as the
	// budget allows.
	pop := queue.popFront
	push := queue.pushBack
	if !c.cfg.BreadthFirst {
		pop = queue.popBack
		push = queue.pushFront
	}

	// A worker must not exit merely because the queue is momentarily empty:
	// another worker may be mid-request and about to enqueue children. The
	// crawl ends only when the queue is empty and no request is in flight.
	var inFlight atomic.Int64
	var wg sync.WaitGroup
	workers := c.cfg.MaxConcurrency
	if workers > 32 {
		workers = 32
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				// Cancellation is checked first so a cancelled crawl does not
				// wait for a slow request to finish.
				select {
				case <-ctx.Done():
					return
				default:
				}
				it, ok := pop()
				if !ok {
					if queue.len() == 0 && inFlight.Load() == 0 {
						return
					}
					// Yield briefly and re-check rather than spinning hard.
					select {
					case <-ctx.Done():
						return
					case <-time.After(20 * time.Millisecond):
					}
					continue
				}
				if it.depth > c.cfg.MaxDepth {
					continue
				}
				if c.pages.Load() >= int64(c.cfg.MaxPages) {
					c.truncated.Store(true)
					continue
				}
				inFlight.Add(1)
				svc, body := c.fetch(ctx, it)
				if svc != nil {
					c.discover(svc, body, it.depth, queue, push)
				}
				inFlight.Add(-1)
			}
		}()
	}
	wg.Wait()

	c.mu.Lock()
	res.Pages = append(res.Pages, c.pagesSeen...)
	res.Endpoints = append(res.Endpoints, c.endpointsSeen...)
	res.Parameters = append(res.Parameters, c.paramsSeen...)
	res.Errors = append(res.Errors, c.errsSeen...)
	c.mu.Unlock()

	models.SortParams(res.Parameters)
	sort.Slice(res.Endpoints, func(i, j int) bool { return res.Endpoints[i].URL < res.Endpoints[j].URL })
	res.OutOfScope = int(c.outOfScope.Load())
	res.BlockedByRobots = int(c.blocked.Load())
	res.Truncated = c.truncated.Load()
	if res.Truncated {
		res.Reason = fmt.Sprintf("max_pages (%d) reached", c.cfg.MaxPages)
	}
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// fetch performs one crawl request. The scope check sits immediately above the
// only call in this package that performs I/O, so it cannot be bypassed.
func (c *Crawler) fetch(ctx context.Context, it item) (*models.HTTPSvc, []byte) {
	u := it.url
	if d := c.scope.CheckURL(u); !d.Allowed {
		c.outOfScope.Add(1)
		return nil, nil
	}
	if c.robots != nil && c.robots.Enabled() {
		if allowed, _ := c.robots.Allowed(u); !allowed {
			c.blocked.Add(1)
			return nil, nil
		}
	}
	if err := c.client.Limiter().Acquire(); err != nil {
		return nil, nil
	}
	if c.pages.Add(1) > int64(c.cfg.MaxPages) {
		c.pages.Add(-1)
		c.truncated.Store(true)
		return nil, nil
	}
	resp, err := c.client.Do(ctx, httpclient.Request{
		URL:               u.String(),
		Method:            http.MethodGet,
		TruncateBody:      true,
		NoFollowRedirects: false,
	})
	if err != nil {
		c.mu.Lock()
		if len(c.errsSeen) < 200 {
			c.errsSeen = append(c.errsSeen, err.Error())
		}
		c.mu.Unlock()
		return nil, nil
	}
	body := resp.Body
	if int64(len(body)) > c.cfg.MaxResponseSize {
		body = body[:c.cfg.MaxResponseSize]
	}
	c.bytesRead.Add(int64(len(resp.Body)))
	svc := ServiceFromResponse(resp, u.String(), it.depth)
	c.mu.Lock()
	c.pagesSeen = append(c.pagesSeen, svc)
	c.mu.Unlock()
	c.recordEndpoint(it.kind, u.String(), it.depth, svc)
	return &svc, body
}

// discover extracts work and parameters from a fetched page.
func (c *Crawler) discover(svc *models.HTTPSvc, body []byte, depth int, queue *queue, push func(item)) []item {
	if svc == nil || depth >= c.cfg.MaxDepth {
		return nil
	}
	base := svc.URL
	if svc.FinalURL != "" {
		base = svc.FinalURL
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil
	}
	extracted := Extract(u, body, svc.ContentType, ExtractOptions{
		JavaScript: c.cfg.ParseJS,
		Forms:      c.cfg.ParseForms,
		Parameters: c.cfg.ParseParameters,
		MaxParams:  c.cfg.MaxParameters,
	})

	c.mu.Lock()
	for _, p := range extracted.Parameters {
		if c.parameters.Load() >= int64(c.cfg.MaxParameters) {
			break
		}
		c.parameters.Add(1)
		c.paramsSeen = append(c.paramsSeen, p)
	}
	c.mu.Unlock()

	var out []item
	for _, l := range extracted.Links {
		if l.Method != "" && !strings.EqualFold(l.Method, http.MethodGet) {
			// A form action is recorded as an endpoint and never submitted.
			c.recordEndpoint(models.EndpointForm, resolveString(u, l.URL), depth, models.HTTPSvc{})
			continue
		}
		nu, err := Resolve(u, l.URL)
		if err != nil {
			continue
		}
		if d := c.scope.CheckURL(nu); !d.Allowed {
			c.outOfScope.Add(1)
			continue
		}
		if !c.cfg.AllowSubdomains && !strings.EqualFold(u.Hostname(), nu.Hostname()) {
			continue
		}
		norm, err := NormalizeURL(nu.String(), http.MethodGet)
		if err != nil {
			continue
		}
		key := norm.String()
		if !c.markSeen(key) {
			continue
		}
		c.recordEndpoint(l.Kind, key, depth, models.HTTPSvc{})
		child := item{url: norm, depth: depth + 1, kind: l.Kind}
		out = append(out, child)
		push(child)
	}
	if c.cfg.FollowRedirects {
		for _, r := range svc.Redirects {
			if r.Blocked {
				continue
			}
			nu, err := Resolve(u, r.To)
			if err != nil {
				continue
			}
			if d := c.scope.CheckURL(nu); !d.Allowed {
				c.outOfScope.Add(1)
				continue
			}
			norm, err := NormalizeURL(nu.String(), http.MethodGet)
			if err != nil {
				continue
			}
			if !c.markSeen(norm.String()) {
				continue
			}
			child := item{url: norm, depth: depth + 1, kind: models.EndpointRedirect}
			out = append(out, child)
			push(child)
		}
	}
	return out
}

func (c *Crawler) markSeen(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, dup := c.seen[key]; dup {
		return false
	}
	c.seen[key] = struct{}{}
	return true
}

func (c *Crawler) recordEndpoint(kind models.EndpointKind, rawURL string, depth int, svc models.HTTPSvc) {
	if kind == "" {
		kind = models.EndpointLink
	}
	if c.endpoints.Load() >= int64(c.cfg.MaxEndpoints) {
		return
	}
	c.endpoints.Add(1)
	c.mu.Lock()
	c.endpointsSeen = append(c.endpointsSeen, models.Endpoint{
		URL:         rawURL,
		Method:      http.MethodGet,
		Kind:        kind,
		Source:      "crawler",
		Depth:       depth,
		StatusCode:  svc.StatusCode,
		ContentType: svc.ContentType,
		Observed:    time.Now().UTC(),
	})
	c.mu.Unlock()
}

func joinPath(base *url.URL, path string) *url.URL {
	u := *base
	u.Path = path
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	u.RawFragment = ""
	return &u
}

func resolveString(base *url.URL, ref string) string {
	u, err := Resolve(base, ref)
	if err != nil {
		return ref
	}
	return u.String()
}

// Stats reports crawler counters.
func (c *Crawler) Stats() map[string]int64 {
	return map[string]int64{
		"pages":             c.pages.Load(),
		"endpoints":         c.endpoints.Load(),
		"parameters":        c.parameters.Load(),
		"bytes":             c.bytesRead.Load(),
		"out_of_scope":      c.outOfScope.Load(),
		"blocked_by_robots": c.blocked.Load(),
	}
}

// queue is a double-ended work queue, so a breadth-first crawl drains the
// queue in order while a depth-first crawl pushes children to the front. It is
// unbounded on purpose: the page budget is enforced by the workers, and a
// bounded queue would deadlock breadth-first traversal by refusing items that
// its own workers would immediately drain.
type queue struct {
	mu    sync.Mutex
	items []item
}

func newQueue() *queue { return &queue{} }

func (q *queue) push(it item) {
	q.mu.Lock()
	q.items = append(q.items, it)
	q.mu.Unlock()
}

func (q *queue) pushBack(it item) { q.push(it) }

func (q *queue) pushFront(it item) {
	q.mu.Lock()
	q.items = append([]item{it}, q.items...)
	q.mu.Unlock()
}

func (q *queue) popFront() (item, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) == 0 {
		return item{}, false
	}
	it := q.items[0]
	q.items = q.items[1:]
	return it, true
}

func (q *queue) popBack() (item, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) == 0 {
		return item{}, false
	}
	it := q.items[len(q.items)-1]
	q.items = q.items[:len(q.items)-1]
	return it, true
}

func (q *queue) len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}
