// Package robots parses and evaluates robots.txt under a scope boundary.
//
// Two properties matter here. First, fetching robots.txt is itself an active
// request, so it goes through the same scope engine as everything else and it
// is skipped entirely in passive-only mode. Second, the parser treats the file
// as hostile input: it is bounded in size, group expansion is bounded against
// the classic billion-laughs shape, and a malformed line is skipped rather
// than treated as a rule.
package robots

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bbtoolkit/bugbounty/internal/http"
	"github.com/bbtoolkit/bugbounty/internal/redact"
	"github.com/bbtoolkit/bugbounty/internal/scope"
)

// MaxSize bounds the robots.txt body that will be parsed.
const MaxSize = 512 << 10

// MaxGroupExpansion bounds the total rules a wildcard group may produce.
const MaxGroupExpansion = 10000

// Rule is one path rule.
type Rule struct {
	Path     string
	Allow    bool
	Priority int
	// Line is the source line, kept for evidence.
	Line int
	// Anchor and Prefix implement the standard matching: a rule ending in $ is
	// anchored, a rule containing * is a prefix match.
	Anchor bool
	Prefix bool
}

type group struct {
	rules  []Rule
	agents []string
}

// Policy is a parsed robots.txt for one origin.
type Policy struct {
	Origin     string
	Groups     []group
	Sitemaps   []string
	CrawlDelay time.Duration
	FetchedAt  time.Time
	Available  bool
	ParseError string
	// DenyAll forces every path to be refused regardless of any rule. It is
	// set when the origin answered in a way that means "stop", and it exists
	// because recording a reason without acting on it would fail open: a note
	// saying to treat a host as off limits, followed by code that walks the
	// whole site, is worse than no note.
	DenyAll bool
}

// Allows reports whether a path may be fetched for the given user agent.
func (p *Policy) Allows(path, agent string) (bool, string) {
	if p == nil {
		return true, "no robots.txt available"
	}
	if p.DenyAll {
		return false, p.ParseError
	}
	if !p.Available {
		return true, "no robots.txt available"
	}
	best, bestPriority, matched := true, 0, ""
	for i := range p.Groups {
		g := &p.Groups[i]
		if !groupApplies(g, agent) {
			continue
		}
		for _, r := range g.rules {
			if !ruleMatches(r, path) {
				continue
			}
			if r.Priority > bestPriority {
				best, bestPriority, matched = r.Allow, r.Priority, r.Path
			}
		}
	}
	return best, matched
}

func groupApplies(g *group, agent string) bool {
	agent = strings.ToLower(agent)
	for _, a := range g.agents {
		if a == "*" || strings.Contains(agent, a) {
			return true
		}
	}
	return false
}

// ruleMatches implements RFC 9309 path matching. The only wildcards are '*'
// (any sequence of characters) and a trailing '$' (end of the path); everything
// else is literal.
func ruleMatches(r Rule, path string) bool {
	if path == "" {
		path = "/"
	}
	if r.Path == "" {
		// "Disallow:" with an empty value means allow everything, which the
		// parser already represents by dropping the rule.
		return false
	}
	return matchGlob(r.Path, path)
}

// matchGlob matches a robots path pattern against a path.
//
// The only wildcards are '*' (any sequence of characters) and a trailing '$',
// which anchors the rule to the end of the path. Everything else is literal.
//
// A non-anchored rule matches any path it is a prefix of, which is what makes
// "Disallow: /admin" cover "/admin/page" and "Disallow: /" cover everything.
// Getting that wrong is a robots bypass, so the pattern is treated as satisfied
// the moment it is exhausted, rather than only when the path is also exhausted.
//
// The scan is the classic two-pointer form: on a mismatch it rewinds to just
// after the last '*' and extends that wildcard by one character, so a hostile
// pattern such as "/*a*a*a*a*a*a*$" cannot trigger exponential backtracking. The
// pattern length is separately capped at parse time, which bounds the constant
// factor.
func matchGlob(pattern, path string) bool {
	anchor := strings.HasSuffix(pattern, "$")
	if anchor {
		pattern = pattern[:len(pattern)-1]
	}
	var p, s int
	star, mark := -1, 0
	for s < len(path) {
		switch {
		case p >= len(pattern) && !anchor:
			// The pattern is spent and the rule is not anchored, so whatever is
			// left of the path is irrelevant: the rule matches this prefix.
			//
			// This is checked before backtracking on purpose. A greedy star may
			// have overshot a position where the pattern was already exhausted,
			// and retrying the star would walk past the match and report no
			// match at all.
			return true
		case p < len(pattern) && pattern[p] == '*':
			star, p, mark = p, p+1, s
		case p < len(pattern) && pattern[p] == path[s]:
			p++
			s++
		case star >= 0:
			p = star + 1
			mark++
			s = mark
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	if p != len(pattern) {
		return false
	}
	return !anchor || s == len(path)
}

// Parse reads a robots.txt body. Malformed input yields the rules that could be
// understood plus a note, never an error that would silently disable the file.
func Parse(origin, body, agent string) *Policy {
	p := &Policy{Origin: origin, FetchedAt: time.Now().UTC()}
	if len(body) > MaxSize {
		p.ParseError = "robots.txt exceeded the size limit; the tail was ignored"
		body = body[:MaxSize]
	}
	lines := strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n")
	var cur *group
	expanded := 0

	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(line) > 2000 {
			continue
		}
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		field := strings.ToLower(strings.TrimSpace(line[:idx]))
		value := strings.TrimSpace(line[idx+1:])

		switch field {
		case "user-agent":
			if cur == nil || len(cur.rules) > 0 {
				p.Groups = append(p.Groups, group{})
				cur = &p.Groups[len(p.Groups)-1]
			}
			a := strings.ToLower(value)
			if len(a) > 128 {
				a = a[:128]
			}
			cur.agents = append(cur.agents, a)
		case "allow", "disallow":
			if cur == nil {
				continue
			}
			// An empty Disallow means allow everything; an empty Allow is a
			// no-op. Both are dropped so they cannot override a later rule.
			if value == "" {
				continue
			}
			if !strings.HasPrefix(value, "/") {
				value = "/" + value
			}
			// The cap is checked before the rule is kept, so the retained count
			// never exceeds the limit.
			if expanded >= MaxGroupExpansion {
				p.ParseError = "robots.txt produced more rules than the limit; the tail was ignored"
				return p
			}
			r := Rule{Path: value, Allow: field == "allow", Line: i + 1}
			r.Anchor = strings.HasSuffix(value, "$")
			r.Prefix = strings.Contains(value, "*")
			r.Priority = len(value)
			cur.rules = append(cur.rules, r)
			expanded++
		case "sitemap":
			if v, err := url.Parse(value); err == nil && isHTTPURL(v) {
				p.Sitemaps = append(p.Sitemaps, v.String())
			}
		case "crawl-delay":
			if d, err := strconv.ParseFloat(value, 64); err == nil && d > 0 && d <= 3600 {
				p.CrawlDelay = time.Duration(d * float64(time.Second))
			}
		}
	}
	p.Available = true
	_ = agent
	return p
}

func isHTTPURL(u *url.URL) bool {
	return (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// Store caches robots policies per origin and answers allow decisions.
type Store struct {
	client  *httpclient.Client
	scope   *scope.Engine
	agent   string
	enabled bool

	mu       sync.Mutex
	policies map[string]*Policy
}

// NewStore builds a robots store. When enabled is false every path is allowed
// without fetching, which is the documented behaviour of respect_robots: false.
func NewStore(client *httpclient.Client, sc *scope.Engine, agent string, enabled bool) *Store {
	return &Store{client: client, scope: sc, agent: agent, enabled: enabled, policies: map[string]*Policy{}}
}

// Enabled reports whether the policy is being honoured.
func (s *Store) Enabled() bool { return s != nil && s.enabled }

// Allowed fetches the policy once per origin and then answers from cache.
func (s *Store) Allowed(u *url.URL) (bool, string) {
	if !s.Enabled() || u == nil {
		return true, "robots enforcement disabled"
	}
	origin := originOf(u)
	pol, err := s.policyFor(context.Background(), u, origin)
	if err != nil || pol == nil || !pol.Available {
		return true, "no robots.txt available"
	}
	return pol.Allows(u.Path, s.agent)
}

func originOf(u *url.URL) string {
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

func (s *Store) policyFor(ctx context.Context, u *url.URL, origin string) (*Policy, error) {
	s.mu.Lock()
	if p, ok := s.policies[origin]; ok {
		s.mu.Unlock()
		return p, nil
	}
	s.mu.Unlock()

	robotsURL := *u
	robotsURL.Path = "/robots.txt"
	robotsURL.RawQuery = ""
	robotsURL.Fragment = ""

	// Fetching robots.txt is an active request, so it is scope-checked like
	// any other and refused in passive-only mode.
	if d := s.scope.CheckURL(&robotsURL); !d.Allowed {
		pol := &Policy{Origin: origin, ParseError: "out of scope: " + d.Reason}
		s.store(origin, pol)
		return nil, fmt.Errorf("%w: %s", scope.ErrTargetDenied, robotsURL.String())
	}
	resp, err := s.client.Do(ctx, httpclient.Request{URL: robotsURL.String(), Method: http.MethodGet, TruncateBody: true})
	if err != nil {
		pol := &Policy{Origin: origin, ParseError: redact.Sanitize(err.Error())}
		s.store(origin, pol)
		return pol, err
	}
	pol := &Policy{Origin: origin}
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		// The origin is actively asking for less traffic. Honouring that is
		// the whole point of reading robots.txt, so nothing is fetched.
		pol.Available = true
		pol.DenyAll = true
		pol.ParseError = "the server returned 429; this host is treated as off limits for the rest of the run"
	case resp.StatusCode >= 500:
		// RFC 9309: a server error means the rules could not be read, and the
		// crawler should assume a complete disallow rather than assume the
		// site is unrestricted.
		pol.Available = true
		pol.DenyAll = true
		pol.ParseError = fmt.Sprintf("the server returned %d; RFC 9309 requires assuming a complete disallow", resp.StatusCode)
	case resp.StatusCode >= 400:
		// Any other 4xx means no restrictions are published, so nothing is
		// forbidden. The body is not parsed: it is an error page, and treating
		// it as rules would let a redirect target dictate what is crawlable.
		pol.Available = true
		pol.DenyAll = false
		pol.ParseError = fmt.Sprintf("the server returned %d; no restrictions are published", resp.StatusCode)
	default:
		pol = Parse(origin, string(resp.Body), s.agent)
	}
	pol.FetchedAt = time.Now().UTC()
	s.store(origin, pol)
	return pol, nil
}

func (s *Store) store(origin string, p *Policy) {
	s.mu.Lock()
	s.policies[origin] = p
	s.mu.Unlock()
}

// Policy returns a cached policy, fetching it if necessary.
func (s *Store) Policy(ctx context.Context, u *url.URL) (*Policy, error) {
	if !s.Enabled() {
		return nil, nil
	}
	return s.policyFor(ctx, u, originOf(u))
}

// Sitemaps returns the sitemap URLs published for an origin.
func (s *Store) Sitemaps(ctx context.Context, u *url.URL) []string {
	pol, err := s.Policy(ctx, u)
	if err != nil || pol == nil {
		return nil
	}
	return pol.Sitemaps
}

// CrawlDelay returns the published crawl delay for an origin, if any.
func (s *Store) CrawlDelay(ctx context.Context, u *url.URL) time.Duration {
	pol, err := s.Policy(ctx, u)
	if err != nil || pol == nil {
		return 0
	}
	return pol.CrawlDelay
}

// Len reports how many origins are cached.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.policies)
}
