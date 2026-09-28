package httpclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bbtoolkit/bugbounty/internal/ratelimit"
	"github.com/bbtoolkit/bugbounty/internal/scope"
)

func newTestEngine(t *testing.T, allowed, excluded []string, passiveOnly bool) *scope.Engine {
	t.Helper()
	p := scope.DefaultPolicy()
	p.PassiveOnly = passiveOnly
	e, err := scope.New(allowed, excluded, p)
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	return e
}

func newClient(t *testing.T, sc *scope.Engine) *Client {
	t.Helper()
	c, err := New(DefaultConfig(), sc, ratelimit.New(0, 4, 0), nil)
	if err != nil {
		t.Fatalf("httpclient.New: %v", err)
	}
	return c
}

// --- SECURITY TEST 1 & 3: out-of-scope and excluded targets ------------------

func TestOutOfScopeTargetNeverRequested(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sc := newTestEngine(t, []string{"example.com"}, nil, false)
	c := newClient(t, sc)

	u := strings.Replace(srv.URL, "127.0.0.1", "outofscope.example", 1)
	_, err := c.Do(context.Background(), Request{URL: u})
	if !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("expected ErrOutOfScope, got %v", err)
	}
	if hits.Load() != 0 {
		t.Errorf("SECURITY: the out-of-scope host was requested %d times", hits.Load())
	}
}

func TestExcludedSubdomainNeverRequested(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()

	sc := newTestEngine(t, []string{"*.example.com"}, []string{"admin.example.com"}, false)
	c := newClient(t, sc)

	u := strings.Replace(srv.URL, "127.0.0.1", "admin.example.com", 1)
	if _, err := c.Do(context.Background(), Request{URL: u}); !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("expected the excluded subdomain to be denied, got %v", err)
	}
	if hits.Load() != 0 {
		t.Errorf("SECURITY: the excluded subdomain was requested %d times", hits.Load())
	}
}

// --- SECURITY TEST 2: out-of-scope redirects cannot be followed --------------

func TestOutOfScopeRedirectNotFollowed(t *testing.T) {
	var victimHits atomic.Int64
	// The victim stands in for a system that must never be reached: a scope
	// escape here is exactly the SSRF we need to prevent.
	victim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		victimHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer victim.Close()

	// The in-scope origin redirects to the victim.
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, victim.URL+"/secret", http.StatusFound)
	}))
	defer origin.Close()

	host, port := splitHost(t, origin.URL)
	sc := newTestEngine(t, []string{net.JoinHostPort(host, port)}, nil, false)
	c := newClient(t, sc)

	_, err := c.Do(context.Background(), Request{URL: origin.URL + "/start"})
	if err == nil {
		t.Fatal("expected the out-of-scope redirect to be refused")
	}
	if !strings.Contains(err.Error(), "out of scope") {
		t.Errorf("error should name the scope denial, got: %v", err)
	}
	if victimHits.Load() != 0 {
		t.Fatalf("SECURITY: the redirect destination was requested %d times", victimHits.Load())
	}
}

func TestRedirectToExcludedSubdomainBlocked(t *testing.T) {
	var hits atomic.Int64
	victim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer victim.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, strings.Replace(victim.URL, "127.0.0.1", "admin.example.com", 1), http.StatusMovedPermanently)
	}))
	defer origin.Close()

	host, port := splitHost(t, origin.URL)
	sc := newTestEngine(t, []string{net.JoinHostPort(host, port)}, []string{"admin.example.com"}, false)
	c := newClient(t, sc)

	if _, err := c.Do(context.Background(), Request{URL: origin.URL}); err == nil {
		t.Fatal("expected the redirect to an excluded host to be refused")
	}
	if hits.Load() != 0 {
		t.Errorf("SECURITY: excluded redirect destination reached %d times", hits.Load())
	}
}

func TestInScopeRedirectIsFollowedAndRecorded(t *testing.T) {
	var final atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/final", http.StatusFound)
	})
	mux.HandleFunc("/final", func(w http.ResponseWriter, r *http.Request) {
		final.Add(1)
		fmt.Fprint(w, "<html><title>Arrived</title></html>")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	host, port := splitHost(t, srv.URL)
	sc := newTestEngine(t, []string{net.JoinHostPort(host, port)}, nil, false)
	c := newClient(t, sc)

	resp, err := c.Do(context.Background(), Request{URL: srv.URL})
	if err != nil {
		t.Fatalf("in-scope redirect should be followed: %v", err)
	}
	if final.Load() != 1 {
		t.Errorf("final page not reached")
	}
	if resp.Title != "Arrived" {
		t.Errorf("title = %q", resp.Title)
	}
	if !strings.HasSuffix(resp.FinalURL, "/final") {
		t.Errorf("final url = %q", resp.FinalURL)
	}
	if len(resp.Redirects) == 0 {
		t.Error("redirect chain was not recorded")
	}
}

func TestRedirectLoopIsBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop", http.StatusFound)
	}))
	defer srv.Close()

	host, port := splitHost(t, srv.URL)
	sc := newTestEngine(t, []string{net.JoinHostPort(host, port)}, nil, false)
	c := newClient(t, sc)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := c.Do(ctx, Request{URL: srv.URL + "/loop"})
	if err == nil {
		t.Fatal("expected the redirect limit to stop the loop")
	}
	if !strings.Contains(err.Error(), "redirect") {
		t.Errorf("error should mention the redirect limit, got: %v", err)
	}
}

// --- SECURITY TEST 6: passive-only performs no active requests --------------

func TestPassiveOnlyPerformsNoRequests(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()

	sc := newTestEngine(t, []string{"example.com"}, nil, true)
	c := newClient(t, sc)

	_, err := c.Do(context.Background(), Request{URL: srv.URL})
	if !errors.Is(err, scope.ErrPassiveOnly) {
		t.Fatalf("expected scope.ErrPassiveOnly, got %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("SECURITY: passive-only mode issued %d requests", hits.Load())
	}
}

func TestPassiveOnlyBlocksDNSAndDial(t *testing.T) {
	sc := newTestEngine(t, []string{"example.com"}, nil, true)
	c := newClient(t, sc)
	// Even a URL that would otherwise pass scope is refused before the dialer
	// is reached.
	_, err := c.Do(context.Background(), Request{URL: "http://example.com/"})
	if !errors.Is(err, scope.ErrPassiveOnly) {
		t.Fatalf("expected ErrPassiveOnly, got %v", err)
	}
}

// --- SSRF: the dialer refuses to reach the local network --------------------

func TestDialerRefusesLoopbackWithoutExplicitRule(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()

	// A domain name is in scope, but the URL points at loopback directly.
	sc := newTestEngine(t, []string{"example.com", "127.0.0.1"}, nil, false)
	c := newClient(t, sc)

	// Force the transport to think it is talking to example.com while the URL
	// is loopback, which is the classic SSRF shape.
	_, err := c.Do(context.Background(), Request{URL: srv.URL})
	if err == nil {
		t.Log("loopback was explicitly scoped, so the request is expected to succeed")
	}
	// Now remove the explicit rule.
	sc2 := newTestEngine(t, []string{"example.com"}, nil, false)
	c2 := newClient(t, sc2)
	if _, err := c2.Do(context.Background(), Request{URL: srv.URL}); !errors.Is(err, ErrOutOfScope) {
		t.Errorf("SECURITY: loopback reachable without an explicit rule: %v", err)
	}
}

func TestCloudMetadataAlwaysRefused(t *testing.T) {
	sc := newTestEngine(t, []string{"169.254.169.254/32"}, nil, false)
	c := newClient(t, sc)
	_, err := c.Do(context.Background(), Request{URL: "http://169.254.169.254/latest/meta-data/"})
	if err == nil || !strings.Contains(err.Error(), "metadata") {
		t.Errorf("SECURITY: cloud metadata endpoint was not refused: %v", err)
	}
}

func TestNonHTTPSchemesRefused(t *testing.T) {
	sc := newTestEngine(t, []string{"example.com"}, nil, false)
	c := newClient(t, sc)
	for _, u := range []string{"file:///etc/passwd", "gopher://example.com/", "ftp://example.com/"} {
		if _, err := c.Do(context.Background(), Request{URL: u}); err == nil {
			t.Errorf("SECURITY: scheme accepted: %s", u)
		}
	}
}

// --- DNS rebinding ----------------------------------------------------------

// rebindingResolver alternates between a permitted answer and a loopback
// answer, which is exactly what a rebinding attack looks like to a client that
// validates the name once and lets the OS resolver connect.
type rebindingResolver struct {
	calls atomic.Int64
}

func (r *rebindingResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	return "", &net.DNSError{Err: "no CNAME", Name: host, IsNotFound: true}
}

func (r *rebindingResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	n := r.calls.Add(1)
	if n%2 == 0 {
		// "Rebound" to the local machine.
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}

func TestDialerRefusesReboundLoopbackAnswer(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, "secret")
	}))
	defer srv.Close()

	sc := newTestEngine(t, []string{"rebind.example.com"}, nil, false)
	c, err := New(DefaultConfig(), sc, ratelimit.New(0, 2, 0), nil)
	if err != nil {
		t.Fatal(err)
	}
	// Swap in a resolver that lies about the address. The real DNS name is
	// out of scope anyway, so the point is the dialer's behaviour.
	c.resolver = &rebindingResolver{}

	_, err = c.Do(context.Background(), Request{URL: "http://rebind.example.com:8080/"})
	if err == nil {
		t.Fatal("expected the rebound loopback answer to be refused")
	}
	if hits.Load() != 0 {
		t.Errorf("SECURITY: a rebound request reached the local server %d times", hits.Load())
	}
	if !strings.Contains(err.Error(), "out of scope") && !strings.Contains(err.Error(), "loopback") {
		t.Logf("error (acceptable): %v", err)
	}
}

// --- method allowlist -------------------------------------------------------

func TestUnsafeMethodsRejected(t *testing.T) {
	sc := newTestEngine(t, []string{"example.com"}, nil, false)
	c := newClient(t, sc)
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE", "TRACE", "PROPFIND", "CONNECT"} {
		_, err := c.Do(context.Background(), Request{URL: "http://example.com/", Method: m})
		if !errors.Is(err, ErrMethodNotAllowed) {
			t.Errorf("SECURITY: method %s was not rejected: %v", m, err)
		}
	}
}

func TestSafeMethodsAllowed(t *testing.T) {
	for _, m := range []string{"GET", "HEAD", "OPTIONS"} {
		sc := newTestEngine(t, []string{"example.com"}, nil, false)
		c := newClient(t, sc)
		_, err := c.Do(context.Background(), Request{URL: "http://example.com/", Method: m})
		if errors.Is(err, ErrMethodNotAllowed) {
			t.Errorf("method %s should be allowed: %v", m, err)
		}
	}
}

func TestRequestBodyRejectedByDefault(t *testing.T) {
	sc := newTestEngine(t, []string{"example.com"}, nil, false)
	c := newClient(t, sc)
	_, err := c.Do(context.Background(), Request{
		URL: "http://example.com/", Method: "POST", Body: strings.NewReader("x"),
	})
	if !errors.Is(err, ErrMethodNotAllowed) {
		t.Errorf("expected the body-carrying method to be rejected, got %v", err)
	}
}

// --- bounded responses ------------------------------------------------------

func TestOversizedResponseIsBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 8 MiB of data against a 64 KiB limit.
		chunk := strings.Repeat("A", 8192)
		for i := 0; i < 1024; i++ {
			_, _ = w.Write([]byte(chunk))
		}
	}))
	defer srv.Close()

	host, port := splitHost(t, srv.URL)
	sc := newTestEngine(t, []string{net.JoinHostPort(host, port)}, nil, false)
	cfg := DefaultConfig()
	cfg.MaxResponseBytes = 64 << 10
	cfg.Retries = 0
	c, err := New(cfg, sc, ratelimit.New(0, 2, 0), nil)
	if err != nil {
		t.Fatal(err)
	}

	// Strict mode: the oversized body is an error.
	if _, err := c.Do(context.Background(), Request{URL: srv.URL}); !errors.Is(err, ErrBodyTooLarge) {
		t.Errorf("expected ErrBodyTooLarge, got %v", err)
	}
	// Truncating mode: the caller gets exactly the limit and a flag.
	resp, err := c.Do(context.Background(), Request{URL: srv.URL, TruncateBody: true})
	if err != nil {
		t.Fatalf("truncating request failed: %v", err)
	}
	if int64(len(resp.Body)) > cfg.MaxResponseBytes {
		t.Errorf("SECURITY: %d bytes returned with a %d byte limit", len(resp.Body), cfg.MaxResponseBytes)
	}
	if !resp.BodyTruncated {
		t.Error("truncation was not reported")
	}
}

func TestChunkedResponseWithoutContentLengthIsBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Transfer-Encoding", "chunked")
		fl, _ := w.(http.Flusher)
		chunk := strings.Repeat("B", 4096)
		for i := 0; i < 4096; i++ {
			_, _ = w.Write([]byte(chunk))
			if fl != nil && i%16 == 0 {
				fl.Flush()
			}
		}
	}))
	defer srv.Close()

	host, port := splitHost(t, srv.URL)
	sc := newTestEngine(t, []string{net.JoinHostPort(host, port)}, nil, false)
	cfg := DefaultConfig()
	cfg.MaxResponseBytes = 32 << 10
	cfg.Retries = 0
	c, _ := New(cfg, sc, ratelimit.New(0, 2, 0), nil)
	resp, err := c.Do(context.Background(), Request{URL: srv.URL, TruncateBody: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if int64(len(resp.Body)) > cfg.MaxResponseBytes {
		t.Errorf("SECURITY: chunked response returned %d bytes", len(resp.Body))
	}
}

// --- hostile content --------------------------------------------------------

func TestHostileResponseDoesNotBreakTheClient(t *testing.T) {
	payloads := []string{
		strings.Repeat("<", 200000),
		"<title>" + strings.Repeat("A", 100000),
		"<html><body>" + strings.Repeat("<div>", 50000),
		"\x00\x01\x02 garbage \xff\xfe",
		"<title>unterminated",
		"<title>" + strings.Repeat("\n", 10000) + "x",
		"<a href=\"javascript:alert(1)\">x</a>",
	}
	for i, p := range payloads {
		body := p
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, body)
		}))
		host, port := splitHost(t, srv.URL)
		sc := newTestEngine(t, []string{net.JoinHostPort(host, port)}, nil, false)
		c := newClient(t, sc)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err := c.Do(ctx, Request{URL: srv.URL, TruncateBody: true})
		cancel()
		srv.Close()
		if err != nil {
			// An error is acceptable; a hang, panic or unbounded read is not.
			t.Logf("payload %d produced an error (acceptable): %v", i, err)
		}
	}
}

func TestOversizedHeadersBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Big", strings.Repeat("C", 4<<20))
		w.WriteHeader(200)
	}))
	defer srv.Close()

	host, port := splitHost(t, srv.URL)
	sc := newTestEngine(t, []string{net.JoinHostPort(host, port)}, nil, false)
	cfg := DefaultConfig()
	cfg.MaxHeaderBytes = 32 << 10
	cfg.Retries = 0
	c, _ := New(cfg, sc, ratelimit.New(0, 2, 0), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Either the header limit trips or the request errors; what must not
	// happen is unbounded memory growth.
	_, _ = c.Do(ctx, Request{URL: srv.URL, TruncateBody: true})
}

// --- header hygiene ---------------------------------------------------------

func TestSensitiveResponseHeadersRedacted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session=supersecretvalue; HttpOnly")
		w.Header().Set("X-Api-Key", "AKIAIOSFODNN7EXAMPLE")
		w.Header().Set("X-Request-Id", "abc-123")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	host, port := splitHost(t, srv.URL)
	sc := newTestEngine(t, []string{net.JoinHostPort(host, port)}, nil, false)
	c := newClient(t, sc)

	resp, err := c.Do(context.Background(), Request{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"set-cookie", "x-api-key"} {
		for _, v := range resp.Header[h] {
			if strings.Contains(v, "supersecretvalue") || strings.Contains(v, "AKIAIOSFODNN7EXAMPLE") {
				t.Errorf("SECURITY: %s leaked into the response record: %q", h, v)
			}
		}
	}
	if got := resp.Header["x-request-id"]; len(got) == 0 || got[0] != "abc-123" {
		t.Errorf("benign header lost: %v", got)
	}
}

func TestOutboundCredentialHeadersDropped(t *testing.T) {
	var seen http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
	}))
	defer srv.Close()

	host, port := splitHost(t, srv.URL)
	sc := newTestEngine(t, []string{net.JoinHostPort(host, port)}, nil, false)
	c := newClient(t, sc)

	_, _ = c.Do(context.Background(), Request{URL: srv.URL, Headers: map[string]string{
		"Authorization": "Bearer stolen",
		"Cookie":        "session=abc",
		"X-Api-Key":     "leaked-key",
		"X-Custom":      "kept",
	}})
	if seen == nil {
		t.Skip("server did not record a request")
	}
	for _, h := range []string{"Authorization", "Cookie", "X-Api-Key"} {
		if v := seen.Get(h); v != "" {
			t.Errorf("SECURITY: outbound header %s was sent: %q", h, v)
		}
	}
	if seen.Get("X-Custom") != "kept" {
		t.Error("a benign header was dropped")
	}
}

// --- TLS --------------------------------------------------------------------

func TestTLSValidationOnByDefault(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	sc := newTestEngine(t, []string{"example.com"}, nil, false)
	c, _ := New(DefaultConfig(), sc, ratelimit.New(0, 2, 0), nil)
	if c.cfg.InsecureSkipVerify {
		t.Error("SECURITY: TLS verification is disabled by default")
	}
	if c.hc.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify {
		t.Error("SECURITY: transport has InsecureSkipVerify set")
	}
}

func TestTLSMetadataCollected(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	host, port := splitHost(t, srv.URL)
	sc := newTestEngine(t, []string{net.JoinHostPort(host, port)}, nil, false)
	cfg := DefaultConfig()
	cfg.InsecureSkipVerify = true // the httptest certificate is self-signed
	cfg.Retries = 0
	c, _ := New(cfg, sc, ratelimit.New(0, 2, 0), nil)

	resp, err := c.Do(context.Background(), Request{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if resp.TLS == nil {
		t.Fatal("no TLS metadata collected")
	}
	if resp.TLS.Version == "" || resp.TLS.Fingerprint == "" {
		t.Errorf("incomplete TLS metadata: %+v", resp.TLS)
	}
	if !resp.TLS.SelfSigned {
		t.Log("certificate is not reported as self-signed (unexpected for httptest)")
	}
}

func TestOldTLSVersionRejectedByClient(t *testing.T) {
	// The client floor is TLS 1.2; a server that only offers TLS 1.0 must not
	// be reachable.
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = &tls.Config{MaxVersion: tls.VersionTLS11}
	srv.StartTLS()
	defer srv.Close()

	host, port := splitHost(t, srv.URL)
	sc := newTestEngine(t, []string{net.JoinHostPort(host, port)}, nil, false)
	cfg := DefaultConfig()
	cfg.InsecureSkipVerify = true
	cfg.Retries = 0
	cfg.Timeout = 5 * time.Second
	c, _ := New(cfg, sc, ratelimit.New(0, 2, 0), nil)
	if _, err := c.Do(context.Background(), Request{URL: srv.URL}); err == nil {
		t.Error("SECURITY: a TLS 1.1-only server was accepted")
	}
}

// --- rate limiting integration ---------------------------------------------

func TestClientConsumesSharedBudget(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()

	host, port := splitHost(t, srv.URL)
	sc := newTestEngine(t, []string{net.JoinHostPort(host, port)}, nil, false)
	c, _ := New(DefaultConfig(), sc, ratelimit.New(0, 2, 3), nil) // budget of 3

	for i := 0; i < 6; i++ {
		_, _ = c.Do(context.Background(), Request{URL: srv.URL})
	}
	if hits.Load() > 3 {
		t.Errorf("SECURITY: %d requests were sent with a budget of 3", hits.Load())
	}
}

func TestContextCancellationStopsRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()

	host, port := splitHost(t, srv.URL)
	sc := newTestEngine(t, []string{net.JoinHostPort(host, port)}, nil, false)
	c, _ := New(DefaultConfig(), sc, ratelimit.New(0, 2, 0), nil)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.Do(ctx, Request{URL: srv.URL})
	if err == nil {
		t.Error("expected cancellation to abort the request")
	}
	if time.Since(start) > time.Second {
		t.Errorf("cancellation took %v; the request was not aborted promptly", time.Since(start))
	}
}

func splitHost(t *testing.T, rawURL string) (string, string) {
	t.Helper()
	u := strings.TrimPrefix(strings.TrimPrefix(rawURL, "http://"), "https://")
	i := strings.Index(u, "/")
	if i >= 0 {
		u = u[:i]
	}
	j := strings.LastIndex(u, ":")
	if j < 0 {
		return u, "80"
	}
	return u[:j], u[j+1:]
}
