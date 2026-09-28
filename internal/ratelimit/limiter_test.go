package ratelimit

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestInFlightIsSafeWhileConcurrencyChanges(t *testing.T) {
	// InFlight reads the slot channel, and SetConcurrency swaps that channel
	// for a new one under the mutex. Reading the field without the mutex is a
	// data race on a channel header, not merely a stale count, and the race
	// detector is the only thing that can see it -- so this test is written to
	// run meaningfully under -race while still asserting correct counts without.
	l := New(0, 4, 0)
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		if err := l.AcquireSlot(ctx); err != nil {
			t.Fatalf("AcquireSlot: %v", err)
		}
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = l.InFlight()
				}
			}
		}()
	}
	for _, n := range []int{2, 8, 1, 16, 3} {
		l.SetConcurrency(n)
		if got := l.InFlight(); got < 0 {
			t.Errorf("InFlight = %d, want a non-negative count", got)
		}
	}
	close(stop)
	wg.Wait()

	l.SetConcurrency(4)
	for i := 0; i < 4; i++ {
		l.ReleaseSlot()
	}
	if got := l.InFlight(); got != 0 {
		t.Errorf("in flight = %d after releasing every slot, want 0", got)
	}
}

// fakeClock lets the tests advance time deterministically.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Unix(1700000000, 0)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Sleep(d time.Duration) { c.Advance(d) }
func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	ch <- c.Now().Add(d)
	return ch
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// --- SECURITY TEST 4: rate limits are enforced ------------------------------

func TestRateLimitEnforcedWithFakeClock(t *testing.T) {
	// The limiter is driven with a hand-advanced clock: no sleeping, no
	// flakiness, and an exact assertion on how many operations were allowed.
	clk := newFakeClock()
	l := NewWithClock(10, 1, 0, clk) // 10 tokens per second

	// The initial burst is one second of traffic, so 10 go immediately.
	allowed := 0
	for i := 0; i < 10; i++ {
		if err := l.Wait(context.Background()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		allowed++
	}
	if allowed != 10 {
		t.Fatalf("expected the 10-token burst to pass, got %d", allowed)
	}

	// The 11th must block: verify by racing it against a short deadline.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := l.Wait(ctx); err == nil {
		t.Error("SECURITY: an 11th request was allowed without advancing time")
	}

	// Half a second of idle time refills 5 tokens.
	clk.Advance(500 * time.Millisecond)
	for i := 0; i < 5; i++ {
		if err := l.Wait(context.Background()); err != nil {
			t.Fatalf("after 500ms at 10rps, request %d should be allowed: %v", i+1, err)
		}
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()
	if err := l.Wait(ctx2); err == nil {
		t.Error("SECURITY: 6 requests were allowed after only 500ms at 10rps")
	}
}

func TestRateLimitRealClock(t *testing.T) {
	l := New(20, 1, 0)
	ctx := context.Background()
	start := time.Now()
	for i := 0; i < 20; i++ {
		if err := l.Wait(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// 20 tokens are granted instantly (burst). Ask for 20 more: at 20rps that
	// should take roughly a second.
	for i := 0; i < 20; i++ {
		if err := l.Wait(ctx); err != nil {
			t.Fatal(err)
		}
	}
	elapsed := time.Since(start)
	if elapsed < 400*time.Millisecond {
		t.Errorf("SECURITY: 40 operations at 20rps completed in %v; the rate limit is not being applied", elapsed)
	}
}

func TestZeroRPSMeansUnlimited(t *testing.T) {
	l := New(0, 1, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	for i := 0; i < 1000; i++ {
		if err := l.Wait(ctx); err != nil {
			t.Fatalf("unlimited limiter blocked at request %d: %v", i, err)
		}
	}
}

func TestBudgetEnforced(t *testing.T) {
	l := New(0, 1, 3)
	for i := 0; i < 3; i++ {
		if err := l.Acquire(); err != nil {
			t.Fatalf("acquire %d failed: %v", i, err)
		}
	}
	if err := l.Acquire(); err != ErrBudgetExhausted {
		t.Errorf("expected ErrBudgetExhausted, got %v", err)
	}
	if l.Remaining() != 0 {
		t.Errorf("remaining should be 0, got %d", l.Remaining())
	}
}

func TestBudgetAppliesThroughDo(t *testing.T) {
	l := New(0, 1, 2)
	ctx := context.Background()
	calls := 0
	for i := 0; i < 5; i++ {
		err := l.Do(ctx, func(context.Context) error { calls++; return nil })
		if err == ErrBudgetExhausted {
			break
		}
	}
	if calls != 2 {
		t.Errorf("SECURITY: %d operations ran with a budget of 2", calls)
	}
}

// --- concurrency ------------------------------------------------------------

func TestConcurrencyLimit(t *testing.T) {
	const limit = 4
	l := New(0, limit, 0)
	var (
		mu      sync.Mutex
		current int
		peak    int
		wg      sync.WaitGroup
	)
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := l.Do(context.Background(), func(context.Context) error {
				mu.Lock()
				current++
				if current > peak {
					peak = current
				}
				mu.Unlock()
				time.Sleep(2 * time.Millisecond)
				mu.Lock()
				current--
				mu.Unlock()
				return nil
			})
			if err != nil {
				t.Errorf("Do: %v", err)
			}
		}()
	}
	wg.Wait()
	if peak > limit {
		t.Errorf("SECURITY: peak concurrency %d exceeded the limit of %d", peak, limit)
	}
	if peak < 2 {
		t.Errorf("expected real parallelism, peak was %d", peak)
	}
}

func TestSetConcurrencyRehomesSlots(t *testing.T) {
	l := New(0, 2, 0)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := l.AcquireSlot(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// Grow while slots are held: the holders must not lose their slot.
	l.SetConcurrency(8)
	if l.Concurrency() != 8 {
		t.Fatalf("concurrency = %d, want 8", l.Concurrency())
	}
	if l.InFlight() != 2 {
		t.Errorf("SECURITY: held slots were lost when growing the semaphore (in flight = %d)", l.InFlight())
	}
	for i := 0; i < 6; i++ {
		if err := l.AcquireSlot(ctx); err != nil {
			t.Fatalf("slot %d unavailable after grow: %v", i, err)
		}
	}
	// Shrink: new holders beyond the new ceiling must block. The three holders
	// still in flight are not revoked; the surplus slot is dropped.
	l.SetConcurrency(3)
	blocked := make(chan error, 1)
	go func() { blocked <- l.AcquireSlot(ctx) }()
	select {
	case err := <-blocked:
		if err == nil {
			t.Error("SECURITY: a holder was admitted above the shrunken ceiling")
		}
	case <-time.After(50 * time.Millisecond):
	}
	for i := 0; i < 3; i++ {
		l.ReleaseSlot()
	}
}

func TestCancellationReleasesNothing(t *testing.T) {
	l := New(0, 1, 0)
	if err := l.AcquireSlot(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := l.AcquireSlot(ctx); err == nil {
		t.Error("expected cancellation to be reported")
	}
	l.ReleaseSlot()
	if l.InFlight() != 0 {
		t.Errorf("in flight = %d after release, want 0", l.InFlight())
	}
}

func TestCloseUnblocksWaiters(t *testing.T) {
	l := New(0, 1, 0)
	if err := l.AcquireSlot(context.Background()); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- l.AcquireSlot(context.Background()) }()
	time.Sleep(20 * time.Millisecond)
	l.Close()
	select {
	case err := <-done:
		if err != ErrClosed {
			t.Errorf("expected ErrClosed, got %v", err)
		}
	case <-time.After(time.Second):
		t.Error("SECURITY: Close() did not unblock a waiter")
	}
	l.Close() // idempotent
}

func TestSetRPSLive(t *testing.T) {
	l := New(0, 1, 0)
	l.SetRPS(50)
	if l.RPS() != 50 {
		t.Fatalf("rps = %v", l.RPS())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	n := 0
	for i := 0; i < 200; i++ {
		if err := l.Wait(ctx); err == nil {
			n++
		} else {
			break
		}
	}
	if n < 2 {
		t.Errorf("expected a burst then throttling, got %d", n)
	}
}

func TestDoPropagatesPanicButReleasesSlot(t *testing.T) {
	l := New(0, 1, 0)
	func() {
		defer func() {
			if recover() == nil {
				t.Error("expected the panic to propagate")
			}
		}()
		_ = l.Do(context.Background(), func(context.Context) error { panic("boom") })
	}()
	if l.InFlight() != 0 {
		t.Errorf("SECURITY: a panicking operation leaked a concurrency slot")
	}
	if l.Used() != 1 {
		t.Errorf("budget accounting wrong after panic: %d", l.Used())
	}
}

func TestCloneIsIndependent(t *testing.T) {
	l := New(5, 2, 10)
	c := l.Clone()
	if err := c.Acquire(); err != nil {
		t.Fatal(err)
	}
	if l.Used() != 0 {
		t.Error("clone shares budget state with the original")
	}
	if c.Concurrency() != 2 || c.RPS() != 5 {
		t.Errorf("clone did not inherit settings: %v rps, %d conc", c.RPS(), c.Concurrency())
	}
}

func TestConcurrentBudgetAccounting(t *testing.T) {
	const workers = 50
	const budget = 20
	l := New(0, 8, budget)
	var granted int64
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := l.Acquire(); err == nil {
				atomic.AddInt64(&granted, 1)
			}
		}()
	}
	wg.Wait()
	if granted != budget {
		t.Errorf("SECURITY: %d operations were granted with a budget of %d", granted, budget)
	}
}
