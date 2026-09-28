// Package ratelimit provides the two controls that bound every active
// operation in the toolkit: a global token bucket (requests per second) and a
// concurrency semaphore. A single Limiter is shared by all modules, so
// concurrency is capped across the whole process and not per module.
//
// The clock is injectable so rate limiting can be tested deterministically
// instead of with sleeps.
package ratelimit

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"
)

var (
	// ErrBudgetExhausted is returned when the run-wide request budget is spent.
	ErrBudgetExhausted = errors.New("ratelimit: per-run request budget exhausted")
	// ErrClosed is returned once the limiter is closed.
	ErrClosed = errors.New("ratelimit: limiter closed")
)

// Clock abstracts the passage of time so tests can advance it by hand.
type Clock interface {
	Now() time.Time
	Sleep(d time.Duration)
	After(d time.Duration) <-chan time.Time
}

type realClock struct{}

func (realClock) Now() time.Time                         { return time.Now() }
func (realClock) Sleep(d time.Duration)                  { time.Sleep(d) }
func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// RealClock is the production clock.
var RealClock Clock = realClock{}

// Limiter combines a token bucket, a concurrency semaphore and a run budget.
// It is safe for concurrent use.
type Limiter struct {
	mu sync.Mutex

	rps    float64
	burst  float64
	tokens float64
	last   time.Time
	clock  Clock

	slots   chan struct{}
	maxConc int
	// done is closed by Close. The slot semaphore itself is never closed:
	// closing it would race with a concurrent sender and panic the process.
	done chan struct{}

	budget     int64
	budgetUsed int64

	closed bool
}

// New creates a limiter. rps <= 0 means "no rate limit". concurrency <= 0
// means 1. budget of 0 means unlimited; a negative budget is treated as zero.
func New(rps float64, concurrency, budget int) *Limiter {
	return NewWithClock(rps, concurrency, budget, RealClock)
}

// NewWithClock is the test constructor.
func NewWithClock(rps float64, concurrency, budget int, c Clock) *Limiter {
	if concurrency <= 0 {
		concurrency = 1
	}
	if budget < 0 {
		budget = 0
	}
	if c == nil {
		c = RealClock
	}
	if rps < 0 {
		rps = 0
	}
	l := &Limiter{
		rps:     rps,
		burst:   1,
		tokens:  1,
		clock:   c,
		slots:   make(chan struct{}, concurrency),
		done:    make(chan struct{}),
		maxConc: concurrency,
		budget:  int64(budget),
	}
	if rps > 0 {
		l.burst = math.Max(1, rps)
		l.tokens = l.burst
	}
	l.last = c.Now()
	return l
}

// SetRPS changes the rate. A pending Wait picks the new rate up on its next
// refill step.
func (l *Limiter) SetRPS(rps float64) {
	if rps < 0 {
		rps = 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rps = rps
	if rps > 0 {
		l.burst = math.Max(1, rps)
		if l.tokens > l.burst {
			l.tokens = l.burst
		}
	} else {
		l.burst = 1
		l.tokens = 1
	}
}

// SetConcurrency changes the concurrency ceiling. Every slot currently held is
// re-homed into the new semaphore, so the change is safe while holders are
// blocked on the network: a reduce request simply stops admitting new holders
// once the current ones drain.
func (l *Limiter) SetConcurrency(n int) {
	if n <= 0 {
		n = 1
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if n == l.maxConc {
		return
	}
	// Re-home held slots into a new semaphore. Because releaseSlot reads
	// l.slots under the same mutex, no holder can release into the old
	// channel: it either reads the old one before we take the lock (and its
	// token was therefore drained above) or the new one after the swap.
	//
	// When shrinking, at most cap(newSlots) tokens can be carried over. The
	// surplus is dropped rather than blocking: those holders already exceeded
	// the new ceiling and cannot be revoked, and their later release simply
	// finds an empty channel and does nothing.
	newSlots := make(chan struct{}, n)
	carried := 0
	for carried < cap(newSlots) {
		select {
		case <-l.slots:
			newSlots <- struct{}{}
			carried++
		default:
			l.slots = newSlots
			l.maxConc = n
			return
		}
	}
	l.slots = newSlots
	l.maxConc = n
}

// Close releases waiters. It is safe to call more than once and safe to call
// while other goroutines are acquiring, because it signals through a separate
// done channel rather than closing the semaphore.
func (l *Limiter) Close() {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.closed = true
	close(l.done)
	l.mu.Unlock()
}

// Acquire consumes one unit of the request budget.
func (l *Limiter) Acquire() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return ErrClosed
	}
	if l.budget > 0 && l.budgetUsed >= l.budget {
		return ErrBudgetExhausted
	}
	l.budgetUsed++
	return nil
}

// Used returns the number of budget units consumed.
func (l *Limiter) Used() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.budgetUsed
}

// Remaining returns the unused budget, or -1 when unlimited.
func (l *Limiter) Remaining() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.budget <= 0 {
		return -1
	}
	if r := l.budget - l.budgetUsed; r > 0 {
		return r
	}
	return 0
}

// waitToken blocks until the token bucket allows the next operation.
func (l *Limiter) waitToken(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			return ErrClosed
		}
		if l.rps <= 0 {
			l.mu.Unlock()
			return nil
		}
		now := l.clock.Now()
		if l.last.IsZero() {
			l.last = now
		}
		if elapsed := now.Sub(l.last).Seconds(); elapsed > 0 {
			l.tokens += elapsed * l.rps
			if l.tokens > l.burst {
				l.tokens = l.burst
			}
			l.last = now
		}
		if l.tokens >= 1 {
			l.tokens--
			l.mu.Unlock()
			return nil
		}
		need := time.Duration((1 - l.tokens) / l.rps * float64(time.Second))
		l.mu.Unlock()

		if need < time.Millisecond {
			need = time.Millisecond
		}
		timer := time.NewTimer(need)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// waitSlot blocks until a concurrency slot is free or ctx is done.
//
// The semaphore is re-read under the lock on every attempt and re-checked after
// acquisition, so a concurrent SetConcurrency cannot strand a token in a
// retired channel.
func (l *Limiter) waitSlot(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			return ErrClosed
		}
		ch, done := l.slots, l.done
		l.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
			return ErrClosed
		case ch <- struct{}{}:
			// The semaphore may have been swapped while we were blocked.
			l.mu.Lock()
			same := l.slots == ch
			closed := l.closed
			l.mu.Unlock()
			if same {
				if closed {
					// Give the token straight back and report the close.
					select {
					case <-ch:
					default:
					}
					return ErrClosed
				}
				return nil
			}
			select {
			case <-ch:
			default:
			}
		}
	}
}

func (l *Limiter) releaseSlot() {
	l.mu.Lock()
	ch := l.slots
	l.mu.Unlock()
	select {
	case <-ch:
	default:
	}
}

// Do runs fn while holding one budget unit, one concurrency slot and one rate
// token. Slots and budget are always released, including on panic, so a
// crashing module cannot leak capacity. A panic in fn is propagated.
func (l *Limiter) Do(ctx context.Context, fn func(ctx context.Context) error) error {
	if err := l.Acquire(); err != nil {
		return err
	}
	if err := l.waitSlot(ctx); err != nil {
		return err
	}
	defer l.releaseSlot()
	if err := l.waitToken(ctx); err != nil {
		return err
	}
	return fn(ctx)
}

// AcquireSlot takes a concurrency slot without a rate-limit ticket. Long-lived
// workers (for example a crawler) use this so the whole crawl counts as one
// concurrent unit.
func (l *Limiter) AcquireSlot(ctx context.Context) error { return l.waitSlot(ctx) }

// ReleaseSlot returns a slot taken with AcquireSlot.
func (l *Limiter) ReleaseSlot() { l.releaseSlot() }

// Wait blocks until the rate limiter allows the next operation. It does not
// consume budget.
func (l *Limiter) Wait(ctx context.Context) error { return l.waitToken(ctx) }

// RPS returns the configured rate.
func (l *Limiter) RPS() float64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.rps
}

// Concurrency returns the configured concurrency ceiling.
func (l *Limiter) Concurrency() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.maxConc
}

// InFlight reports how many slots are currently held.
//
// The mutex is taken because SetConcurrency swaps l.slots while other goroutines
// hold slots; reading the field unlocked is a data race on a channel header, not
// merely a stale answer.
func (l *Limiter) InFlight() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.slots)
}

// Clone returns an independent limiter with the same settings and a fresh
// budget. Used to give a sub-scan its own budget while keeping the rate.
func (l *Limiter) Clone() *Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	return &Limiter{
		rps: l.rps, burst: l.burst, tokens: l.burst, last: l.clock.Now(), clock: l.clock,
		slots: make(chan struct{}, l.maxConc), done: make(chan struct{}), maxConc: l.maxConc, budget: l.budget,
	}
}
