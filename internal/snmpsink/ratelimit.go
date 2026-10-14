package snmpsink

import (
	"container/list"
	"sync"
	"time"
)

type queryLimiter struct {
	rate  float64
	burst float64
	now   func() time.Time

	mu      sync.Mutex
	buckets map[string]*qbucket
	// order holds every bucket, most recent last-allow time at the front,
	// so eviction and the idle sweep start from the back.
	order     *list.List
	lastSweep time.Time
	sweeps    int
}

type qbucket struct {
	tokens float64
	last   time.Time
	key    string
	elem   *list.Element
}

// maxQueryBuckets matches DefaultMaxInflight and the regression ceiling.
const maxQueryBuckets = 1024

func newQueryLimiter(rate, burst float64, now func() time.Time) *queryLimiter {
	if now == nil {
		now = time.Now
	}
	if rate <= 0 {
		return nil
	}
	if burst <= 0 {
		burst = rate
	}
	return &queryLimiter{rate: rate, burst: burst, now: now, buckets: map[string]*qbucket{}, order: list.New()}
}

func (l *queryLimiter) setRate(rate, burst float64) {
	if l == nil {
		return
	}
	if rate <= 0 {
		rate = 1
	}
	if burst <= 0 {
		burst = rate
	}
	l.mu.Lock()
	l.rate = rate
	l.burst = burst
	l.mu.Unlock()
}

func (l *queryLimiter) allow(key string) bool {
	if l == nil {
		return true
	}
	if key == "" {
		key = "unknown"
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	// Sample the clock under the lock: concurrent handlers then commit
	// timestamps in order, which keeps order sorted by last.
	now := l.now()
	l.evictIdleLocked(now)
	b := l.buckets[key]
	if b == nil {
		if len(l.buckets) >= maxQueryBuckets {
			l.evictOldestLocked()
		}
		b = &qbucket{tokens: l.burst, last: now, key: key}
		b.elem = l.order.PushFront(b)
		l.buckets[key] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * l.rate
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.last = now
		// Move only when last advances, denied or not, so the list stays
		// ordered by last.
		l.order.MoveToFront(b.elem)
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// idleFor is the management idle window: 30s, or four burst-refill
// intervals when that is longer.
func (l *queryLimiter) idleFor() time.Duration {
	idleFor := 30 * time.Second
	if l != nil && l.rate > 0 {
		refill := time.Duration(float64(time.Second) * (l.burst / l.rate) * 4)
		if refill > idleFor {
			idleFor = refill
		}
	}
	return idleFor
}

// sweepGap is how often an idle scan may run: the idle window divided
// by four, and at least one second.
func sweepGap(idle time.Duration) time.Duration {
	every := idle / 4
	if every < time.Second {
		return time.Second
	}
	return every
}

func (l *queryLimiter) sweepInterval() time.Duration {
	if l == nil {
		return time.Second
	}
	return sweepGap(l.idleFor())
}

// evictIdleLocked drops buckets idle longer than the management window.
// The scan runs at most once per sweep interval.
func (l *queryLimiter) evictIdleLocked(now time.Time) {
	if l == nil {
		return
	}
	if !l.lastSweep.IsZero() && now.Sub(l.lastSweep) < l.sweepInterval() {
		return
	}
	l.lastSweep = now
	l.sweeps++
	if len(l.buckets) == 0 {
		return
	}
	idleFor := l.idleFor()
	// The back holds the oldest last; stop at the first bucket still in
	// the window, since every bucket in front of it is newer.
	for e := l.order.Back(); e != nil; {
		b := e.Value.(*qbucket)
		if now.Sub(b.last) <= idleFor {
			break
		}
		prev := e.Prev()
		l.order.Remove(e)
		delete(l.buckets, b.key)
		e = prev
	}
}

// evictOldestLocked drops the bucket at the back of order, the oldest
// last-allow time, so a new key can be inserted without passing
// maxQueryBuckets. Constant time. Ties on last go to the bucket least
// recently inserted or moved. This matches a scan for the minimum last
// while the clock only moves forward (allow samples it under l.mu, so
// concurrent callers commit in order). After a backward clock step
// a different old bucket may go, and idle buckets in front of a newer one
// stay until they reach the back; the cap still holds. Production clocks
// are monotonic.
func (l *queryLimiter) evictOldestLocked() {
	e := l.order.Back()
	if e == nil {
		return
	}
	b := e.Value.(*qbucket)
	l.order.Remove(e)
	delete(l.buckets, b.key)
}
