package snmpagent

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestPerIPLimiterEvictsIdleBuckets asserts the per-source datagram
// limiter drops buckets that have been idle, matching the management
// plane limiter. A spoofed UDP source must not grow the map without bound.
func TestPerIPLimiterEvictsIdleBuckets(t *testing.T) {
	now := time.Unix(0, 0)
	l := newQueryLimiter(10, 10, func() time.Time { return now })
	const n = 1000
	for i := 0; i < n; i++ {
		key := fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff)
		if !l.allow(key) {
			t.Fatalf("fresh key %d denied", i)
		}
	}
	now = now.Add(time.Hour)
	if !l.allow("192.0.2.1") {
		t.Fatal("idle window should admit a new key")
	}
	l.mu.Lock()
	got := len(l.buckets)
	l.mu.Unlock()
	if got > 2 {
		t.Fatalf("per-IP limiter kept %d idle buckets", got)
	}
	requireOrderMatchesBuckets(t, l)
}

// TestPerIPLimiterCapsDistinctSources asserts a flood of distinct sources
// inside one idle window cannot grow the bucket map past 1024. The oldest
// bucket is evicted to make room.
func TestPerIPLimiterCapsDistinctSources(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	now := start
	l := newQueryLimiter(10, 10, func() time.Time { return now })
	const n = maxQueryBuckets + 200
	for i := 0; i < n; i++ {
		now = start.Add(time.Duration(i) * time.Millisecond)
		key := sourceKey(i)
		if !l.allow(key) {
			t.Fatalf("fresh key %d denied", i)
		}
		l.mu.Lock()
		got := len(l.buckets)
		l.mu.Unlock()
		if got > maxQueryBuckets {
			t.Fatalf("per-source limiter grew to %d buckets at key %d", got, i)
		}
		requireOrderMatchesBuckets(t, l)
	}
	l.mu.Lock()
	got := len(l.buckets)
	_, oldest := l.buckets[sourceKey(0)]
	_, newest := l.buckets[sourceKey(n-1)]
	l.mu.Unlock()
	if got != maxQueryBuckets {
		t.Fatalf("per-source limiter len=%d want %d", got, maxQueryBuckets)
	}
	if oldest {
		t.Fatal("oldest bucket was kept at the cap")
	}
	if !newest {
		t.Fatal("newest bucket missing at the cap")
	}
	// The resident key keeps its own token bucket.
	for i := 0; i < 9; i++ {
		if !l.allow(sourceKey(n - 1)) {
			t.Fatalf("existing key denied inside its burst at %d", i)
		}
	}
	if l.allow(sourceKey(n - 1)) {
		t.Fatal("existing key exceeded its burst")
	}
}

// TestPerIPLimiterSweepsAtMostOncePerInterval asserts idle buckets stay
// until the sweep interval elapses. The idle window for rate 10 burst 10
// is 30s, so the interval is 30s/4.
func TestPerIPLimiterSweepsAtMostOncePerInterval(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	now := start
	l := newQueryLimiter(10, 10, func() time.Time { return now })
	if !l.allow("a") {
		t.Fatal("admit a")
	}
	const idle = 30 * time.Second
	const every = idle / 4
	now = start.Add(idle - every + time.Second) // 23.5s
	if !l.allow("b") {
		t.Fatal("admit b")
	}
	l.mu.Lock()
	_, aOK := l.buckets["a"]
	l.mu.Unlock()
	if !aOK {
		t.Fatal("setup removed a before the idle window")
	}
	sweptAt := now
	now = start.Add(idle + time.Millisecond)
	if !l.allow("c") {
		t.Fatal("admit c")
	}
	l.mu.Lock()
	_, aOK = l.buckets["a"]
	l.mu.Unlock()
	if !aOK {
		t.Fatal("idle bucket swept before the sweep interval elapsed")
	}
	now = sweptAt.Add(every)
	if !l.allow("d") {
		t.Fatal("admit d")
	}
	l.mu.Lock()
	_, aOK = l.buckets["a"]
	l.mu.Unlock()
	if aOK {
		t.Fatal("idle bucket remained after the sweep interval elapsed")
	}
	// The sweep stops at the first bucket still in the window.
	for _, k := range []string{"b", "c", "d"} {
		if !hasBucket(l, k) {
			t.Fatalf("sweep removed non-idle bucket %q", k)
		}
	}
	requireOrderMatchesBuckets(t, l)
}

// TestPerIPLimiterCountsSweepsOncePerInterval counts idle scans. A burst
// of allows inside one interval must scan once.
func TestPerIPLimiterCountsSweepsOncePerInterval(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	now := start
	l := newQueryLimiter(10, 10, func() time.Time { return now })
	const n = 100
	for i := 0; i < n; i++ {
		if !l.allow(fmt.Sprintf("k%d", i)) {
			t.Fatalf("fresh key %d denied", i)
		}
	}
	l.mu.Lock()
	got := l.sweeps
	l.mu.Unlock()
	if got != 1 {
		t.Fatalf("idle sweep ran %d times in one interval, want 1", got)
	}
	const every = 30 * time.Second / 4
	now = start.Add(every - time.Millisecond)
	if !l.allow("later") {
		t.Fatal("admit later")
	}
	l.mu.Lock()
	got = l.sweeps
	l.mu.Unlock()
	if got != 1 {
		t.Fatalf("idle sweep ran %d times before the interval elapsed, want 1", got)
	}
	now = start.Add(every)
	if !l.allow("due") {
		t.Fatal("admit due")
	}
	l.mu.Lock()
	got = l.sweeps
	l.mu.Unlock()
	if got != 2 {
		t.Fatalf("idle sweep ran %d times after the interval, want 2", got)
	}
}

// TestNewQueryLimiterZeroRateLimits locks the pre-branch fail-safe:
// a non-positive rate is 1/s, not a nil limiter. Nil allow is unlimited,
// and setRate returns immediately on nil.
func TestNewQueryLimiterZeroRateLimits(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newQueryLimiter(0, 0, func() time.Time { return now })
	if l == nil {
		t.Fatal("newQueryLimiter(0, 0) returned nil (unlimited)")
	}
	if !l.allow("10.0.0.1") {
		t.Fatal("zero rate denied the first datagram; want 1/s")
	}
	if l.allow("10.0.0.1") {
		t.Fatal("zero rate allowed a second datagram in the same instant")
	}
	l.setRate(2, 2)
	if !l.allow("10.0.0.2") {
		t.Fatal("setRate did not admit the first datagram of the updated burst")
	}
	if !l.allow("10.0.0.2") {
		t.Fatal("setRate did not admit the second datagram of the updated burst")
	}
	if l.allow("10.0.0.2") {
		t.Fatal("setRate left the limiter above the updated burst")
	}
}

func TestSweepIntervalFloor(t *testing.T) {
	if got := sweepGap(2 * time.Second); got != time.Second {
		t.Fatalf("sweep floor = %s, want 1s", got)
	}
	if got := sweepGap(30 * time.Second); got != 30*time.Second/4 {
		t.Fatalf("sweep quarter = %s, want %s", got, 30*time.Second/4)
	}
	l := newQueryLimiter(10, 10, time.Now)
	if got := l.sweepInterval(); got != 30*time.Second/4 {
		t.Fatalf("limiter sweep interval = %s, want %s", got, 30*time.Second/4)
	}
	if maxQueryBuckets != 1024 {
		t.Fatalf("maxQueryBuckets = %d, want 1024", maxQueryBuckets)
	}
}

func sourceKey(i int) string {
	return fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff)
}

// requireOrderMatchesBuckets checks that the eviction list holds exactly the
// map's buckets, ordered by last (front newest).
func requireOrderMatchesBuckets(t *testing.T, l *queryLimiter) {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.order.Len() != len(l.buckets) {
		t.Fatalf("order len=%d buckets=%d", l.order.Len(), len(l.buckets))
	}
	var newer time.Time
	for e := l.order.Front(); e != nil; e = e.Next() {
		b := e.Value.(*qbucket)
		if l.buckets[b.key] != b || b.elem != e {
			t.Fatalf("order element for %q is not the map bucket", b.key)
		}
		if !newer.IsZero() && b.last.After(newer) {
			t.Fatalf("order not sorted by last at %q", b.key)
		}
		newer = b.last
	}
}

// fillToCap inserts maxQueryBuckets keys 1ms apart (about 1s, inside one
// sweep interval at rate 10), advancing *now.
func fillToCap(t *testing.T, l *queryLimiter, now *time.Time, start time.Time) {
	t.Helper()
	for i := 0; i < maxQueryBuckets; i++ {
		*now = start.Add(time.Duration(i) * time.Millisecond)
		if !l.allow(sourceKey(i)) {
			t.Fatalf("fresh key %d denied", i)
		}
	}
}

func hasBucket(l *queryLimiter, key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.buckets[key]
	return ok
}

// TestEvictOldestFollowsLastRefill pins which bucket goes at the cap: the
// oldest last-allow time. A key refilled later (allowed or denied) moves
// up; a key touched again at the same instant does not.
func TestEvictOldestFollowsLastRefill(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	end := start.Add(time.Duration(maxQueryBuckets-1) * time.Millisecond)
	newKey := "192.0.2.200"

	t.Run("refreshed key kept", func(t *testing.T) {
		now := start
		l := newQueryLimiter(10, 10, func() time.Time { return now })
		fillToCap(t, l, &now, start)
		now = end.Add(5 * time.Millisecond)
		l.allow(sourceKey(0))
		now = now.Add(time.Millisecond)
		l.allow(newKey)
		if !hasBucket(l, sourceKey(0)) || hasBucket(l, sourceKey(1)) || !hasBucket(l, newKey) {
			t.Fatal("want key 1 evicted, key 0 and the new key kept")
		}
		requireLenAndNewKey(t, l, newKey)
		requireOrderMatchesBuckets(t, l)
	})

	t.Run("denied refill still moves", func(t *testing.T) {
		// Rate 0.5/s, burst 1: about 1s later key 0 has refilled half a
		// token, so its next allow is denied but its last advances.
		now := start
		l := newQueryLimiter(0.5, 1, func() time.Time { return now })
		fillToCap(t, l, &now, start)
		now = end.Add(5 * time.Millisecond)
		if l.allow(sourceKey(0)) {
			t.Fatal("key 0 should be denied after a partial refill")
		}
		now = now.Add(time.Millisecond)
		l.allow(newKey)
		if !hasBucket(l, sourceKey(0)) || hasBucket(l, sourceKey(1)) {
			t.Fatal("a denied key whose last advanced must not be the eviction victim")
		}
		requireLenAndNewKey(t, l, newKey)
		requireOrderMatchesBuckets(t, l)
	})

	t.Run("same instant does not move", func(t *testing.T) {
		now := start
		l := newQueryLimiter(10, 10, func() time.Time { return now })
		fillToCap(t, l, &now, start)
		now = start // key 0's own timestamp: elapsed == 0
		l.allow(sourceKey(0))
		now = end.Add(time.Millisecond)
		l.allow(newKey)
		if hasBucket(l, sourceKey(0)) || !hasBucket(l, sourceKey(1)) {
			t.Fatal("key 0 touched at its own last must still be the oldest")
		}
		requireLenAndNewKey(t, l, newKey)
		requireOrderMatchesBuckets(t, l)
	})
}

// BenchmarkAllowNewKeyFullMap measures allow for a new source once the map
// holds maxQueryBuckets buckets: every op evicts one bucket. The fake clock
// advances 1µs per op, so the idle sweep stays out of the timed loop.
func BenchmarkAllowNewKeyFullMap(b *testing.B) {
	now := time.Unix(0, 0)
	l := newQueryLimiter(1e6, 1e6, func() time.Time { return now })
	for i := 0; i < maxQueryBuckets; i++ {
		l.allow(fmt.Sprintf("k%d", i))
	}
	keys := make([]string, b.N)
	for i := range keys {
		keys[i] = fmt.Sprintf("n%d", i)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		now = now.Add(time.Microsecond)
		l.allow(keys[i])
	}
}

// TestAllowSamplesClockUnderLock pins that concurrent allows commit their
// timestamps in clock order: a second allow must not read the clock while
// the first is still inside it, or an older last could land in front.
func TestAllowSamplesClockUnderLock(t *testing.T) {
	t1 := time.Unix(1_700_000_000, 0)
	t2 := t1.Add(time.Second)
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	var firstInside, overlapped atomic.Bool
	l := newQueryLimiter(10, 10, func() time.Time {
		if calls.Add(1) == 1 {
			firstInside.Store(true)
			close(entered)
			<-release
			firstInside.Store(false)
			return t1
		}
		if firstInside.Load() {
			overlapped.Store(true)
		}
		return t2
	})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); l.allow("a") }()
	<-entered
	started := make(chan struct{})
	go func() { defer wg.Done(); close(started); l.allow("b") }()
	<-started
	// With the clock read outside the lock, the second allow reaches the
	// clock within this window; under the lock it waits on l.mu.
	for deadline := time.Now().Add(200 * time.Millisecond); time.Now().Before(deadline) && calls.Load() < 2; {
		time.Sleep(time.Millisecond)
	}
	close(release)
	wg.Wait()
	if overlapped.Load() {
		t.Fatal("second allow read the clock while the first was inside it")
	}
	l.mu.Lock()
	back := l.order.Back().Value.(*qbucket)
	l.mu.Unlock()
	if back.key != "a" || !back.last.Equal(t1) {
		t.Fatalf("back bucket = %q at %v; want a at %v", back.key, back.last, t1)
	}
	requireOrderMatchesBuckets(t, l)
}

func requireLenAndNewKey(t *testing.T, l *queryLimiter, newKey string) {
	t.Helper()
	l.mu.Lock()
	n := len(l.buckets)
	l.mu.Unlock()
	if n != maxQueryBuckets {
		t.Fatalf("len=%d want %d", n, maxQueryBuckets)
	}
	if !hasBucket(l, newKey) {
		t.Fatalf("new key %q missing", newKey)
	}
}
