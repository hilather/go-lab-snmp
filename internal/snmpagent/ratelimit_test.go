package snmpagent

import (
	"fmt"
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
