package snmpsink

import (
	"fmt"
	"testing"
	"time"
)

// TestPerIPLimiterEvictsIdleBuckets asserts the trap per-source datagram
// limiter drops buckets that have been idle, matching the agent limiter.
func TestPerIPLimiterEvictsIdleBuckets(t *testing.T) {
	now := time.Unix(0, 0)
	l := newQueryLimiter(10, 10, func() time.Time { return now })
	if l == nil {
		t.Fatal("newQueryLimiter(10, 10) is nil")
	}
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
