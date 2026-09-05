package testutil

import (
	"sync"
	"testing"
	"time"
)

func TestFakeClockAdvance(t *testing.T) {
	start := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	c := NewFakeClock(start)
	if !c.Now().Equal(start) {
		t.Fatal("now")
	}
	c.Advance(10 * time.Second)
	if c.Now().Sub(start) != 10*time.Second {
		t.Fatal("advance")
	}
	c.Set(start)
	if !c.Now().Equal(start) {
		t.Fatal("set")
	}
}

func TestFakeClockConcurrent(t *testing.T) {
	c := NewFakeClock(time.Unix(0, 0).UTC())
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				c.Advance(time.Millisecond)
				_ = c.Now()
			}
		}()
	}
	wg.Wait()
	if c.Now().Before(time.Unix(0, 0).UTC()) {
		t.Fatal("clock went backwards")
	}
}
