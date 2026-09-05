package snmpsink

import (
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hilather/go-lab-snmp/internal/snmptest"
	"github.com/hilather/go-lab-snmp/internal/snmpwire"
	"github.com/hilather/go-lab-snmp/internal/store"
)

func soakDuration(t *testing.T) time.Duration {
	t.Helper()
	d := 2 * time.Second
	if env := os.Getenv("LABSNMP_SOAK_DURATION"); env != "" {
		parsed, err := time.ParseDuration(env)
		if err != nil {
			t.Fatalf("LABSNMP_SOAK_DURATION: %v", err)
		}
		d = parsed
	}
	if testing.Short() && d > 500*time.Millisecond {
		d = 500 * time.Millisecond
	}
	if d < 50*time.Millisecond {
		d = 50 * time.Millisecond
	}
	return d
}

// TestSoakTrapCapsHold inserts traps/informs until the ring cap holds.
func TestSoakTrapCapsHold(t *testing.T) {
	d := soakDuration(t)
	const maxMessages = 32
	ring := store.NewTrapRing(store.TrapPolicy{
		MaxMessages: maxMessages,
		MaxBytes:    1 << 20,
		FullPolicy:  "evict_oldest",
		MaxWait:     time.Second,
	})
	s := startSink(t, Config{Store: ring, MaxPerSec: 10000, MaxPerIP: 5000})
	addr := dst(s)
	deadline := time.Now().Add(d)

	var traps, informs, bad atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(id int32) {
			defer wg.Done()
			reqID := id * 1000
			for time.Now().Before(deadline) {
				reqID++
				pkt, err := snmptest.EncodeTrapV2("public", reqID, coldStart())
				if err != nil {
					bad.Add(1)
					continue
				}
				if err := snmptest.Send(addr, pkt); err != nil {
					bad.Add(1)
					continue
				}
				traps.Add(1)
			}
		}(int32(i + 1))
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		reqID := int32(8000)
		for time.Now().Before(deadline) {
			reqID++
			pkt, err := snmptest.EncodeInform("public", reqID, coldStart())
			if err != nil {
				bad.Add(1)
				continue
			}
			raw, err := snmptest.Exchange(addr, pkt, 500*time.Millisecond)
			if err != nil {
				bad.Add(1)
				continue
			}
			m, err := snmpwire.Decode(raw)
			if err != nil {
				bad.Add(1)
				continue
			}
			p := m.RequestPDU()
			if p == nil || p.Type != snmpwire.PDUResponse || p.RequestID != reqID {
				bad.Add(1)
				continue
			}
			informs.Add(1)
		}
	}()
	wg.Wait()

	deadlineDrain := time.Now().Add(time.Second)
	for time.Now().Before(deadlineDrain) {
		if ring.Stats().Messages > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	st := ring.Stats()
	if st.Messages > maxMessages {
		t.Fatalf("trap ring over cap: messages=%d max=%d", st.Messages, maxMessages)
	}
	if traps.Load() < 1 || informs.Load() < 1 {
		t.Fatalf("soak under-ran traps=%d informs=%d bad=%d", traps.Load(), informs.Load(), bad.Load())
	}
	if traps.Load() >= int64(maxMessages) && st.Messages > maxMessages {
		t.Fatalf("cap failed after %d traps: %+v", traps.Load(), st)
	}
	t.Logf("soak trap dur=%s traps=%d informs=%d messages=%d dropped=%d bad=%d", d, traps.Load(), informs.Load(), st.Messages, st.Dropped, bad.Load())
}
