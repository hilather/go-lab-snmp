package snmpagent

import (
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hilather/go-lab-snmp/internal/snmptest"
	"github.com/hilather/go-lab-snmp/internal/snmpwire"
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

// TestSoakGETNEXTAndSET walks GETNEXT and overlays SET for the GA soak.
func TestSoakGETNEXTAndSET(t *testing.T) {
	d := soakDuration(t)
	s := startAgent(t, loadYAML(t, rwYAML, nil))
	addr := dst(s)
	deadline := time.Now().Add(d)

	var walks, sets, gets, bad, order atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(id int32) {
			defer wg.Done()
			reqID := id * 1000
			for time.Now().Before(deadline) {
				reqID++
				cur := oid(1, 3)
				var prev snmpwire.OID
				ok := true
				for step := 0; step < 16; step++ {
					req, err := snmptest.EncodeGetNext(snmpwire.VersionV2c, "public", reqID, cur)
					if err != nil {
						bad.Add(1)
						ok = false
						break
					}
					raw, err := snmptest.Exchange(addr, req, 500*time.Millisecond)
					if err != nil {
						bad.Add(1)
						ok = false
						break
					}
					m, err := snmpwire.Decode(raw)
					if err != nil {
						bad.Add(1)
						ok = false
						break
					}
					p := m.RequestPDU()
					if p == nil || len(p.VarBinds) != 1 {
						bad.Add(1)
						ok = false
						break
					}
					if p.VarBinds[0].Value.Type == snmpwire.TypeEndOfMibView {
						break
					}
					next := p.VarBinds[0].Name
					if prev != nil && !oidLess(prev, next) {
						order.Add(1)
						ok = false
						break
					}
					prev = next
					cur = next
					reqID++
				}
				if ok {
					walks.Add(1)
				}
			}
		}(int32(i + 1))
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		reqID := int32(9000)
		val := int64(1)
		for time.Now().Before(deadline) {
			reqID++
			if val == 1 {
				val = 2
			} else {
				val = 1
			}
			req, err := snmptest.EncodeSet(snmpwire.VersionV2c, "private", reqID, []snmpwire.VarBind{{
				Name:  ifOper(),
				Value: snmpwire.Int(val),
			}})
			if err != nil {
				bad.Add(1)
				continue
			}
			raw, err := snmptest.Exchange(addr, req, 500*time.Millisecond)
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
			if p == nil || p.ErrorStatus != snmpwire.ErrorStatusNoError {
				bad.Add(1)
				continue
			}
			sets.Add(1)
			getReq, err := snmptest.EncodeGet(snmpwire.VersionV2c, "private", reqID+10000, ifOper())
			if err != nil {
				bad.Add(1)
				continue
			}
			gotRaw, err := snmptest.Exchange(addr, getReq, 500*time.Millisecond)
			if err != nil {
				bad.Add(1)
				continue
			}
			got, err := snmpwire.Decode(gotRaw)
			if err != nil {
				bad.Add(1)
				continue
			}
			gp := got.RequestPDU()
			if gp == nil || len(gp.VarBinds) == 0 || gp.VarBinds[0].Value.Int != val {
				bad.Add(1)
				continue
			}
			gets.Add(1)
		}
	}()

	wg.Wait()
	if order.Load() > 0 {
		t.Fatalf("GETNEXT order regressions=%d", order.Load())
	}
	if walks.Load() < 1 || sets.Load() < 1 || gets.Load() < 1 {
		t.Fatalf("soak under-ran walks=%d sets=%d gets=%d bad=%d dur=%s", walks.Load(), sets.Load(), gets.Load(), bad.Load(), d)
	}
	if n := bad.Load(); n > walks.Load()/2 {
		t.Fatalf("too many soak errors: bad=%d walks=%d sets=%d", n, walks.Load(), sets.Load())
	}
	t.Logf("soak GETNEXT+SET dur=%s walks=%d sets=%d gets=%d bad=%d", d, walks.Load(), sets.Load(), gets.Load(), bad.Load())
}

func oidLess(a, b snmpwire.OID) bool {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}
