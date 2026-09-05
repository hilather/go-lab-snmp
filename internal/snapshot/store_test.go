package snapshot

import (
	"net/netip"
	"testing"
)

func TestStoreSwap(t *testing.T) {
	st := NewStore()
	if st.Load() != nil {
		t.Fatal("empty")
	}
	a := &Snapshot{Generation: 1}
	b := &Snapshot{Generation: 2}
	st.InstallBootstrap(a)
	if st.Load() != a || st.Bootstrap() != a {
		t.Fatal("bootstrap")
	}
	prev := st.Swap(b)
	if prev != a || st.Load() != b || st.Previous() != a {
		t.Fatal("swap")
	}
}

func TestAllowedLoopbackWhenEmpty(t *testing.T) {
	s := &Snapshot{}
	if !s.Allowed(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("loopback")
	}
	if s.Allowed(netip.MustParseAddr("10.0.0.1")) {
		t.Fatal("non-loopback")
	}
}
