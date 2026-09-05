package snapshot

import (
	"net/netip"
	"time"

	"github.com/hilather/go-lab-snmp/internal/config"
	"github.com/hilather/go-lab-snmp/internal/mibtree"
	"github.com/hilather/go-lab-snmp/internal/model"
	"github.com/hilather/go-lab-snmp/internal/usm"
)

// Clock is an injectable time source. Tests use testutil.FakeClock.
type Clock interface {
	Now() time.Time
}

// Community is a compiled v1/v2c identity. Name is the DNS-label row id;
// Wire is the trimmed communityFile contents used on the wire.
type Community struct {
	Name     string
	Wire     []byte
	Versions map[string]bool
	Access   string
	Map      string
}

// Snapshot is immutable after Compile returns. Overlay, traps, and the
// query ring are process-local and live in store, not here.
type Snapshot struct {
	Canonical         *model.State
	Revision          model.Revision
	BootstrapRevision model.Revision
	Generation        model.Generation
	CompiledAt        time.Time
	Warnings          []config.Warning

	AgentAddress      string
	TrapAddress       string
	ManagementAddress string
	RESTPath          string
	MCPPath           string
	AgentEnabled      bool
	TrapsEnabled      bool

	Maps        map[string]*mibtree.Tree
	Communities map[string]*Community // keyed by wire community string
	Engine      *usm.Engine

	UptimeEpoch time.Time
	Clock       Clock

	Allow           []netip.Prefix
	MaxPerSec       int
	MaxPerIP        int
	MaxVarBinds     int
	MaxRepetitions  int
	MaxMessageBytes int64
	Versions        map[string]bool

	AcceptUnauthenticated bool
	RawRetain             bool
}

// Drifted reports whether the live revision differs from bootstrap.
func (s *Snapshot) Drifted() bool {
	if s == nil {
		return false
	}
	return s.Revision != "" && s.BootstrapRevision != "" && s.Revision != s.BootstrapRevision
}

// Spec is the compiled canonical spec, or a zero spec.
func (s *Snapshot) Spec() model.Spec {
	if s == nil || s.Canonical == nil {
		return model.Spec{}
	}
	return s.Canonical.Spec
}

// VersionOK reports whether SNMP version label is in the compiled set.
func (s *Snapshot) VersionOK(label string) bool {
	if s == nil || len(s.Versions) == 0 {
		return true
	}
	return s.Versions[label]
}

// Allowed reports whether unmapped ip is in allowClientCidrs.
// An empty allow list admits loopback only (docs/04 omitted default).
func (s *Snapshot) Allowed(ip netip.Addr) bool {
	if s == nil {
		return false
	}
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	if len(s.Allow) == 0 {
		return ip.IsLoopback()
	}
	for _, p := range s.Allow {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// LookupCommunity returns the compiled community for a wire string.
func (s *Snapshot) LookupCommunity(wire []byte) *Community {
	if s == nil {
		return nil
	}
	return s.Communities[string(wire)]
}

// UptimeTicks is hundredths of a second since UptimeEpoch.
func (s *Snapshot) UptimeTicks() uint32 {
	if s == nil || s.Clock == nil {
		return 0
	}
	d := s.Clock.Now().Sub(s.UptimeEpoch)
	if d < 0 {
		d = 0
	}
	return uint32(uint64(d / (10 * time.Millisecond)))
}
