package snmpagent

import (
	"net/netip"
	"time"

	"github.com/hilather/go-lab-snmp/internal/mibtree"
	"github.com/hilather/go-lab-snmp/internal/model"
	"github.com/hilather/go-lab-snmp/internal/snapshot"
	"github.com/hilather/go-lab-snmp/internal/store"
	"github.com/hilather/go-lab-snmp/internal/usm"
)

// Clock is an injectable time source. Tests use testutil.FakeClock.
type Clock = snapshot.Clock

// Community is a compiled v1/v2c identity (snapshot.Community).
type Community = snapshot.Community

// Runtime is one packet's view of the compiled snapshot plus process-local
// overlay and query ring. Compile lives in compiler; this is not a second path.
type Runtime struct {
	Maps            map[string]*mibtree.Tree
	Communities     map[string]*Community
	Engine          *usm.Engine
	Overlay         *store.Overlay
	Queries         *store.QueryRing
	UptimeEpoch     time.Time
	Clock           Clock
	Allow           []netip.Prefix
	MaxPerSec       int
	MaxPerIP        int
	MaxVarBinds     int
	MaxRepetitions  int
	MaxMessageBytes int64
	Versions        map[string]bool
}

func viewOf(snap *snapshot.Snapshot, overlay *store.Overlay, queries *store.QueryRing, clk Clock) *Runtime {
	if snap == nil {
		return nil
	}
	if clk == nil {
		clk = snap.Clock
	}
	ov := overlay
	if ov == nil {
		ov = store.NewOverlay()
	}
	q := queries
	if q == nil {
		q = store.NewQueryRing(store.DefaultQueryRing)
	}
	return &Runtime{
		Maps:            snap.Maps,
		Communities:     snap.Communities,
		Engine:          snap.Engine,
		Overlay:         ov,
		Queries:         q,
		UptimeEpoch:     snap.UptimeEpoch,
		Clock:           clk,
		Allow:           snap.Allow,
		MaxPerSec:       snap.MaxPerSec,
		MaxPerIP:        snap.MaxPerIP,
		MaxVarBinds:     snap.MaxVarBinds,
		MaxRepetitions:  snap.MaxRepetitions,
		MaxMessageBytes: snap.MaxMessageBytes,
		Versions:        snap.Versions,
	}
}

func (rt *Runtime) uptimeTicks() uint32 {
	if rt == nil || rt.Clock == nil {
		return 0
	}
	d := rt.Clock.Now().Sub(rt.UptimeEpoch)
	if d < 0 {
		d = 0
	}
	return uint32(uint64(d / (10 * time.Millisecond)))
}

func (rt *Runtime) get(mapName string, oid mibtree.OID) mibtree.Result {
	tree := rt.Maps[mapName]
	res := tree.Get(oid)
	if res.Exception != mibtree.NoException {
		return res
	}
	if res.Value.ValueFrom == model.ValueFromUptime {
		res.Value = mibtree.Value{Type: model.TypeTimeTicks, Unsigned: uint64(rt.uptimeTicks()), ValueFrom: model.ValueFromUptime}
		return res
	}
	if ov, ok := rt.Overlay.Get(mapName, res.OID.String()); ok {
		res.Value = ov
	}
	return res
}

func (rt *Runtime) getNext(mapName string, oid mibtree.OID) mibtree.Result {
	tree := rt.Maps[mapName]
	res := tree.GetNext(oid)
	if res.Exception != mibtree.NoException {
		return res
	}
	return rt.get(mapName, res.OID)
}

func (rt *Runtime) lookupCommunity(wire []byte) *Community {
	if rt == nil {
		return nil
	}
	return rt.Communities[string(wire)]
}

func (rt *Runtime) versionOK(label string) bool {
	if rt == nil || len(rt.Versions) == 0 {
		return true
	}
	return rt.Versions[label]
}

func (rt *Runtime) record(typ, identity, decision string, status int32) {
	if rt == nil || rt.Queries == nil {
		return
	}
	rt.Queries.Insert(store.Query{
		Type:        typ,
		Identity:    identity,
		Decision:    decision,
		ErrorStatus: status,
	})
}
