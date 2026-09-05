package snmpagent

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"net/netip"

	"github.com/hilather/go-lab-snmp/internal/config"
	"github.com/hilather/go-lab-snmp/internal/mibtree"
	"github.com/hilather/go-lab-snmp/internal/model"
	"github.com/hilather/go-lab-snmp/internal/store"
	"github.com/hilather/go-lab-snmp/internal/usm"
)

// Clock is an injectable time source. Tests use testutil.FakeClock.
type Clock interface {
	Now() time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

type clockAdapter struct{ Clock }

func (c clockAdapter) Now() time.Time {
	if c.Clock == nil {
		return time.Now()
	}
	return c.Clock.Now()
}

// LoadOptions tunes hand-wire compilation. Clock nil uses the process clock.
type LoadOptions struct {
	BaseDir string
	Clock   Clock
	Overlay *store.Overlay
	Queries *store.QueryRing
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

// Runtime is the AGENT-001 hand-wire of maps, identities, overlay, and USM.
type Runtime struct {
	Maps            map[string]*mibtree.Tree
	Communities     map[string]*Community // keyed by wire community string
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

// LoadFile is Decode/Normalize/Validate then Load.
func LoadFile(path string, opts LoadOptions) (*Runtime, error) {
	st, err := config.LoadFile(path)
	if err != nil {
		return nil, err
	}
	if opts.BaseDir == "" {
		opts.BaseDir = filepath.Dir(path)
	}
	return Load(st, opts)
}

// Load compiles maps, localizes USM users, and reads community files.
func Load(st *model.State, opts LoadOptions) (*Runtime, error) {
	if st == nil {
		return nil, fmt.Errorf("snmpagent: nil state")
	}
	clk := opts.Clock
	if clk == nil {
		clk = systemClock{}
	}
	ov := opts.Overlay
	if ov == nil {
		ov = store.NewOverlay()
	}
	q := opts.Queries
	if q == nil {
		q = store.NewQueryRing(store.DefaultQueryRing)
	}

	maps := make(map[string]*mibtree.Tree, len(st.Spec.Maps))
	maxRep := st.Spec.Agent.MaxRepetitions
	if maxRep < 1 {
		maxRep = mibtree.DefaultMaxRepetitions
	}
	for _, m := range st.Spec.Maps {
		tree, err := mibtree.Compile(m.Objects)
		if err != nil {
			return nil, err
		}
		tree.SetMaxRepetitions(maxRep)
		maps[m.Name] = tree
	}

	comms := make(map[string]*Community, len(st.Spec.Communities))
	for _, c := range st.Spec.Communities {
		wire, err := readTrimmed(c.CommunityFile, opts.BaseDir)
		if err != nil {
			return nil, fmt.Errorf("snmpagent: community %q: %w", c.Name, err)
		}
		vers := make(map[string]bool, len(c.Versions))
		for _, v := range c.Versions {
			vers[v] = true
		}
		access := c.Access
		if access == "" {
			access = model.AccessRead
		}
		cc := &Community{
			Name:     c.Name,
			Wire:     wire,
			Versions: vers,
			Access:   access,
			Map:      c.Map,
		}
		comms[string(wire)] = cc
	}

	eng, err := usm.New(usm.Config{
		EngineIDHex: st.Spec.Engine.EngineID,
		EngineBoots: int32(st.Spec.Engine.EngineBoots),
		Clock:       clockAdapter{clk},
	})
	if err != nil {
		return nil, err
	}
	for _, u := range st.Spec.Users {
		cfg := usm.UserConfig{
			Name:   u.Name,
			Level:  u.Level,
			Access: u.Access,
			Map:    u.Map,
		}
		if u.Auth != nil {
			cfg.AuthProtocol = u.Auth.Protocol
			pass, err := readTrimmed(u.Auth.SecretFile, opts.BaseDir)
			if err != nil {
				return nil, fmt.Errorf("snmpagent: user %q auth: %w", u.Name, err)
			}
			cfg.AuthPassphrase = pass
		}
		if u.Priv != nil {
			cfg.PrivProtocol = u.Priv.Protocol
			pass, err := readTrimmed(u.Priv.SecretFile, opts.BaseDir)
			if err != nil {
				return nil, fmt.Errorf("snmpagent: user %q priv: %w", u.Name, err)
			}
			cfg.PrivPassphrase = pass
		}
		if err := eng.AddUser(cfg); err != nil {
			return nil, err
		}
	}

	allow := make([]netip.Prefix, 0, len(st.Spec.Admission.AllowClientCidrs))
	for _, s := range st.Spec.Admission.AllowClientCidrs {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("snmpagent: CIDR %q: %w", s, err)
		}
		allow = append(allow, p)
	}

	vers := make(map[string]bool, len(st.Spec.Agent.Versions))
	for _, v := range st.Spec.Agent.Versions {
		vers[v] = true
	}

	maxVB := st.Spec.Agent.MaxVarBinds
	if maxVB < 1 {
		maxVB = config.DefaultMaxVarBinds
	}
	maxMsg := st.Spec.Agent.MaxMessageBytes
	if maxMsg < 1 {
		maxMsg = config.DefaultMaxMessageBytes
	}
	maxSec := st.Spec.Admission.MaxDatagramsPerSec
	if maxSec < 1 {
		maxSec = config.DefaultMaxDatagramsPerSec
	}
	maxIP := st.Spec.Admission.MaxDatagramsPerIP
	if maxIP < 1 {
		maxIP = config.DefaultMaxDatagramsPerIP
	}

	return &Runtime{
		Maps:            maps,
		Communities:     comms,
		Engine:          eng,
		Overlay:         ov,
		Queries:         q,
		UptimeEpoch:     clk.Now(),
		Clock:           clk,
		Allow:           allow,
		MaxPerSec:       maxSec,
		MaxPerIP:        maxIP,
		MaxVarBinds:     maxVB,
		MaxRepetitions:  maxRep,
		MaxMessageBytes: maxMsg,
		Versions:        vers,
	}, nil
}

func readTrimmed(path, baseDir string) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, os.ErrNotExist
	}
	candidates := []string{path}
	if !filepath.IsAbs(path) && baseDir != "" {
		rel := filepath.Join(baseDir, path)
		if rel != path {
			candidates = append(candidates, rel)
		}
	}
	var first error
	for _, c := range candidates {
		b, err := os.ReadFile(c)
		if err == nil {
			return bytes.TrimSpace(b), nil
		}
		if first == nil {
			first = err
		}
	}
	return nil, first
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
