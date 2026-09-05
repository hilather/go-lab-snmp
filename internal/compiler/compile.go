package compiler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hilather/go-lab-snmp/internal/config"
	"github.com/hilather/go-lab-snmp/internal/domainerr"
	"github.com/hilather/go-lab-snmp/internal/mibtree"
	"github.com/hilather/go-lab-snmp/internal/model"
	"github.com/hilather/go-lab-snmp/internal/snapshot"
	"github.com/hilather/go-lab-snmp/internal/testutil"
	"github.com/hilather/go-lab-snmp/internal/usm"
)

// CompileOpts controls revision metadata, secret path resolution, and the compile clock.
type CompileOpts struct {
	Clock             testutil.Clock
	BaseDir           string
	BootstrapRevision model.Revision
	Generation        model.Generation
	Previous          *snapshot.Snapshot
}

type clockAdapter struct{ testutil.Clock }

func (c clockAdapter) Now() time.Time {
	if c.Clock == nil {
		return time.Now()
	}
	return c.Clock.Now()
}

// Compile normalizes and validates st, compiles map trees, localizes USM
// keys, and returns an immutable Snapshot. Overlay is not compiled.
func Compile(st *model.State, opts CompileOpts) (*snapshot.Snapshot, error) {
	n, warns, err := config.Normalize(st)
	if err != nil {
		return nil, err
	}
	if err := config.ValidateWithBaseDir(n, opts.BaseDir); err != nil {
		return nil, err
	}
	clk := opts.Clock
	if clk == nil {
		clk = testutil.SystemClock{}
	}
	now := clk.Now()

	maxRep := n.Spec.Agent.MaxRepetitions
	if maxRep < 1 {
		maxRep = mibtree.DefaultMaxRepetitions
	}
	maps := make(map[string]*mibtree.Tree, len(n.Spec.Maps))
	for _, m := range n.Spec.Maps {
		tree, err := mibtree.Compile(m.Objects)
		if err != nil {
			return nil, err
		}
		tree.SetMaxRepetitions(maxRep)
		maps[m.Name] = tree
	}

	comms := make(map[string]*snapshot.Community, len(n.Spec.Communities))
	for _, c := range n.Spec.Communities {
		wire, err := readTrimmed(c.CommunityFile, opts.BaseDir)
		if err != nil {
			return nil, fmt.Errorf("compiler: community %q: %w", c.Name, err)
		}
		vers := make(map[string]bool, len(c.Versions))
		for _, v := range c.Versions {
			vers[v] = true
		}
		access := c.Access
		if access == "" {
			access = model.AccessRead
		}
		comms[string(wire)] = &snapshot.Community{
			Name:     c.Name,
			Wire:     wire,
			Versions: vers,
			Access:   access,
			Map:      c.Map,
		}
	}

	eng, err := compileEngine(n, opts, clk)
	if err != nil {
		return nil, err
	}

	allow, err := compileAllow(n.Spec.Admission.AllowClientCidrs)
	if err != nil {
		return nil, err
	}

	vers := make(map[string]bool, len(n.Spec.Agent.Versions))
	for _, v := range n.Spec.Agent.Versions {
		vers[v] = true
	}

	maxVB := n.Spec.Agent.MaxVarBinds
	if maxVB < 1 {
		maxVB = config.DefaultMaxVarBinds
	}
	maxMsg := n.Spec.Agent.MaxMessageBytes
	if maxMsg < 1 {
		maxMsg = config.DefaultMaxMessageBytes
	}
	maxSec := n.Spec.Admission.MaxDatagramsPerSec
	if maxSec < 1 {
		maxSec = config.DefaultMaxDatagramsPerSec
	}
	maxIP := n.Spec.Admission.MaxDatagramsPerIP
	if maxIP < 1 {
		maxIP = config.DefaultMaxDatagramsPerIP
	}

	rev, err := config.Revision(n)
	if err != nil {
		return nil, err
	}
	bootRev := opts.BootstrapRevision
	if bootRev == "" {
		bootRev = rev
	}

	uptimeEpoch := now
	if opts.Previous != nil && !opts.Previous.UptimeEpoch.IsZero() {
		uptimeEpoch = opts.Previous.UptimeEpoch
	}

	return &snapshot.Snapshot{
		Canonical:             n,
		Revision:              rev,
		BootstrapRevision:     bootRev,
		Generation:            opts.Generation,
		CompiledAt:            now,
		Warnings:              warns,
		AgentAddress:          n.Spec.Listeners.Agent.Address,
		TrapAddress:           n.Spec.Listeners.Traps.Address,
		ManagementAddress:     n.Spec.Listeners.Management.Address,
		RESTPath:              n.Spec.Listeners.Management.RESTPath,
		MCPPath:               n.Spec.Listeners.Management.MCPPath,
		AgentEnabled:          n.Spec.Listeners.Agent.Enabled,
		TrapsEnabled:          n.Spec.Listeners.Traps.Enabled,
		TCPEnabled:            n.Spec.Listeners.TCP.Enabled,
		TCPAddress:            n.Spec.Listeners.TCP.Address,
		TCPTrapsAddress:       n.Spec.Listeners.TCP.TrapsAddress,
		DTLSEnabled:           n.Spec.Listeners.DTLS.Enabled,
		DTLSAddress:           n.Spec.Listeners.DTLS.Address,
		DTLSTrapsAddress:      n.Spec.Listeners.DTLS.TrapsAddress,
		DTLSCertFile:          n.Spec.Listeners.DTLS.CertFile,
		DTLSKeyFile:           n.Spec.Listeners.DTLS.KeyFile,
		DTLSClientCAFile:      n.Spec.Listeners.DTLS.ClientCAFile,
		Maps:                  maps,
		Communities:           comms,
		Engine:                eng,
		UptimeEpoch:           uptimeEpoch,
		Clock:                 clk,
		Allow:                 allow,
		MaxPerSec:             maxSec,
		MaxPerIP:              maxIP,
		MaxVarBinds:           maxVB,
		MaxRepetitions:        maxRep,
		MaxMessageBytes:       maxMsg,
		Versions:              vers,
		AcceptUnauthenticated: n.Spec.Traps.AcceptUnauthenticated,
		RawRetain:             n.Spec.Traps.RawRetain,
	}, nil
}

func compileEngine(n *model.State, opts CompileOpts, clk testutil.Clock) (*usm.Engine, error) {
	if opts.Previous != nil && opts.Previous.Engine != nil && sameEngineUsers(opts.Previous, n) {
		return opts.Previous.Engine, nil
	}
	eng, err := usm.New(usm.Config{
		EngineIDHex: n.Spec.Engine.EngineID,
		EngineBoots: int32(n.Spec.Engine.EngineBoots),
		Clock:       clockAdapter{clk},
	})
	if err != nil {
		return nil, err
	}
	for _, u := range n.Spec.Users {
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
				return nil, fmt.Errorf("compiler: user %q auth: %w", u.Name, err)
			}
			cfg.AuthPassphrase = pass
		}
		if u.Priv != nil {
			cfg.PrivProtocol = u.Priv.Protocol
			pass, err := readTrimmed(u.Priv.SecretFile, opts.BaseDir)
			if err != nil {
				return nil, fmt.Errorf("compiler: user %q priv: %w", u.Name, err)
			}
			cfg.PrivPassphrase = pass
		}
		if err := eng.AddUser(cfg); err != nil {
			return nil, err
		}
	}
	return eng, nil
}

func sameEngineUsers(prev *snapshot.Snapshot, n *model.State) bool {
	if prev == nil || prev.Canonical == nil || n == nil {
		return false
	}
	a := prev.Canonical.Spec
	b := n.Spec
	if a.Engine.EngineID != b.Engine.EngineID || a.Engine.EngineBoots != b.Engine.EngineBoots {
		return false
	}
	return jsonEqual(a.Users, b.Users)
}

func jsonEqual(a, b any) bool {
	ab, err := json.Marshal(a)
	if err != nil {
		return false
	}
	bb, err := json.Marshal(b)
	if err != nil {
		return false
	}
	return bytes.Equal(ab, bb)
}

func compileAllow(cidrs []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(cidrs))
	for i, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, domainerr.ValidationFailed("invalid allowClientCidrs",
				domainerr.FieldViolation{Path: fmt.Sprintf("spec.admission.allowClientCidrs[%d]", i), Code: "invalid_value", Message: err.Error()})
		}
		out = append(out, p)
	}
	return out, nil
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
