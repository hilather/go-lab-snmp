package app

import (
	"context"

	"github.com/hilather/go-lab-snmp/internal/config"
	"github.com/hilather/go-lab-snmp/internal/domainerr"
	"github.com/hilather/go-lab-snmp/internal/observability"
)

// Export returns canonical YAML or JSON of the active snapshot.
func (s *App) Export(ctx context.Context, actor Actor, format ExportFormat) (*Export, error) {
	if err := s.requireCtx(ctx); err != nil {
		return nil, err
	}
	_ = actor
	snap, err := s.active()
	if err != nil {
		return nil, err
	}
	if format == "" {
		format = ExportYAML
	}
	if format != ExportYAML && format != ExportJSON {
		return nil, domainerr.ValidationFailed("unknown export format",
			domainerr.FieldViolation{Path: "format", Code: "invalid_value", Message: "format must be yaml or json"})
	}
	var body []byte
	switch format {
	case ExportJSON:
		body, err = config.CanonicalJSON(snap.Canonical)
	default:
		body, err = config.CanonicalYAML(snap.Canonical)
	}
	if err != nil {
		return nil, asDomain(err)
	}
	bootCanon := snap.Canonical
	if b := s.snaps.Bootstrap(); b != nil {
		bootCanon = b.Canonical
	}
	_, human, err := diffStates(bootCanon, snap.Canonical)
	if err != nil {
		return nil, err
	}
	return &Export{
		Format:            format,
		Body:              append([]byte(nil), body...),
		Revision:          snap.Revision,
		BootstrapRevision: snap.BootstrapRevision,
		Drifted:           snap.Drifted(),
		HumanDiff:         human,
	}, nil
}

// GetState returns a copy of the live spec plus revision metadata.
func (s *App) GetState(ctx context.Context, actor Actor) (*StateView, error) {
	if err := s.requireCtx(ctx); err != nil {
		return nil, err
	}
	_ = actor
	snap, err := s.active()
	if err != nil {
		return nil, err
	}
	copied, err := cloneState(snap.Canonical)
	if err != nil {
		return nil, err
	}
	return &StateView{
		BootstrapRevision: snap.BootstrapRevision,
		RuntimeRevision:   snap.Revision,
		Generation:        snap.Generation,
		StoreGeneration:   s.storeGeneration(),
		Drifted:           snap.Drifted(),
		LoadedAt:          snap.CompiledAt,
		Canonical:         copied,
	}, nil
}

// Status is revisions plus listeners and hostTime.
func (s *App) Status(ctx context.Context, actor Actor) (*Status, error) {
	if err := s.requireCtx(ctx); err != nil {
		return nil, err
	}
	_ = actor
	snap, err := s.active()
	if err != nil {
		return nil, err
	}
	snmpAddr := effectiveSNMP(s.snmpOverride, snap.AgentAddress, snap.AgentEnabled)
	trapAddr := effectiveTrap(s.trapOverride, snap.TrapAddress, snap.TrapsEnabled)
	mgmtAddr := effectiveMgmt(s.mgmtOverride, snap.ManagementAddress)
	tcpAgent := effectiveTCP(snap.TCPEnabled, snap.TCPAddress, snmpAddr)
	tcpTrap := effectiveTCP(snap.TCPEnabled, snap.TCPTrapsAddress, trapAddr)
	dtlsAgent := effectiveDTLS(s.dtlsOverride, snap.DTLSAddress, snap.DTLSEnabled)
	dtlsTrap := effectiveDTLS(s.dtlsTrapOverride, snap.DTLSTrapsAddress, snap.DTLSEnabled)
	probe := observability.Evaluate(s.HealthFacts())
	warns := make([]Warning, 0, len(probe.Warnings)+4)
	for _, w := range probe.Warnings {
		warns = append(warns, Warning{Code: w.Code, Message: w.Message})
	}
	for _, w := range warningsOf(snap) {
		if len(warns) >= observability.MaxWarnings {
			break
		}
		warns = append(warns, w)
	}
	listeners := []ListenerStatus{
		{Name: "agent", Address: displayListen(snmpAddr)},
		{Name: "traps", Address: displayListen(trapAddr)},
		{Name: "management", Address: displayListen(mgmtAddr)},
	}
	if snap.TCPEnabled {
		listeners = append(listeners,
			ListenerStatus{Name: "agent-tcp", Address: displayListen(tcpAgent)},
			ListenerStatus{Name: "traps-tcp", Address: displayListen(tcpTrap)},
		)
	}
	if snap.DTLSEnabled {
		listeners = append(listeners,
			ListenerStatus{Name: "agent-dtls", Address: displayListen(dtlsAgent)},
			ListenerStatus{Name: "traps-dtls", Address: displayListen(dtlsTrap)},
		)
	}
	return &Status{
		Ready: probe.Ready,
		Revisions: RevisionView{
			BootstrapRevision: snap.BootstrapRevision,
			RuntimeRevision:   snap.Revision,
			Generation:        snap.Generation,
			StoreGeneration:   s.storeGeneration(),
			Drifted:           snap.Drifted(),
			LoadedAt:          snap.CompiledAt,
		},
		Listeners: listeners,
		HostTime:  s.clock.Now().UTC(),
		Warnings:  warns,
	}, nil
}
