package observability

// Warning codes are a bounded, stable Status DTO surface.
const (
	WarnAgentUnbound    = "agent_unbound"
	WarnTrapUnbound     = "trap_unbound"
	WarnSnapshotMissing = "snapshot_missing"
	WarnMgmtUnbound     = "management_unbound"
	WarnListenerUnbound = "listener_unbound"
)

// MaxWarnings caps the Status warning list.
const MaxWarnings = 16

// Warning is one agent-readable operational note.
type Warning struct {
	Code    string
	Message string
}

// Facts are process observations used to evaluate health.
type Facts struct {
	ProcessDown bool
	SnapshotUp  bool
	// AgentBound is true when the UDP/161 listener is accepting.
	AgentBound bool
	// AgentOff is true when the agent was explicitly disabled.
	AgentOff bool
	// TrapBound is true when the UDP/162 listener is accepting.
	TrapBound bool
	// TrapOff is true when traps are not enabled (--trap-listen=off or YAML traps.enabled false).
	TrapOff bool
	// MgmtBound is true when the management listener is accepting.
	MgmtBound bool
	// MgmtOff is true when management was explicitly disabled (off/none/-).
	MgmtOff bool
}

// Probe is liveness and readiness plus bounded warnings.
type Probe struct {
	Live     bool
	Ready    bool
	Warnings []Warning
}

// Evaluate implements Ready = snapshot installed AND every enabled
// data-plane listener bound AND (management bound OR --management-listen=off).
// Ready stays true on the old sockets until a new bind succeeds.
func Evaluate(in Facts) Probe {
	p := Probe{Live: !in.ProcessDown}
	agentOK := in.AgentBound || in.AgentOff
	trapOK := in.TrapBound || in.TrapOff
	mgmtOK := in.MgmtBound || in.MgmtOff
	p.Ready = p.Live && in.SnapshotUp && agentOK && trapOK && mgmtOK

	add := func(code, msg string) {
		if len(p.Warnings) >= MaxWarnings {
			return
		}
		p.Warnings = append(p.Warnings, Warning{Code: code, Message: msg})
	}
	listenerUnbound := false
	if !agentOK {
		add(WarnAgentUnbound, "SNMP agent UDP listener is not bound")
		listenerUnbound = true
	}
	if !trapOK {
		add(WarnTrapUnbound, "trap UDP listener is not bound")
		listenerUnbound = true
	}
	if !in.SnapshotUp {
		add(WarnSnapshotMissing, "compiled snapshot is not installed")
	}
	if !mgmtOK {
		add(WarnMgmtUnbound, "management listener is not bound")
		listenerUnbound = true
	}
	if listenerUnbound {
		add(WarnListenerUnbound, "a required listener is not bound")
	}
	return p
}
