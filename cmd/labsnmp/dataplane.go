package main

import (
	"fmt"
	"net"
	"sync"

	"github.com/hilather/go-lab-snmp/internal/app"
	"github.com/hilather/go-lab-snmp/internal/snmpagent"
	"github.com/hilather/go-lab-snmp/internal/snmpsink"
)

// dataPlane owns the UDP agent and trap sockets. Sync binds from desired
// and must not re-read app.Active().
type dataPlane struct {
	mu    sync.Mutex
	agent *snmpagent.Server
	sink  *snmpsink.Server
	bound app.DesiredListeners
}

func (d *dataPlane) last() app.DesiredListeners {
	if d == nil {
		return app.DesiredListeners{}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.bound
}

// Sync binds every new UDP address before closing any old socket.
// A failed new bind rolls back sockets opened in this call; the previous
// listeners keep serving. Empty desired UDP address stops that listener.
func (d *dataPlane) Sync(desired app.DesiredListeners) error {
	if d == nil {
		return fmt.Errorf("dataplane: nil")
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	var newAgent, newTrap net.PacketConn
	rollback := func() {
		if newAgent != nil {
			_ = newAgent.Close()
			newAgent = nil
		}
		if newTrap != nil {
			_ = newTrap.Close()
			newTrap = nil
		}
	}

	if desired.AgentUDP != "" && d.agent == nil {
		return fmt.Errorf("dataplane: agent server missing")
	}
	if desired.TrapUDP != "" && d.sink == nil {
		return fmt.Errorf("dataplane: trap server missing")
	}

	agentBound := d.agent != nil && d.agent.Bound()
	if desired.AgentUDP != "" && (desired.AgentUDP != d.bound.AgentUDP || !agentBound) {
		pc, err := net.ListenPacket("udp", desired.AgentUDP)
		if err != nil {
			return fmt.Errorf("snmpagent: udp listen: %w", err)
		}
		newAgent = pc
	}

	trapBound := d.sink != nil && d.sink.Bound()
	if desired.TrapUDP != "" && (desired.TrapUDP != d.bound.TrapUDP || !trapBound) {
		pc, err := net.ListenPacket("udp", desired.TrapUDP)
		if err != nil {
			rollback()
			return fmt.Errorf("snmpsink: udp listen: %w", err)
		}
		newTrap = pc
	}

	if d.agent != nil {
		switch {
		case desired.AgentUDP == "":
			old := d.agent.SwapUDP(nil)
			if old != nil {
				_ = old.Close()
			}
		case newAgent != nil:
			old := d.agent.SwapUDP(newAgent)
			if old != nil {
				_ = old.Close()
			}
		}
	}
	if d.sink != nil {
		switch {
		case desired.TrapUDP == "":
			old := d.sink.SwapUDP(nil)
			if old != nil {
				_ = old.Close()
			}
		case newTrap != nil:
			old := d.sink.SwapUDP(newTrap)
			if old != nil {
				_ = old.Close()
			}
		}
	}

	d.bound = desired
	return nil
}
