package snmpsink

import (
	"net"
	"time"

	"github.com/hilather/go-lab-snmp/internal/snmpwire"
)

func (s *Server) serveTCP(gen uint64) {
	defer s.wg.Done()
	for {
		if s.ctx.Err() != nil {
			return
		}
		s.mu.Lock()
		if s.tcpGen != gen {
			s.mu.Unlock()
			return
		}
		ln := s.tcp
		s.mu.Unlock()
		if ln == nil {
			return
		}
		conn, err := ln.Accept()
		if err != nil {
			if s.ctx.Err() != nil || isClosed(err) {
				return
			}
			continue
		}
		if !takeSlot(s.tcpSlots) {
			_ = conn.Close()
			s.Admission.Add(1)
			s.Dropped.Add(1)
			s.observeTrap("", "admission")
			continue
		}
		s.mu.Lock()
		trackConn(s.tcpStreams, conn)
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer releaseSlot(s.tcpSlots)
			defer func() {
				s.mu.Lock()
				untrackConn(s.tcpStreams, conn)
				s.mu.Unlock()
				_ = conn.Close()
			}()
			s.serveTCPConn(conn)
		}()
	}
}

func (s *Server) serveTCPConn(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	sink := streamReply{conn: conn, tcp: true}
	max := s.maxMessageBytes()
	for {
		if s.ctx.Err() != nil {
			return
		}
		_ = conn.SetDeadline(time.Now().Add(tcpIdleTimeout))
		pkt, err := snmpwire.ReadTCP(conn, max)
		if err != nil {
			return
		}
		s.handle(sink, pkt)
	}
}
