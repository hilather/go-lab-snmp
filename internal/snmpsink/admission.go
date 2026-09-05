package snmpsink

import (
	"net"
	"net/netip"
)

func peerAddr(addr net.Addr) netip.Addr {
	if addr == nil {
		return netip.Addr{}
	}
	if a, ok := addr.(*net.UDPAddr); ok && a != nil {
		ip, ok := netip.AddrFromSlice(a.IP)
		if !ok {
			return netip.Addr{}
		}
		return ip.Unmap()
	}
	ap, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

func (s *Server) allowed(ip netip.Addr) bool {
	if s == nil {
		return false
	}
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	if len(s.cfg.Allow) == 0 {
		return ip.IsLoopback()
	}
	for _, p := range s.cfg.Allow {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
