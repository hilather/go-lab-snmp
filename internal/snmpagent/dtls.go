package snmpagent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/pion/dtls/v3"

	"github.com/hilather/go-lab-snmp/internal/config"
)

var errAllowlist = errors.New("snmpagent: allowlist")

// AEAD only: ECDHE + AES-GCM and ChaCha20-Poly1305. No PSK, no CBC.
var dtlsAllowlist = []dtls.CipherSuiteID{
	dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	dtls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	dtls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
}

// ListenDTLS binds a DTLS 1.2 listener without swapping it into service.
// Cert paths come from the caller (candidate snapshot); CIDR uses live prefixes.
func (s *Server) ListenDTLS(addr, certFile, keyFile, clientCAFile string) (net.Listener, error) {
	if s == nil {
		return nil, errors.New("snmpagent: nil server")
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("snmpagent: dtls listen: %w", err)
	}
	opts, err := s.dtlsServerOptions(certFile, keyFile, clientCAFile)
	if err != nil {
		return nil, err
	}
	ln, err := dtls.ListenWithOptions("udp", udpAddr, opts...)
	if err != nil {
		return nil, fmt.Errorf("snmpagent: dtls listen: %w", err)
	}
	return ln, nil
}

func (s *Server) dtlsServerOptions(certFile, keyFile, clientCAFile string) ([]dtls.ServerOption, error) {
	certPath, err := config.ResolveFileRef(certFile, s.cfg.BaseDir)
	if err != nil {
		return nil, fmt.Errorf("snmpagent: dtls certFile: %w", err)
	}
	keyPath, err := config.ResolveFileRef(keyFile, s.cfg.BaseDir)
	if err != nil {
		return nil, fmt.Errorf("snmpagent: dtls keyFile: %w", err)
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("snmpagent: dtls certificate: %w", err)
	}
	opts := []dtls.ServerOption{
		dtls.WithCertificates(cert),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		dtls.WithCipherSuites(dtlsAllowlist...),
		dtls.WithOnConnectionAttempt(s.dtlsAdmit),
	}
	if clientCAFile != "" {
		pool, err := loadClientCAs(clientCAFile, s.cfg.BaseDir)
		if err != nil {
			return nil, err
		}
		opts = append(opts,
			dtls.WithClientCAs(pool),
			dtls.WithClientAuth(dtls.RequireAndVerifyClientCert),
		)
	}
	return opts, nil
}

func (s *Server) dtlsAdmit(a net.Addr) error {
	rt := s.view()
	if rt == nil || !s.allowed(rt, peerAddr(a)) {
		s.Allowlist.Add(1)
		s.Dropped.Add(1)
		s.observePDU("", "", "allowlist")
		return errAllowlist
	}
	return nil
}

func loadClientCAs(path, baseDir string) (*x509.CertPool, error) {
	resolved, err := config.ResolveFileRef(path, baseDir)
	if err != nil {
		return nil, fmt.Errorf("snmpagent: clientCAFile: %w", err)
	}
	b, err := os.ReadFile(resolved)
	if err != nil {
		return nil, fmt.Errorf("snmpagent: clientCAFile: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, errors.New("snmpagent: clientCAFile has no certificates")
	}
	return pool, nil
}

func (s *Server) serveDTLS(gen uint64) {
	defer s.wg.Done()
	for {
		if s.ctx.Err() != nil {
			return
		}
		s.mu.Lock()
		if s.dtlsGen != gen {
			s.mu.Unlock()
			return
		}
		ln := s.dtls
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
		if !takeSlot(s.dtlsSlots) {
			_ = conn.Close()
			s.Admission.Add(1)
			s.Dropped.Add(1)
			s.observePDU("", "", "admission")
			continue
		}
		s.mu.Lock()
		trackConn(s.dtlsStreams, conn)
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer releaseSlot(s.dtlsSlots)
			defer func() {
				s.mu.Lock()
				untrackConn(s.dtlsStreams, conn)
				s.mu.Unlock()
				_ = conn.Close()
			}()
			s.serveDTLSConn(conn)
		}()
	}
}

func (s *Server) serveDTLSConn(conn net.Conn) {
	dtlsConn, ok := conn.(*dtls.Conn)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, dtlsHandshakeTimeout)
	err := dtlsConn.HandshakeContext(ctx)
	cancel()
	if err != nil {
		return
	}
	if s.observeWrite != nil {
		conn = writeObserveConn{Conn: conn, observe: s.observeWrite}
	}
	sink := streamReply{conn: conn, tcp: false}
	max := s.maxMessageBytes()
	buf := make([]byte, int(max)+1)
	for {
		if s.ctx.Err() != nil {
			return
		}
		_ = conn.SetDeadline(time.Now().Add(dtlsIdleTimeout))
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		s.handle(sink, pkt)
	}
}
