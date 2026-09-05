package snmpagent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hilather/go-lab-snmp/internal/config"
	"github.com/hilather/go-lab-snmp/internal/observability"
	"github.com/hilather/go-lab-snmp/internal/snapshot"
	"github.com/hilather/go-lab-snmp/internal/store"
)

const (
	DefaultMaxInflight   = 1024
	DefaultShutdownWait  = 5 * time.Second
	MaxAcceptedConns     = 1024
	tcpIdleTimeout       = 30 * time.Second
	dtlsIdleTimeout      = 30 * time.Second
	dtlsHandshakeTimeout = 10 * time.Second
)

// Config is the agent listener configuration. Addr may be empty when
// only TCP or DTLS will bind later via SwapTCP / SwapDTLS.
type Config struct {
	Addr        string
	Store       *snapshot.Store
	Overlay     *store.Overlay
	Queries     *store.QueryRing
	Clock       Clock
	MaxInflight int
	Metrics     *observability.Registry
	Logger      *observability.Logger
	BaseDir     string
}

// Server is a unicast SNMPv1/v2c/v3 listener (UDP, TCP, DTLS).
type Server struct {
	cfg     Config
	store   *snapshot.Store
	overlay *store.Overlay
	queries *store.QueryRing
	clock   Clock
	metrics *observability.Registry
	logger  *observability.Logger

	ctx    context.Context
	cancel context.CancelFunc

	mu       sync.Mutex
	udp      net.PacketConn
	udpGen   uint64
	bindAddr string
	tcp      net.Listener
	tcpGen   uint64
	dtls     net.Listener
	dtlsGen  uint64
	started  bool
	stopped  bool

	inflight    chan struct{}
	tcpSlots    chan struct{}
	dtlsSlots   chan struct{}
	tcpStreams  map[net.Conn]struct{}
	dtlsStreams map[net.Conn]struct{}
	global      *queryLimiter
	perIP       *queryLimiter

	wg sync.WaitGroup

	AuthFail  atomic.Int64
	Allowlist atomic.Int64
	Admission atomic.Int64
	Dropped   atomic.Int64
	Served    atomic.Int64
}

// New validates cfg. Start binds and serves.
func New(cfg Config) (*Server, error) {
	if cfg.Store == nil {
		return nil, errors.New("snmpagent: Store is required")
	}
	if cfg.Store.Load() == nil {
		return nil, errors.New("snmpagent: snapshot is required")
	}
	if cfg.MaxInflight <= 0 {
		cfg.MaxInflight = DefaultMaxInflight
	}
	if cfg.Overlay == nil {
		cfg.Overlay = store.NewOverlay()
	}
	if cfg.Queries == nil {
		cfg.Queries = store.NewQueryRing(store.DefaultQueryRing)
	}
	snap := cfg.Store.Load()
	now := time.Now
	clk := cfg.Clock
	if clk == nil {
		clk = snap.Clock
	}
	if clk != nil {
		now = clk.Now
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		cfg:         cfg,
		store:       cfg.Store,
		overlay:     cfg.Overlay,
		queries:     cfg.Queries,
		clock:       clk,
		metrics:     cfg.Metrics,
		logger:      cfg.Logger,
		ctx:         ctx,
		cancel:      cancel,
		bindAddr:    cfg.Addr,
		inflight:    make(chan struct{}, cfg.MaxInflight),
		tcpSlots:    make(chan struct{}, MaxAcceptedConns),
		dtlsSlots:   make(chan struct{}, MaxAcceptedConns),
		tcpStreams:  map[net.Conn]struct{}{},
		dtlsStreams: map[net.Conn]struct{}{},
		global:      newQueryLimiter(float64(snap.MaxPerSec), float64(snap.MaxPerSec), now),
		perIP:       newQueryLimiter(float64(snap.MaxPerIP), float64(snap.MaxPerIP), now),
	}, nil
}

func (s *Server) view() *Runtime {
	if s == nil || s.store == nil {
		return nil
	}
	return viewOf(s.store.Load(), s.overlay, s.queries, s.clock)
}

// Overlay is the process-local SET / oids:set layer shared with app.
func (s *Server) Overlay() *store.Overlay {
	if s == nil {
		return nil
	}
	return s.overlay
}

// Snapshot is the active compiled snapshot, or nil.
func (s *Server) Snapshot() *snapshot.Snapshot {
	if s == nil || s.store == nil {
		return nil
	}
	return s.store.Load()
}

// Start binds ListenPacket("udp") and serves in the background.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return errors.New("snmpagent: already started")
	}
	if s.stopped {
		return errors.New("snmpagent: start after shutdown")
	}
	if s.cfg.Addr == "" {
		return errors.New("snmpagent: Addr is required")
	}
	pc, err := net.ListenPacket("udp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("snmpagent: udp listen: %w", err)
	}
	s.udp = pc
	s.bindAddr = s.cfg.Addr
	s.started = true
	s.udpGen++
	gen := s.udpGen
	s.wg.Add(1)
	go s.serveUDP(gen)
	return nil
}

// SwapUDP installs pc as the serving PacketConn and starts a read loop.
// The previous conn is returned for the caller to close. A nil pc unbinds.
func (s *Server) SwapUDP(pc net.PacketConn) net.PacketConn {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.udp
	s.udp = pc
	s.udpGen++
	if pc != nil {
		s.bindAddr = pc.LocalAddr().String()
		s.started = true
		gen := s.udpGen
		s.wg.Add(1)
		go s.serveUDP(gen)
	} else {
		s.bindAddr = ""
	}
	return old
}

// Rebind binds addr first, then closes the previous PacketConn.
// Empty addr unbinds. The previous socket keeps serving if Listen fails.
func (s *Server) Rebind(addr string) error {
	if s == nil {
		return errors.New("snmpagent: nil server")
	}
	if addr == "" {
		old := s.SwapUDP(nil)
		if old != nil {
			_ = old.Close()
		}
		return nil
	}
	s.mu.Lock()
	same := s.bindAddr == addr && s.udp != nil && !s.stopped
	s.mu.Unlock()
	if same {
		return nil
	}
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("snmpagent: udp listen: %w", err)
	}
	old := s.SwapUDP(pc)
	if old != nil {
		_ = old.Close()
	}
	s.mu.Lock()
	s.bindAddr = addr
	s.mu.Unlock()
	return nil
}

// SwapTCP installs ln as the serving TCP listener and starts Accept.
// The previous listener is returned for the caller to close. A nil ln unbinds.
func (s *Server) SwapTCP(ln net.Listener) net.Listener {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	old := s.tcp
	s.tcp = ln
	s.tcpGen++
	conns := stealConns(s.tcpStreams)
	if ln != nil {
		s.started = true
		gen := s.tcpGen
		s.wg.Add(1)
		go s.serveTCP(gen)
	}
	s.mu.Unlock()
	closeConns(conns)
	return old
}

// SwapDTLS installs ln as the serving DTLS listener and starts Accept.
// The previous listener is returned for the caller to close. A nil ln unbinds.
func (s *Server) SwapDTLS(ln net.Listener) net.Listener {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	old := s.dtls
	s.dtls = ln
	s.dtlsGen++
	conns := stealConns(s.dtlsStreams)
	if ln != nil {
		s.started = true
		gen := s.dtlsGen
		s.wg.Add(1)
		go s.serveDTLS(gen)
	}
	s.mu.Unlock()
	closeConns(conns)
	return old
}

// Bound reports whether a PacketConn is currently serving.
func (s *Server) Bound() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.udp != nil && s.started && !s.stopped
}

// BoundTCP reports whether a TCP listener is currently serving.
func (s *Server) BoundTCP() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tcp != nil && !s.stopped
}

// BoundDTLS reports whether a DTLS listener is currently serving.
func (s *Server) BoundDTLS() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dtls != nil && !s.stopped
}

// Ready is the agent clause: snapshot loaded and at least one agent listener bound.
func (s *Server) Ready() bool {
	return s != nil && s.store != nil && s.store.Load() != nil && (s.Bound() || s.BoundTCP() || s.BoundDTLS())
}

// Addr is the bound UDP address, or nil.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.udp == nil {
		return nil
	}
	return s.udp.LocalAddr()
}

// TCPAddr is the bound TCP address, or nil.
func (s *Server) TCPAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tcp == nil {
		return nil
	}
	return s.tcp.Addr()
}

// DTLSAddr is the bound DTLS address, or nil.
func (s *Server) DTLSAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dtls == nil {
		return nil
	}
	return s.dtls.Addr()
}

// Shutdown stops the read loops and waits up to ctx.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return nil
	}
	s.stopped = true
	s.cancel()
	udp := s.udp
	tcp := s.tcp
	dtlsLn := s.dtls
	s.udp = nil
	s.tcp = nil
	s.dtls = nil
	tcpConns := stealConns(s.tcpStreams)
	dtlsConns := stealConns(s.dtlsStreams)
	s.mu.Unlock()
	if udp != nil {
		_ = udp.Close()
	}
	if tcp != nil {
		_ = tcp.Close()
	}
	if dtlsLn != nil {
		_ = dtlsLn.Close()
	}
	closeConns(tcpConns)
	closeConns(dtlsConns)
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server) syncAdmission(rt *Runtime) {
	if s == nil || rt == nil {
		return
	}
	s.global.setRate(float64(rt.MaxPerSec), float64(rt.MaxPerSec))
	s.perIP.setRate(float64(rt.MaxPerIP), float64(rt.MaxPerIP))
}

func (s *Server) serveUDP(gen uint64) {
	defer s.wg.Done()
	max := int(config.DefaultMaxMessageBytes)
	if snap := s.store.Load(); snap != nil && int(snap.MaxMessageBytes) > max {
		max = int(snap.MaxMessageBytes)
	}
	if max < 1 {
		max = 64 << 10
	}
	buf := make([]byte, max+1)
	for {
		if s.ctx.Err() != nil {
			return
		}
		s.mu.Lock()
		if s.udpGen != gen {
			s.mu.Unlock()
			return
		}
		pc := s.udp
		s.mu.Unlock()
		if pc == nil {
			return
		}
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if s.ctx.Err() != nil || isClosed(err) {
				return
			}
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		select {
		case s.inflight <- struct{}{}:
		default:
			s.Admission.Add(1)
			s.Dropped.Add(1)
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.inflight }()
			s.handle(udpReply{pc: pc, addr: addr}, pkt)
		}()
	}
}

func (s *Server) maxMessageBytes() int64 {
	max := config.DefaultMaxMessageBytes
	if s != nil && s.store != nil {
		if snap := s.store.Load(); snap != nil && snap.MaxMessageBytes > max {
			max = snap.MaxMessageBytes
		}
	}
	if max < 1 {
		max = 64 << 10
	}
	return max
}

func takeSlot(slots chan struct{}) bool {
	if slots == nil {
		return false
	}
	select {
	case slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func releaseSlot(slots chan struct{}) {
	if slots == nil {
		return
	}
	select {
	case <-slots:
	default:
	}
}

func stealConns(m map[net.Conn]struct{}) []net.Conn {
	if len(m) == 0 {
		return nil
	}
	out := make([]net.Conn, 0, len(m))
	for c := range m {
		out = append(out, c)
		delete(m, c)
	}
	return out
}

func closeConns(conns []net.Conn) {
	for _, c := range conns {
		if c != nil {
			_ = c.Close()
		}
	}
}

func trackConn(m map[net.Conn]struct{}, c net.Conn) {
	if m == nil || c == nil {
		return
	}
	m[c] = struct{}{}
}

func untrackConn(m map[net.Conn]struct{}, c net.Conn) {
	if m == nil || c == nil {
		return
	}
	delete(m, c)
}

func isClosed(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	return errors.Is(err, context.Canceled)
}
