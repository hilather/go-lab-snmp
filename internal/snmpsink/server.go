package snmpsink

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hilather/go-lab-snmp/internal/observability"
	"github.com/hilather/go-lab-snmp/internal/snapshot"
	"github.com/hilather/go-lab-snmp/internal/store"
	"github.com/hilather/go-lab-snmp/internal/usm"
)

const (
	DefaultMaxInflight  = 1024
	DefaultShutdownWait = 5 * time.Second
)

// Clock is an injectable time source.
type Clock interface {
	Now() time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// Community is a compiled v1/v2c identity. Name is the DNS-label row id.
type Community struct {
	Name     string
	Wire     []byte
	Versions map[string]bool
}

// Config is the UDP/162 listener configuration.
type Config struct {
	Addr                  string
	Store                 *store.TrapRing
	Snapshots             *snapshot.Store       // live communities/users/admission/trap-policy; nil uses static fields
	Communities           map[string]*Community // keyed by wire community string
	Engine                *usm.Engine
	Versions              map[string]bool // spec.agent.versions; empty allows all
	AcceptUnauthenticated bool
	RawRetain             bool
	MaxMessageBytes       int64
	Allow                 []netip.Prefix
	MaxPerSec             int
	MaxPerIP              int
	MaxInflight           int
	Clock                 Clock
	Metrics               *observability.Registry
}

// Server is a receive-only SNMPv1/v2c/v3 UDP trap/inform listener.
type Server struct {
	cfg Config

	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	udp     net.PacketConn
	started bool
	stopped bool

	inflight chan struct{}
	global   *queryLimiter
	perIP    *queryLimiter

	wg sync.WaitGroup

	AuthFail  atomic.Int64
	Allowlist atomic.Int64
	Admission atomic.Int64
	Dropped   atomic.Int64
	Stored    atomic.Int64
	InformAck atomic.Int64
}

// New validates cfg. Start binds and serves.
func New(cfg Config) (*Server, error) {
	if cfg.Store == nil {
		return nil, errors.New("snmpsink: Store is required")
	}
	if cfg.Addr == "" {
		return nil, errors.New("snmpsink: Addr is required")
	}
	if cfg.MaxInflight <= 0 {
		cfg.MaxInflight = DefaultMaxInflight
	}
	if cfg.MaxMessageBytes < 1 {
		cfg.MaxMessageBytes = 64 << 10
	}
	if cfg.Clock == nil {
		cfg.Clock = systemClock{}
	}
	now := cfg.Clock.Now
	maxSec, maxIP := cfg.MaxPerSec, cfg.MaxPerIP
	if cfg.Snapshots != nil {
		if snap := cfg.Snapshots.Load(); snap != nil {
			maxSec, maxIP = snap.MaxPerSec, snap.MaxPerIP
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		cfg:      cfg,
		ctx:      ctx,
		cancel:   cancel,
		inflight: make(chan struct{}, cfg.MaxInflight),
		global:   newQueryLimiter(float64(maxSec), float64(maxSec), now),
		perIP:    newQueryLimiter(float64(maxIP), float64(maxIP), now),
	}, nil
}

func (s *Server) snap() *snapshot.Snapshot {
	if s == nil || s.cfg.Snapshots == nil {
		return nil
	}
	return s.cfg.Snapshots.Load()
}

func (s *Server) engine() *usm.Engine {
	if snap := s.snap(); snap != nil {
		return snap.Engine
	}
	return s.cfg.Engine
}

func (s *Server) maxMessageBytes() int64 {
	if snap := s.snap(); snap != nil && snap.MaxMessageBytes > 0 {
		return snap.MaxMessageBytes
	}
	if s.cfg.MaxMessageBytes < 1 {
		return 64 << 10
	}
	return s.cfg.MaxMessageBytes
}

func (s *Server) rawRetain() bool {
	if snap := s.snap(); snap != nil {
		return snap.RawRetain
	}
	return s.cfg.RawRetain
}

func (s *Server) acceptUnauth() bool {
	if snap := s.snap(); snap != nil {
		return snap.AcceptUnauthenticated
	}
	return s.cfg.AcceptUnauthenticated
}

func (s *Server) syncAdmission() {
	snap := s.snap()
	if snap == nil {
		return
	}
	s.global.setRate(float64(snap.MaxPerSec), float64(snap.MaxPerSec))
	s.perIP.setRate(float64(snap.MaxPerIP), float64(snap.MaxPerIP))
}

// Start binds ListenPacket("udp") and serves in the background.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return errors.New("snmpsink: already started")
	}
	if s.stopped {
		return errors.New("snmpsink: start after shutdown")
	}
	pc, err := net.ListenPacket("udp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("snmpsink: udp listen: %w", err)
	}
	s.udp = pc
	s.started = true
	s.wg.Add(1)
	go s.serveUDP()
	return nil
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

// Ready is the trap clause: the sink is bound.
func (s *Server) Ready() bool {
	return s != nil && s.cfg.Store != nil && s.Bound()
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

// Store is the inbox this sink inserts into.
func (s *Server) Store() *store.TrapRing {
	if s == nil {
		return nil
	}
	return s.cfg.Store
}

// Shutdown stops the read loop and waits up to ctx.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return nil
	}
	s.stopped = true
	s.cancel()
	udp := s.udp
	s.mu.Unlock()
	if udp != nil {
		_ = udp.Close()
	}
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

func (s *Server) conn() net.PacketConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.udp
}

func (s *Server) serveUDP() {
	defer s.wg.Done()
	max := int(s.cfg.MaxMessageBytes)
	if max < 1 {
		max = 64 << 10
	}
	buf := make([]byte, max+1)
	for {
		if s.ctx.Err() != nil {
			return
		}
		pc := s.conn()
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
			s.handle(pkt, addr)
		}()
	}
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
