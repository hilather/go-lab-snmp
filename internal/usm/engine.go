package usm

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hilather/go-lab-snmp/internal/domainerr"
	"github.com/hilather/go-lab-snmp/internal/model"
	"github.com/hilather/go-lab-snmp/internal/snmpwire"
)

const (
	minEngineIDOctets = 5
	maxEngineIDOctets = 32
	maxEngineBoots    = 2147483647
	maxEngineTime     = 2147483646
	defaultBoots      = 1
)

// Clock is an injectable time source. Tests use testutil.FakeClock.
type Clock interface {
	Now() time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// Config constructs an authoritative SNMP engine.
type Config struct {
	EngineID    []byte
	EngineIDHex string
	EngineBoots int32
	Hostname    string
	Clock       Clock
}

// Engine is the local SNMPv3 engine: identity, users, and usmStats.
type Engine struct {
	mu    sync.Mutex
	id    []byte
	boots int32
	start time.Time
	clock Clock
	users map[string]*User
	stats Stats
	salt  uint64
}

// Stats are RFC 3414 usmStats counters. They appear in Report PDUs only.
type Stats struct {
	UnsupportedSecLevels uint32
	NotInTimeWindows     uint32
	UnknownUserNames     uint32
	UnknownEngineIDs     uint32
	WrongDigests         uint32
	DecryptionErrors     uint32
}

// User is a compiled USM principal. Keys are localized to this engine.
type User struct {
	Name         string
	Level        string
	AuthProtocol string
	PrivProtocol string
	Access       string
	Map          string

	authKey  []byte
	privKey  []byte
	authPass []byte
	privPass []byte
}

// UserConfig is one user plus passphrases (file contents, already trimmed).
type UserConfig struct {
	Name           string
	Level          string
	AuthProtocol   string
	AuthPassphrase []byte
	PrivProtocol   string
	PrivPassphrase []byte
	Access         string
	Map            string
}

// New builds an engine. Empty EngineID is derived per the 1.0 spec.
func New(cfg Config) (*Engine, error) {
	id, err := resolveEngineID(cfg)
	if err != nil {
		return nil, err
	}
	boots := cfg.EngineBoots
	if boots == 0 {
		boots = defaultBoots
	}
	if boots < 1 {
		return nil, fmt.Errorf("usm: engineBoots must be >= 1")
	}
	clk := cfg.Clock
	if clk == nil {
		clk = systemClock{}
	}
	return &Engine{
		id:    bytes.Clone(id),
		boots: boots,
		start: clk.Now(),
		clock: clk,
		users: make(map[string]*User),
	}, nil
}

func resolveEngineID(cfg Config) ([]byte, error) {
	if len(cfg.EngineID) > 0 {
		if len(cfg.EngineID) < minEngineIDOctets || len(cfg.EngineID) > maxEngineIDOctets {
			return nil, fmt.Errorf("usm: engineID must be 5–32 octets")
		}
		return cfg.EngineID, nil
	}
	if strings.TrimSpace(cfg.EngineIDHex) != "" {
		return ParseEngineID(cfg.EngineIDHex)
	}
	host := cfg.Hostname
	if host == "" {
		var err error
		host, err = os.Hostname()
		if err != nil || host == "" {
			host = "localhost"
		}
	}
	return DeriveEngineID(host), nil
}

// DeriveEngineID is the 1.0 default: enterprise 0, text "labsnmp", hostname hash.
func DeriveEngineID(hostname string) []byte {
	sum := sha256.Sum256([]byte(hostname))
	id := make([]byte, 0, 20)
	id = append(id, 0x80, 0x00, 0x00, 0x00) // enterprise 0, MSB set
	id = append(id, 0x04)                   // RFC 3411 text format
	id = append(id, []byte("labsnmp")...)
	id = append(id, sum[:8]...)
	return id
}

// ParseEngineID decodes hex with optional colons, 5–32 octets.
func ParseEngineID(s string) ([]byte, error) {
	s = strings.ReplaceAll(strings.TrimSpace(s), ":", "")
	s = strings.ReplaceAll(s, " ", "")
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("usm: engineID must be hex (optional colons), 5–32 octets")
	}
	if len(b) < minEngineIDOctets || len(b) > maxEngineIDOctets {
		return nil, fmt.Errorf("usm: engineID must be 5–32 octets")
	}
	return b, nil
}

// ID returns a copy of the local engineID.
func (e *Engine) ID() []byte {
	e.mu.Lock()
	defer e.mu.Unlock()
	return bytes.Clone(e.id)
}

// BootsTime returns snmpEngineBoots and process-clock snmpEngineTime.
func (e *Engine) BootsTime() (boots, engineTime int32) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.bootsTimeLocked()
}

func (e *Engine) bootsTimeLocked() (int32, int32) {
	d := e.clock.Now().Sub(e.start) / time.Second
	if d < 0 {
		d = 0
	}
	if d > maxEngineTime {
		d = maxEngineTime
	}
	return e.boots, int32(d)
}

// Stats returns a snapshot of usmStats counters.
func (e *Engine) Stats() Stats {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stats
}

// User looks up a compiled user by USM userName.
func (e *Engine) User(name string) *User {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.users[name]
}

// AddUser localizes keys for one user onto this engine.
func (e *Engine) AddUser(cfg UserConfig) error {
	u, err := compileUser(cfg, e.ID())
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.users[u.Name]; ok {
		return fmt.Errorf("usm: duplicate user %q", u.Name)
	}
	e.users[u.Name] = u
	return nil
}

func compileUser(cfg UserConfig, engineID []byte) (*User, error) {
	name := strings.TrimSpace(cfg.Name)
	if name == "" {
		return nil, fmt.Errorf("usm: user name is required")
	}
	u := &User{
		Name:         name,
		Level:        cfg.Level,
		AuthProtocol: strings.ToLower(strings.TrimSpace(cfg.AuthProtocol)),
		PrivProtocol: strings.ToLower(strings.TrimSpace(cfg.PrivProtocol)),
		Access:       cfg.Access,
		Map:          cfg.Map,
		authPass:     bytes.Clone(cfg.AuthPassphrase),
		privPass:     bytes.Clone(cfg.PrivPassphrase),
	}
	switch u.Level {
	case model.LevelNoAuthNoPriv:
		if u.AuthProtocol != "" || u.PrivProtocol != "" {
			return nil, fmt.Errorf("usm: auth/priv forbidden on noAuthNoPriv")
		}
		return u, nil
	case model.LevelAuthNoPriv:
		if u.PrivProtocol != "" {
			return nil, fmt.Errorf("usm: priv requires authPriv")
		}
		if err := u.localizeAuth(engineID); err != nil {
			return nil, err
		}
		return u, nil
	case model.LevelAuthPriv:
		if err := u.localizeAuth(engineID); err != nil {
			return nil, err
		}
		if err := u.localizePriv(engineID); err != nil {
			return nil, err
		}
		return u, nil
	default:
		return nil, fmt.Errorf("usm: level must be noAuthNoPriv, authNoPriv, or authPriv")
	}
}

func (u *User) localizeAuth(engineID []byte) error {
	if _, err := lookupAuth(u.AuthProtocol); err != nil {
		return err
	}
	key, err := Localize(u.AuthProtocol, u.authPass, engineID)
	if err != nil {
		return err
	}
	u.authKey = key
	return nil
}

func (u *User) localizePriv(engineID []byte) error {
	if _, err := lookupPriv(u.PrivProtocol); err != nil {
		return err
	}
	// Privacy key uses the auth hash (RFC 3414 A.2 / RFC 3826).
	key, err := Localize(u.AuthProtocol, u.privPass, engineID)
	if err != nil {
		return err
	}
	u.privKey = key
	return nil
}

// Localize derives a localized key from a passphrase (RFC 3414 A.2 / RFC 7860).
func Localize(authProtocol string, passphrase, engineID []byte) ([]byte, error) {
	alg, err := lookupAuth(authProtocol)
	if err != nil {
		return nil, err
	}
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("usm: empty passphrase")
	}
	if len(engineID) < minEngineIDOctets || len(engineID) > maxEngineIDOctets {
		return nil, fmt.Errorf("usm: engineID must be 5–32 octets")
	}
	ku := passwordToKey(alg.new, passphrase)
	return localizeKey(alg.new, ku, engineID), nil
}

func lookupAuth(proto string) (authAlg, error) {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case model.AuthMD5:
		return authMD5, nil
	case model.AuthSHA1:
		return authSHA1, nil
	case model.AuthSHA256:
		return authSHA256, nil
	case "":
		return authAlg{}, fmt.Errorf("usm: auth.protocol is required")
	default:
		return authAlg{}, domainerr.USMAlgUnsupported("auth protocol is not supported in 1.0")
	}
}

func lookupPriv(proto string) (privAlg, error) {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case model.PrivDES:
		return privDES, nil
	case model.PrivAES128:
		return privAES128, nil
	case "":
		return privAlg{}, fmt.Errorf("usm: priv.protocol is required")
	default:
		return privAlg{}, domainerr.USMAlgUnsupported("priv protocol is not supported in 1.0")
	}
}

// LocalizeFor derives auth/priv keys for engineID (trap sink: sender is authoritative).
func (u *User) LocalizeFor(engineID []byte) (authKey, privKey []byte, err error) {
	if u == nil {
		return nil, nil, fmt.Errorf("usm: nil user")
	}
	if u.AuthProtocol != "" {
		authKey, err = Localize(u.AuthProtocol, u.authPass, engineID)
		if err != nil {
			return nil, nil, err
		}
	}
	if u.PrivProtocol != "" {
		privKey, err = Localize(u.AuthProtocol, u.privPass, engineID)
		if err != nil {
			return nil, nil, err
		}
	}
	return authKey, privKey, nil
}

// Flags returns msgFlags for a security level.
func Flags(level string, reportable bool) byte {
	var f byte
	switch level {
	case model.LevelAuthNoPriv:
		f = snmpwire.FlagAuth
	case model.LevelAuthPriv:
		f = snmpwire.FlagAuth | snmpwire.FlagPriv
	}
	if reportable {
		f |= snmpwire.FlagReportable
	}
	return f
}
