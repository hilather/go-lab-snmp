package model

import "time"

const (
	MgmtAuthBearer = "bearer"

	RoleAdministrator = "administrator"
	RoleReader        = "reader"

	ScopeSNMPRead      = "snmp.read"
	ScopeSNMPWrite     = "snmp.write"
	ScopeSNMPAdmin     = "snmp.admin"
	ScopeSNMPAuditRead = "snmp.audit.read"

	LogLevelDebug = "debug"
	LogLevelInfo  = "info"
	LogLevelWarn  = "warn"
	LogLevelError = "error"

	VersionV1  = "v1"
	VersionV2c = "v2c"
	VersionV3  = "v3"

	AccessRead      = "read"
	AccessReadWrite = "read-write"
	AccessWrite     = "write"

	LevelNoAuthNoPriv = "noAuthNoPriv"
	LevelAuthNoPriv   = "authNoPriv"
	LevelAuthPriv     = "authPriv"

	AuthMD5    = "md5"
	AuthSHA1   = "sha1"
	AuthSHA256 = "sha256"

	PrivDES    = "des"
	PrivAES128 = "aes128"

	ValueFromUptime = "uptime"

	TypeInteger          = "integer"
	TypeOctetString      = "octetString"
	TypeObjectIdentifier = "objectIdentifier"
	TypeNull             = "null"
	TypeIPAddress        = "ipAddress"
	TypeCounter32        = "counter32"
	TypeGauge32          = "gauge32"
	TypeUnsigned32       = "unsigned32"
	TypeTimeTicks        = "timeTicks"
	TypeOpaque           = "opaque"
	TypeCounter64        = "counter64"

	FullPolicyEvictOldest = "evict_oldest"
	FullPolicyReject      = "reject"
)

// KnownRole reports whether role is a v1alpha1 token role.
func KnownRole(role string) bool {
	switch role {
	case RoleAdministrator, RoleReader:
		return true
	default:
		return false
	}
}

// ScopesForRole returns the frozen scope set for a token role.
func ScopesForRole(role string) []string {
	switch role {
	case RoleAdministrator:
		return []string{ScopeSNMPRead, ScopeSNMPWrite, ScopeSNMPAdmin, ScopeSNMPAuditRead}
	case RoleReader:
		return []string{ScopeSNMPRead}
	default:
		return nil
	}
}

// KnownObjectType reports whether t is a 1.0 YAML BER type name.
func KnownObjectType(t string) bool {
	switch t {
	case TypeInteger, TypeOctetString, TypeObjectIdentifier, TypeNull,
		TypeIPAddress, TypeCounter32, TypeGauge32, TypeUnsigned32,
		TypeTimeTicks, TypeOpaque, TypeCounter64:
		return true
	default:
		return false
	}
}

// KnownSNMPVersion reports whether v is v1, v2c, or v3.
func KnownSNMPVersion(v string) bool {
	switch v {
	case VersionV1, VersionV2c, VersionV3:
		return true
	default:
		return false
	}
}

// ListenersSpec configures agent, trap, and management listeners.
type ListenersSpec struct {
	Agent      UDPListenerSpec  `json:"agent"`
	Traps      UDPListenerSpec  `json:"traps"`
	DTLS       ToggleSpec       `json:"dtls"`
	TCP        ToggleSpec       `json:"tcp"`
	Management MgmtListenerSpec `json:"management"`
}

// UDPListenerSpec is a data-plane UDP listener.
type UDPListenerSpec struct {
	Enabled bool   `json:"enabled"`
	Address string `json:"address"`
}

// ToggleSpec is a schema key that 1.0 must keep false.
type ToggleSpec struct {
	Enabled bool `json:"enabled"`
}

// MgmtListenerSpec is the control-plane HTTP listener.
type MgmtListenerSpec struct {
	Address  string `json:"address"`
	RESTPath string `json:"restPath"`
	MCPPath  string `json:"mcpPath"`
}

// AuthSpec is spec.auth (not spec.management.auth).
type AuthSpec struct {
	Mode   string      `json:"mode"`
	Tokens []TokenSpec `json:"tokens"`
}

// TokenSpec is one static bearer principal. Secrets are file refs only.
// 1.0 has no scopes field; role expands to the frozen set.
type TokenSpec struct {
	ID         string `json:"id"`
	Role       string `json:"role"`
	SecretFile string `json:"secretFile"`
}

// EngineSpec is the SNMPv3 engine identity. engineID empty means derived.
type EngineSpec struct {
	EngineID    string `json:"engineID,omitempty"`
	EngineBoots int    `json:"engineBoots"`
}

// AgentSpec is PDU caps and advertised versions.
type AgentSpec struct {
	Versions        []string `json:"versions"`
	MaxVarBinds     int      `json:"maxVarBinds"`
	MaxRepetitions  int      `json:"maxRepetitions"`
	MaxMessageBytes int64    `json:"maxMessageBytes"`
}

// AdmissionSpec is CIDR reachability and datagram token buckets.
type AdmissionSpec struct {
	AllowClientCidrs   []string `json:"allowClientCidrs"`
	MaxDatagramsPerSec int      `json:"maxDatagramsPerSec"`
	MaxDatagramsPerIP  int      `json:"maxDatagramsPerIP"`
}

// MapSpec is one named collection of instance leaves.
type MapSpec struct {
	Name    string       `json:"name"`
	Objects []ObjectSpec `json:"objects"`
}

// ObjectSpec is one explicit instance leaf (ADR 0008).
type ObjectSpec struct {
	OID       string     `json:"oid"`
	Name      string     `json:"name,omitempty"`
	Type      string     `json:"type"`
	Access    string     `json:"access"`
	Value     any        `json:"value,omitempty"`
	ValueFrom string     `json:"valueFrom,omitempty"`
	Range     *RangeSpec `json:"range,omitempty"`
	Size      *RangeSpec `json:"size,omitempty"`
}

// Object is an instance leaf. YAML decode uses ObjectSpec; mibtree.Compile
// takes the same fields.
type Object = ObjectSpec

// RangeSpec is inclusive min/max for integer types or octet length.
type RangeSpec struct {
	Min int64 `json:"min"`
	Max int64 `json:"max"`
}

// CommunitySpec is one v1/v2c identity. name is a DNS-label row id;
// communityFile is required; the wire string is trimmed file contents.
type CommunitySpec struct {
	Name          string   `json:"name"`
	CommunityFile string   `json:"communityFile"`
	Versions      []string `json:"versions,omitempty"`
	Access        string   `json:"access"`
	Map           string   `json:"map"`
}

// UserSpec is one SNMPv3 USM user.
type UserSpec struct {
	Name   string   `json:"name"`
	Level  string   `json:"level"`
	Auth   *USMAuth `json:"auth,omitempty"`
	Priv   *USMPriv `json:"priv,omitempty"`
	Access string   `json:"access"`
	Map    string   `json:"map"`
}

// USMAuth is USM authentication protocol + passphrase file.
type USMAuth struct {
	Protocol   string `json:"protocol"`
	SecretFile string `json:"secretFile"`
}

// USMPriv is USM privacy protocol + passphrase file.
type USMPriv struct {
	Protocol   string `json:"protocol"`
	SecretFile string `json:"secretFile"`
}

// TrapStoreSpec is the in-memory trap/inform inbox policy.
type TrapStoreSpec struct {
	MaxMessages           int           `json:"maxMessages"`
	MaxBytes              int64         `json:"maxBytes"`
	FullPolicy            string        `json:"fullPolicy"`
	MaxWait               time.Duration `json:"maxWait"`
	AcceptUnauthenticated bool          `json:"acceptUnauthenticated"`
	RawRetain             bool          `json:"rawRetain"`
}

// UISpec is spec.ui.enabled.
type UISpec struct {
	Enabled bool `json:"enabled"`
}

// ManagementSpec is origins, MCP, and HTTP limits — not ui, not auth.
type ManagementSpec struct {
	AllowedOrigins []string `json:"allowedOrigins"`
	MCP            MCPSpec  `json:"mcp"`
	BodyLimit      int64    `json:"bodyLimit"`
}

// MCPSpec is management MCP adapter knobs.
type MCPSpec struct {
	AllowLegacyClients bool `json:"allowLegacyClients"`
}

// ObservabilitySpec is log level and metrics bind.
type ObservabilitySpec struct {
	LogLevel string      `json:"logLevel"`
	Metrics  MetricsSpec `json:"metrics"`
}

// MetricsSpec is hand-rolled OpenMetrics scrape policy.
type MetricsSpec struct {
	PublicPath bool `json:"publicPath"`
}
