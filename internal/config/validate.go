package config

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/hilather/go-lab-snmp/internal/domainerr"
	"github.com/hilather/go-lab-snmp/internal/model"
)

var (
	dnsLabelPattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	usmUserPattern  = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,32}$`)
)

var unsupportedAuthAlgs = map[string]bool{
	"sha384": true, "sha512": true, "sha224": true,
}
var unsupportedPrivAlgs = map[string]bool{
	"aes192": true, "aes256": true,
}

// Validate checks a (preferably normalized) state. Relative secret paths
// are resolved against the process working directory.
func Validate(st *model.State) error {
	return ValidateWithBaseDir(st, "")
}

// ValidateWithBaseDir is Validate plus a directory used when a relative
// secret path is not found in the working directory.
func ValidateWithBaseDir(st *model.State, baseDir string) error {
	if st == nil {
		return domainerr.ValidationFailed("nil state",
			domainerr.FieldViolation{Path: "", Code: violationRequired, Message: "state is nil"})
	}
	var vs []domainerr.FieldViolation
	validateDocument(st, &vs)
	validateListeners(&st.Spec.Listeners, baseDir, &vs)
	validateAuth(&st.Spec.Auth, baseDir, &vs)
	validateEngine(&st.Spec.Engine, &vs)
	validateAgent(&st.Spec.Agent, &vs)
	validateAdmission(&st.Spec.Admission, &vs)
	validateManagement(&st.Spec.Management, &vs)
	mapNames := validateMaps(st.Spec.Maps, &vs)
	validateCommunities(st.Spec.Communities, st.Spec.Agent.Versions, mapNames, baseDir, &vs)
	validateUsers(st.Spec.Users, mapNames, baseDir, &vs)
	agentPlane := agentPlaneWillBind(&st.Spec.Listeners)
	if !agentPlane {
		vs = append(vs, domainerr.FieldViolation{
			Path:    "spec",
			Code:    violationRequired,
			Message: "at least one agent-plane listener is required",
		})
	}
	if agentPlane && len(st.Spec.Communities) == 0 && len(st.Spec.Users) == 0 {
		vs = append(vs, domainerr.FieldViolation{
			Path:    "spec",
			Code:    violationRequired,
			Message: "at least one community or user is required when the agent is enabled",
		})
	}
	validateTraps(&st.Spec.Traps, &vs)
	validateObservability(&st.Spec.Observability, &vs)
	if len(vs) == 0 {
		return nil
	}
	return finishValidate(vs)
}

func finishValidate(vs []domainerr.FieldViolation) error {
	code := domainerr.CodeValidationFailed
	for _, v := range vs {
		switch v.Code {
		case violationUSMAlgUnsupported:
			code = domainerr.CodeUSMAlgUnsupported
		case violationTLSUnsupported:
			if code != domainerr.CodeUSMAlgUnsupported {
				code = domainerr.CodeTLSUnsupported
			}
		case violationUnknownField:
			if code == domainerr.CodeValidationFailed {
				code = domainerr.CodeUnknownField
			}
		case violationReservedKey:
			if code == domainerr.CodeValidationFailed {
				code = domainerr.CodeReservedKey
			}
		}
	}
	return domainerr.New(code, "Candidate state is invalid.").WithViolations(vs...)
}

func validateDocument(st *model.State, vs *[]domainerr.FieldViolation) {
	if st.APIVersion != model.APIVersionV1Alpha1 {
		code := violationUnsupportedVersion
		msg := fmt.Sprintf("apiVersion must be %q", model.APIVersionV1Alpha1)
		if strings.TrimSpace(st.APIVersion) == "" {
			code = violationRequired
			msg = "apiVersion is required"
		}
		*vs = append(*vs, domainerr.FieldViolation{Path: "apiVersion", Code: code, Message: msg})
	}
	if st.Kind != model.KindLabSNMP {
		code := violationInvalidValue
		msg := fmt.Sprintf("kind must be %q", model.KindLabSNMP)
		if strings.TrimSpace(st.Kind) == "" {
			code = violationRequired
			msg = "kind is required"
		}
		*vs = append(*vs, domainerr.FieldViolation{Path: "kind", Code: code, Message: msg})
	}
	if strings.TrimSpace(st.Metadata.Name) == "" {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    "metadata.name",
			Code:    violationRequired,
			Message: "metadata.name is required",
		})
	} else if !dnsLabelPattern.MatchString(st.Metadata.Name) {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    "metadata.name",
			Code:    violationInvalidValue,
			Message: "metadata.name must be a DNS label",
		})
	}
}

func validateListeners(l *model.ListenersSpec, baseDir string, vs *[]domainerr.FieldViolation) {
	validateUDPAddr("spec.listeners.agent.address", l.Agent.Address, vs)
	validateUDPAddr("spec.listeners.traps.address", l.Traps.Address, vs)
	validateTCPListeners(l, vs)
	validateDTLSListeners(l, baseDir, vs)
	if strings.TrimSpace(l.Management.Address) != "" {
		validateTCPAddr("spec.listeners.management.address", l.Management.Address, vs)
	}
	if l.Management.RESTPath != "" && !strings.HasPrefix(l.Management.RESTPath, "/") {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    "spec.listeners.management.restPath",
			Code:    violationInvalidValue,
			Message: "restPath must start with /",
		})
	}
	if l.Management.MCPPath != "" && !strings.HasPrefix(l.Management.MCPPath, "/") {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    "spec.listeners.management.mcpPath",
			Code:    violationInvalidValue,
			Message: "mcpPath must start with /",
		})
	}
}

func tcpAgentOn(l *model.ListenersSpec) bool {
	return l.TCP.Enabled && (l.Agent.Enabled || strings.TrimSpace(l.TCP.Address) != "")
}

func tcpTrapsOn(l *model.ListenersSpec) bool {
	return l.TCP.Enabled && (l.Traps.Enabled || strings.TrimSpace(l.TCP.TrapsAddress) != "")
}

func dtlsAgentOn(l *model.ListenersSpec) bool {
	return l.DTLS.Enabled && strings.TrimSpace(l.DTLS.Address) != ""
}

func agentPlaneWillBind(l *model.ListenersSpec) bool {
	return l.Agent.Enabled || tcpAgentOn(l) || dtlsAgentOn(l)
}

func validateTCPListeners(l *model.ListenersSpec, vs *[]domainerr.FieldViolation) {
	if !l.TCP.Enabled {
		return
	}
	if addr := strings.TrimSpace(l.TCP.Address); addr != "" {
		validateTCPAddr("spec.listeners.tcp.address", addr, vs)
	}
	if addr := strings.TrimSpace(l.TCP.TrapsAddress); addr != "" {
		validateTCPAddr("spec.listeners.tcp.trapsAddress", addr, vs)
	}
	if !tcpAgentOn(l) && !tcpTrapsOn(l) {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    "spec.listeners.tcp.enabled",
			Code:    violationRequired,
			Message: "tcp.enabled requires an agent or trap TCP address",
		})
	}
}

func validateDTLSListeners(l *model.ListenersSpec, baseDir string, vs *[]domainerr.FieldViolation) {
	if !l.DTLS.Enabled {
		return
	}
	if strings.TrimSpace(l.DTLS.CertFile) == "" {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    "spec.listeners.dtls.certFile",
			Code:    violationRequired,
			Message: "certFile is required (file ref, never inline)",
		})
	}
	if strings.TrimSpace(l.DTLS.KeyFile) == "" {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    "spec.listeners.dtls.keyFile",
			Code:    violationRequired,
			Message: "keyFile is required (file ref, never inline)",
		})
	}
	if strings.TrimSpace(l.DTLS.CertFile) != "" && strings.TrimSpace(l.DTLS.KeyFile) != "" {
		validateTLSKeyPair(l.DTLS.CertFile, l.DTLS.KeyFile, baseDir, vs)
	}
	if strings.TrimSpace(l.DTLS.ClientCAFile) != "" {
		validateClientCAFile(l.DTLS.ClientCAFile, baseDir, vs)
	}

	agentAddr := strings.TrimSpace(l.DTLS.Address)
	trapsAddr := strings.TrimSpace(l.DTLS.TrapsAddress)
	if agentAddr != "" {
		validateUDPAddr("spec.listeners.dtls.address", agentAddr, vs)
	}
	if trapsAddr != "" {
		validateUDPAddr("spec.listeners.dtls.trapsAddress", trapsAddr, vs)
	}
	if agentAddr == "" && trapsAddr == "" {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    "spec.listeners.dtls.enabled",
			Code:    violationRequired,
			Message: "dtls.enabled requires an agent or trap DTLS address",
		})
	}
	if l.Agent.Enabled && agentAddr != "" && udpAddrsCollide(l.Agent.Address, agentAddr) {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    "spec.listeners.dtls.address",
			Code:    violationInvalidValue,
			Message: "DTLS and SNMP UDP cannot share a socket",
		})
	}
	if l.Traps.Enabled && trapsAddr != "" && udpAddrsCollide(l.Traps.Address, trapsAddr) {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    "spec.listeners.dtls.trapsAddress",
			Code:    violationInvalidValue,
			Message: "DTLS and SNMP UDP cannot share a socket",
		})
	}
}

func validateTLSKeyPair(certFile, keyFile, baseDir string, vs *[]domainerr.FieldViolation) {
	certPath, err := ResolveFileRef(certFile, baseDir)
	if err != nil {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    "spec.listeners.dtls.certFile",
			Code:    violationInvalidValue,
			Message: "cert file not found",
		})
		return
	}
	keyPath, err := ResolveFileRef(keyFile, baseDir)
	if err != nil {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    "spec.listeners.dtls.keyFile",
			Code:    violationInvalidValue,
			Message: "key file not found",
		})
		return
	}
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    "spec.listeners.dtls.certFile",
			Code:    violationInvalidValue,
			Message: "certFile and keyFile are not a valid X.509 key pair",
		})
	}
}

func validateClientCAFile(path, baseDir string, vs *[]domainerr.FieldViolation) {
	resolved, err := ResolveFileRef(path, baseDir)
	if err != nil {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    "spec.listeners.dtls.clientCAFile",
			Code:    violationInvalidValue,
			Message: "clientCAFile not found",
		})
		return
	}
	b, err := os.ReadFile(resolved)
	if err != nil {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    "spec.listeners.dtls.clientCAFile",
			Code:    violationInvalidValue,
			Message: "clientCAFile not found",
		})
		return
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    "spec.listeners.dtls.clientCAFile",
			Code:    violationInvalidValue,
			Message: "clientCAFile must contain at least one PEM certificate",
		})
	}
}

func udpAddrsCollide(a, b string) bool {
	ca, okA := canonicalUDPAddr(a)
	cb, okB := canonicalUDPAddr(b)
	return okA && okB && ca == cb
}

func canonicalUDPAddr(addr string) (string, bool) {
	ua, err := net.ResolveUDPAddr("udp", strings.TrimSpace(addr))
	if err != nil {
		return "", false
	}
	if ua.IP == nil || ua.IP.IsUnspecified() {
		return fmt.Sprintf("*:%d", ua.Port), true
	}
	return ua.String(), true
}

func validateAuth(a *model.AuthSpec, baseDir string, vs *[]domainerr.FieldViolation) {
	switch a.Mode {
	case "", model.MgmtAuthBearer:
	default:
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    "spec.auth.mode",
			Code:    violationInvalidValue,
			Message: "mode must be bearer",
		})
	}
	ids := map[string]int{}
	for i, tok := range a.Tokens {
		p := fmt.Sprintf("spec.auth.tokens[%d]", i)
		if strings.TrimSpace(tok.ID) == "" {
			*vs = append(*vs, domainerr.FieldViolation{Path: p + ".id", Code: violationEmptyID, Message: "token id is required"})
		} else if !dnsLabelPattern.MatchString(tok.ID) {
			*vs = append(*vs, domainerr.FieldViolation{Path: p + ".id", Code: violationInvalidValue, Message: "token id must be a DNS label"})
		} else if prev, ok := ids[tok.ID]; ok {
			*vs = append(*vs, domainerr.FieldViolation{
				Path:    p + ".id",
				Code:    violationDuplicateID,
				Message: fmt.Sprintf("duplicate token id %q (also tokens[%d])", tok.ID, prev),
			})
		} else {
			ids[tok.ID] = i
		}
		if !model.KnownRole(tok.Role) {
			code := violationInvalidValue
			msg := "role must be administrator or reader"
			if strings.TrimSpace(tok.Role) == "" {
				code = violationRequired
				msg = "role is required"
			}
			*vs = append(*vs, domainerr.FieldViolation{Path: p + ".role", Code: code, Message: msg})
		}
		if strings.TrimSpace(tok.SecretFile) == "" {
			*vs = append(*vs, domainerr.FieldViolation{Path: p + ".secretFile", Code: violationRequired, Message: "secretFile is required (file ref, never inline)"})
			continue
		}
		b, err := trimmedSecret(tok.SecretFile, baseDir)
		if err != nil {
			*vs = append(*vs, domainerr.FieldViolation{
				Path:    p + ".secretFile",
				Code:    violationInvalidValue,
				Message: "secret file not found",
			})
			continue
		}
		if len(b) < MinTokenBytes {
			*vs = append(*vs, domainerr.FieldViolation{
				Path:    p + ".secretFile",
				Code:    violationInvalidValue,
				Message: fmt.Sprintf("token secretFile must be at least %d bytes", MinTokenBytes),
			})
		}
	}
}

func validateEngine(e *model.EngineSpec, vs *[]domainerr.FieldViolation) {
	if e.EngineBoots < 1 {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    "spec.engine.engineBoots",
			Code:    violationInvalidValue,
			Message: "engineBoots must be >= 1",
		})
	}
	id := strings.TrimSpace(e.EngineID)
	if id == "" {
		return
	}
	n, err := engineIDOctets(id)
	if err != nil {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    "spec.engine.engineID",
			Code:    violationInvalidValue,
			Message: "engineID must be hex (optional colons), 5–32 octets",
		})
		return
	}
	if n < MinEngineIDOctets || n > MaxEngineIDOctets {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    "spec.engine.engineID",
			Code:    violationInvalidValue,
			Message: "engineID must be 5–32 octets",
		})
	}
}

func engineIDOctets(s string) (int, error) {
	s = strings.ReplaceAll(s, ":", "")
	s = strings.ReplaceAll(s, " ", "")
	if len(s)%2 != 0 {
		return 0, strconv.ErrSyntax
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func validateAgent(a *model.AgentSpec, vs *[]domainerr.FieldViolation) {
	seen := map[string]bool{}
	for i, v := range a.Versions {
		if !model.KnownSNMPVersion(v) {
			*vs = append(*vs, domainerr.FieldViolation{
				Path:    fmt.Sprintf("spec.agent.versions[%d]", i),
				Code:    violationInvalidValue,
				Message: "versions must be a subset of {v1,v2c,v3}",
			})
		}
		if seen[v] {
			*vs = append(*vs, domainerr.FieldViolation{
				Path:    fmt.Sprintf("spec.agent.versions[%d]", i),
				Code:    violationDuplicateID,
				Message: "duplicate version",
			})
		}
		seen[v] = true
	}
	if a.MaxVarBinds < 1 {
		*vs = append(*vs, domainerr.FieldViolation{Path: "spec.agent.maxVarBinds", Code: violationInvalidValue, Message: "maxVarBinds must be >= 1"})
	}
	if a.MaxRepetitions < 1 {
		*vs = append(*vs, domainerr.FieldViolation{Path: "spec.agent.maxRepetitions", Code: violationInvalidValue, Message: "maxRepetitions must be >= 1"})
	}
	if a.MaxMessageBytes < 1 {
		*vs = append(*vs, domainerr.FieldViolation{Path: "spec.agent.maxMessageBytes", Code: violationInvalidValue, Message: "maxMessageBytes must be >= 1"})
	}
}

func validateAdmission(a *model.AdmissionSpec, vs *[]domainerr.FieldViolation) {
	if a.MaxDatagramsPerSec < 1 {
		*vs = append(*vs, domainerr.FieldViolation{Path: "spec.admission.maxDatagramsPerSec", Code: violationInvalidValue, Message: "maxDatagramsPerSec must be >= 1"})
	}
	if a.MaxDatagramsPerIP < 1 {
		*vs = append(*vs, domainerr.FieldViolation{Path: "spec.admission.maxDatagramsPerIP", Code: violationInvalidValue, Message: "maxDatagramsPerIP must be >= 1"})
	}
	for i, c := range a.AllowClientCidrs {
		if _, err := netip.ParsePrefix(c); err != nil {
			*vs = append(*vs, domainerr.FieldViolation{
				Path:    fmt.Sprintf("spec.admission.allowClientCidrs[%d]", i),
				Code:    violationInvalidValue,
				Message: fmt.Sprintf("invalid CIDR %q", c),
			})
		}
	}
}

func validateManagement(m *model.ManagementSpec, vs *[]domainerr.FieldViolation) {
	if m.BodyLimit < 0 {
		*vs = append(*vs, domainerr.FieldViolation{Path: "spec.management.bodyLimit", Code: violationInvalidValue, Message: "bodyLimit must be >= 0"})
	}
	for i, o := range m.AllowedOrigins {
		if o == "*" {
			*vs = append(*vs, domainerr.FieldViolation{
				Path:    fmt.Sprintf("spec.management.allowedOrigins[%d]", i),
				Code:    violationInvalidValue,
				Message: `"*" is not allowed in allowedOrigins`,
			})
		}
	}
}

func validateMaps(maps []model.MapSpec, vs *[]domainerr.FieldViolation) map[string]int {
	names := map[string]int{}
	for i, m := range maps {
		p := fmt.Sprintf("spec.maps[%d]", i)
		if strings.TrimSpace(m.Name) == "" {
			*vs = append(*vs, domainerr.FieldViolation{Path: p + ".name", Code: violationEmptyID, Message: "map name is required"})
		} else if !dnsLabelPattern.MatchString(m.Name) {
			*vs = append(*vs, domainerr.FieldViolation{Path: p + ".name", Code: violationInvalidValue, Message: "map name must be a DNS label"})
		} else if prev, ok := names[m.Name]; ok {
			*vs = append(*vs, domainerr.FieldViolation{
				Path:    p + ".name",
				Code:    violationDuplicateID,
				Message: fmt.Sprintf("duplicate map name %q (also maps[%d])", m.Name, prev),
			})
		} else {
			names[m.Name] = i
		}
		oids := map[string]int{}
		aliases := map[string]int{}
		for j, o := range m.Objects {
			op := fmt.Sprintf("%s.objects[%d]", p, j)
			if strings.TrimSpace(o.OID) == "" {
				*vs = append(*vs, domainerr.FieldViolation{Path: op + ".oid", Code: violationRequired, Message: "oid is required"})
			} else if err := validateOID(o.OID); err != nil {
				*vs = append(*vs, domainerr.FieldViolation{Path: op + ".oid", Code: violationInvalidValue, Message: err.Error()})
			} else if prev, ok := oids[o.OID]; ok {
				*vs = append(*vs, domainerr.FieldViolation{
					Path:    op + ".oid",
					Code:    violationDuplicateID,
					Message: fmt.Sprintf("duplicate oid %q (also objects[%d])", o.OID, prev),
				})
			} else {
				oids[o.OID] = j
			}
			if alias := strings.TrimSpace(o.Name); alias != "" {
				if prev, ok := aliases[alias]; ok {
					*vs = append(*vs, domainerr.FieldViolation{
						Path:    op + ".name",
						Code:    violationDuplicateID,
						Message: fmt.Sprintf("duplicate object name %q (also objects[%d])", alias, prev),
					})
				} else {
					aliases[alias] = j
				}
			}
			if !model.KnownObjectType(o.Type) {
				code := violationInvalidValue
				msg := "type must be a 1.0 SNMP varbind type"
				if strings.TrimSpace(o.Type) == "" {
					code = violationRequired
					msg = "type is required"
				}
				*vs = append(*vs, domainerr.FieldViolation{Path: op + ".type", Code: code, Message: msg})
			}
			switch o.Access {
			case "", model.AccessRead, model.AccessWrite:
			default:
				*vs = append(*vs, domainerr.FieldViolation{Path: op + ".access", Code: violationInvalidValue, Message: "access must be read or write"})
			}
			vf := strings.TrimSpace(o.ValueFrom)
			if vf != "" && vf != model.ValueFromUptime {
				*vs = append(*vs, domainerr.FieldViolation{
					Path:    op + ".valueFrom",
					Code:    violationInvalidValue,
					Message: "valueFrom must be uptime",
				})
			}
			if vf == model.ValueFromUptime {
				if o.Type != model.TypeTimeTicks {
					*vs = append(*vs, domainerr.FieldViolation{
						Path:    op + ".type",
						Code:    violationInvalidValue,
						Message: "valueFrom uptime requires type timeTicks",
					})
				}
				if o.Access != "" && o.Access != model.AccessRead {
					*vs = append(*vs, domainerr.FieldViolation{
						Path:    op + ".access",
						Code:    violationInvalidValue,
						Message: "valueFrom uptime requires access read",
					})
				}
			}
			if vf == "" && o.Value == nil && o.Type != model.TypeNull {
				*vs = append(*vs, domainerr.FieldViolation{Path: op + ".value", Code: violationRequired, Message: "value is required unless valueFrom is set"})
			}
			if vf != "" && o.Value != nil {
				*vs = append(*vs, domainerr.FieldViolation{Path: op + ".value", Code: violationInvalidValue, Message: "value must be omitted when valueFrom is set"})
			}
			if o.Range != nil && o.Range.Min > o.Range.Max {
				*vs = append(*vs, domainerr.FieldViolation{Path: op + ".range", Code: violationInvalidValue, Message: "range.min must be <= range.max"})
			}
			if o.Size != nil && o.Size.Min > o.Size.Max {
				*vs = append(*vs, domainerr.FieldViolation{Path: op + ".size", Code: violationInvalidValue, Message: "size.min must be <= size.max"})
			}
		}
	}
	return names
}

func validateOID(oid string) error {
	if strings.HasPrefix(oid, ".") {
		return fmt.Errorf("oid must not have a leading dot")
	}
	if strings.TrimSpace(oid) != oid || oid == "" {
		return fmt.Errorf("oid is not a dotted numeric identifier")
	}
	parts := strings.Split(oid, ".")
	if len(parts) < 1 {
		return fmt.Errorf("oid is not a dotted numeric identifier")
	}
	for _, p := range parts {
		if p == "" {
			return fmt.Errorf("oid contains an empty arc")
		}
		if len(p) > 1 && p[0] == '0' {
			return fmt.Errorf("oid arcs must not have leading zeros")
		}
		for _, r := range p {
			if r < '0' || r > '9' {
				return fmt.Errorf("oid must be dotted numeric")
			}
		}
	}
	return nil
}

func validateCommunities(comms []model.CommunitySpec, agentVersions []string, mapNames map[string]int, baseDir string, vs *[]domainerr.FieldViolation) {
	names := map[string]int{}
	wires := map[string]int{}
	agentSet := map[string]bool{}
	for _, v := range agentVersions {
		agentSet[v] = true
	}
	for i, c := range comms {
		p := fmt.Sprintf("spec.communities[%d]", i)
		if strings.TrimSpace(c.Name) == "" {
			*vs = append(*vs, domainerr.FieldViolation{Path: p + ".name", Code: violationEmptyID, Message: "community name is required"})
		} else if !dnsLabelPattern.MatchString(c.Name) {
			*vs = append(*vs, domainerr.FieldViolation{Path: p + ".name", Code: violationInvalidValue, Message: "community name must be a DNS label"})
		} else if prev, ok := names[c.Name]; ok {
			*vs = append(*vs, domainerr.FieldViolation{
				Path:    p + ".name",
				Code:    violationDuplicateID,
				Message: fmt.Sprintf("duplicate community name %q (also communities[%d])", c.Name, prev),
			})
		} else {
			names[c.Name] = i
		}
		if strings.TrimSpace(c.CommunityFile) == "" {
			*vs = append(*vs, domainerr.FieldViolation{Path: p + ".communityFile", Code: violationRequired, Message: "communityFile is required"})
		} else {
			b, err := trimmedSecret(c.CommunityFile, baseDir)
			if err != nil {
				*vs = append(*vs, domainerr.FieldViolation{Path: p + ".communityFile", Code: violationInvalidValue, Message: "community file not found"})
			} else if len(b) == 0 {
				*vs = append(*vs, domainerr.FieldViolation{Path: p + ".communityFile", Code: violationInvalidValue, Message: "communityFile is empty after trim"})
			} else {
				wire := string(b)
				if prev, ok := wires[wire]; ok {
					*vs = append(*vs, domainerr.FieldViolation{
						Path:    p + ".communityFile",
						Code:    violationDuplicateID,
						Message: fmt.Sprintf("duplicate community wire string (also communities[%d])", prev),
					})
				} else {
					wires[wire] = i
				}
			}
		}
		switch c.Access {
		case "", model.AccessRead, model.AccessReadWrite:
		default:
			*vs = append(*vs, domainerr.FieldViolation{Path: p + ".access", Code: violationInvalidValue, Message: "access must be read or read-write"})
		}
		if strings.TrimSpace(c.Map) == "" {
			*vs = append(*vs, domainerr.FieldViolation{Path: p + ".map", Code: violationRequired, Message: "map is required"})
		} else if _, ok := mapNames[c.Map]; !ok {
			*vs = append(*vs, domainerr.FieldViolation{Path: p + ".map", Code: violationInvalidValue, Message: fmt.Sprintf("map %q does not exist", c.Map)})
		}
		if len(c.Versions) == 0 {
			*vs = append(*vs, domainerr.FieldViolation{Path: p + ".versions", Code: violationRequired, Message: "community versions must be non-empty"})
		}
		seenV := map[string]bool{}
		for j, v := range c.Versions {
			if v == model.VersionV3 {
				*vs = append(*vs, domainerr.FieldViolation{
					Path:    fmt.Sprintf("%s.versions[%d]", p, j),
					Code:    violationInvalidValue,
					Message: "communities cannot include v3",
				})
			} else if !model.KnownSNMPVersion(v) {
				*vs = append(*vs, domainerr.FieldViolation{
					Path:    fmt.Sprintf("%s.versions[%d]", p, j),
					Code:    violationInvalidValue,
					Message: "versions must be a subset of {v1,v2c}",
				})
			} else if len(agentSet) > 0 && !agentSet[v] {
				*vs = append(*vs, domainerr.FieldViolation{
					Path:    fmt.Sprintf("%s.versions[%d]", p, j),
					Code:    violationInvalidValue,
					Message: "community version is not enabled on spec.agent.versions",
				})
			}
			if seenV[v] {
				*vs = append(*vs, domainerr.FieldViolation{
					Path:    fmt.Sprintf("%s.versions[%d]", p, j),
					Code:    violationDuplicateID,
					Message: "duplicate version",
				})
			}
			seenV[v] = true
		}
	}
}

func validateUsers(users []model.UserSpec, mapNames map[string]int, baseDir string, vs *[]domainerr.FieldViolation) {
	names := map[string]int{}
	for i, u := range users {
		p := fmt.Sprintf("spec.users[%d]", i)
		if strings.TrimSpace(u.Name) == "" {
			*vs = append(*vs, domainerr.FieldViolation{Path: p + ".name", Code: violationEmptyID, Message: "user name is required"})
		} else if !usmUserPattern.MatchString(u.Name) || utf8.RuneCountInString(u.Name) > MaxUSMUserNameBytes {
			*vs = append(*vs, domainerr.FieldViolation{Path: p + ".name", Code: violationInvalidValue, Message: "user name must be 1–32 USM userName characters"})
		} else if prev, ok := names[u.Name]; ok {
			*vs = append(*vs, domainerr.FieldViolation{
				Path:    p + ".name",
				Code:    violationDuplicateID,
				Message: fmt.Sprintf("duplicate user name %q (also users[%d])", u.Name, prev),
			})
		} else {
			names[u.Name] = i
		}
		switch u.Level {
		case model.LevelNoAuthNoPriv, model.LevelAuthNoPriv, model.LevelAuthPriv:
		case "":
			*vs = append(*vs, domainerr.FieldViolation{Path: p + ".level", Code: violationRequired, Message: "level is required"})
		default:
			*vs = append(*vs, domainerr.FieldViolation{Path: p + ".level", Code: violationInvalidValue, Message: "level must be noAuthNoPriv, authNoPriv, or authPriv"})
		}
		switch u.Access {
		case "", model.AccessRead, model.AccessReadWrite:
		default:
			*vs = append(*vs, domainerr.FieldViolation{Path: p + ".access", Code: violationInvalidValue, Message: "access must be read or read-write"})
		}
		if strings.TrimSpace(u.Map) == "" {
			*vs = append(*vs, domainerr.FieldViolation{Path: p + ".map", Code: violationRequired, Message: "map is required"})
		} else if _, ok := mapNames[u.Map]; !ok {
			*vs = append(*vs, domainerr.FieldViolation{Path: p + ".map", Code: violationInvalidValue, Message: fmt.Sprintf("map %q does not exist", u.Map)})
		}

		needAuth := u.Level == model.LevelAuthNoPriv || u.Level == model.LevelAuthPriv
		needPriv := u.Level == model.LevelAuthPriv
		if u.Level == model.LevelNoAuthNoPriv && u.Auth != nil {
			*vs = append(*vs, domainerr.FieldViolation{Path: p + ".auth", Code: violationInvalidValue, Message: "auth is forbidden on noAuthNoPriv"})
		}
		if !needPriv && u.Priv != nil {
			*vs = append(*vs, domainerr.FieldViolation{Path: p + ".priv", Code: violationInvalidValue, Message: "priv requires authPriv"})
		}
		if needAuth {
			if u.Auth == nil {
				*vs = append(*vs, domainerr.FieldViolation{Path: p + ".auth", Code: violationRequired, Message: "auth is required for this security level"})
			} else {
				validateUSMAuth(p+".auth", u.Auth, baseDir, vs)
			}
		}
		if needPriv {
			if u.Priv == nil {
				*vs = append(*vs, domainerr.FieldViolation{Path: p + ".priv", Code: violationRequired, Message: "priv is required for authPriv"})
			} else {
				validateUSMPriv(p+".priv", u.Priv, baseDir, vs)
			}
		}
		if u.Priv != nil && u.Auth == nil && u.Level != model.LevelNoAuthNoPriv {
			*vs = append(*vs, domainerr.FieldViolation{Path: p + ".priv", Code: violationInvalidValue, Message: "priv requires auth"})
		}
	}
}

func validateUSMAuth(path string, a *model.USMAuth, baseDir string, vs *[]domainerr.FieldViolation) {
	proto := strings.ToLower(strings.TrimSpace(a.Protocol))
	switch proto {
	case model.AuthMD5, model.AuthSHA1, model.AuthSHA256:
	case "":
		*vs = append(*vs, domainerr.FieldViolation{Path: path + ".protocol", Code: violationRequired, Message: "auth.protocol is required"})
	default:
		code := violationInvalidValue
		msg := "auth.protocol must be md5, sha1, or sha256"
		if unsupportedAuthAlgs[proto] {
			code = violationUSMAlgUnsupported
			msg = "auth protocol is not supported in 1.0"
		}
		*vs = append(*vs, domainerr.FieldViolation{Path: path + ".protocol", Code: code, Message: msg})
	}
	validateUSMSecret(path+".secretFile", a.SecretFile, baseDir, vs)
}

func validateUSMPriv(path string, p *model.USMPriv, baseDir string, vs *[]domainerr.FieldViolation) {
	proto := strings.ToLower(strings.TrimSpace(p.Protocol))
	switch proto {
	case model.PrivDES, model.PrivAES128:
	case "":
		*vs = append(*vs, domainerr.FieldViolation{Path: path + ".protocol", Code: violationRequired, Message: "priv.protocol is required"})
	default:
		code := violationInvalidValue
		msg := "priv.protocol must be des or aes128"
		if unsupportedPrivAlgs[proto] {
			code = violationUSMAlgUnsupported
			msg = "priv protocol is not supported in 1.0"
		}
		*vs = append(*vs, domainerr.FieldViolation{Path: path + ".protocol", Code: code, Message: msg})
	}
	validateUSMSecret(path+".secretFile", p.SecretFile, baseDir, vs)
}

func validateUSMSecret(path, file, baseDir string, vs *[]domainerr.FieldViolation) {
	if strings.TrimSpace(file) == "" {
		*vs = append(*vs, domainerr.FieldViolation{Path: path, Code: violationRequired, Message: "secretFile is required (file ref, never inline)"})
		return
	}
	b, err := trimmedSecret(file, baseDir)
	if err != nil {
		*vs = append(*vs, domainerr.FieldViolation{Path: path, Code: violationInvalidValue, Message: "secret file not found"})
		return
	}
	if len(b) < MinUSMSecretBytes {
		*vs = append(*vs, domainerr.FieldViolation{
			Path:    path,
			Code:    violationInvalidValue,
			Message: fmt.Sprintf("USM secretFile must be at least %d bytes", MinUSMSecretBytes),
		})
	}
}

func validateTraps(t *model.TrapStoreSpec, vs *[]domainerr.FieldViolation) {
	if t.MaxMessages < 1 {
		*vs = append(*vs, domainerr.FieldViolation{Path: "spec.traps.maxMessages", Code: violationInvalidValue, Message: "maxMessages must be >= 1"})
	}
	if t.MaxBytes < 1 {
		*vs = append(*vs, domainerr.FieldViolation{Path: "spec.traps.maxBytes", Code: violationInvalidValue, Message: "maxBytes must be >= 1"})
	}
	switch t.FullPolicy {
	case "", model.FullPolicyEvictOldest, model.FullPolicyReject:
	default:
		*vs = append(*vs, domainerr.FieldViolation{Path: "spec.traps.fullPolicy", Code: violationInvalidValue, Message: "fullPolicy must be evict_oldest or reject"})
	}
	if t.MaxWait <= 0 {
		*vs = append(*vs, domainerr.FieldViolation{Path: "spec.traps.maxWait", Code: violationInvalidValue, Message: "maxWait must be > 0"})
	}
}

func validateObservability(o *model.ObservabilitySpec, vs *[]domainerr.FieldViolation) {
	switch o.LogLevel {
	case "", model.LogLevelDebug, model.LogLevelInfo, model.LogLevelWarn, model.LogLevelError:
	default:
		*vs = append(*vs, domainerr.FieldViolation{Path: "spec.observability.logLevel", Code: violationInvalidValue, Message: "logLevel must be debug, info, warn, or error"})
	}
}

func validateUDPAddr(path, addr string, vs *[]domainerr.FieldViolation) {
	if strings.TrimSpace(addr) == "" {
		*vs = append(*vs, domainerr.FieldViolation{Path: path, Code: violationRequired, Message: "address is required"})
		return
	}
	if _, err := net.ResolveUDPAddr("udp", addr); err != nil {
		*vs = append(*vs, domainerr.FieldViolation{Path: path, Code: violationInvalidValue, Message: "invalid UDP host:port"})
	}
}

func validateTCPAddr(path, addr string, vs *[]domainerr.FieldViolation) {
	if strings.TrimSpace(addr) == "" {
		*vs = append(*vs, domainerr.FieldViolation{Path: path, Code: violationRequired, Message: "address is required"})
		return
	}
	if _, err := net.ResolveTCPAddr("tcp", addr); err != nil {
		*vs = append(*vs, domainerr.FieldViolation{Path: path, Code: violationInvalidValue, Message: "invalid TCP host:port"})
	}
}
