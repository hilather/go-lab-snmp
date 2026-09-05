package mcp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/hilather/go-lab-snmp/internal/app"
	"github.com/hilather/go-lab-snmp/internal/buildinfo"
	"github.com/hilather/go-lab-snmp/internal/config"
	"github.com/hilather/go-lab-snmp/internal/domainerr"
	"github.com/hilather/go-lab-snmp/internal/mibtree"
	"github.com/hilather/go-lab-snmp/internal/model"
	"github.com/hilather/go-lab-snmp/internal/store"
)

type emptyIn struct{}

type idIn struct {
	ID string `json:"id"`
}

type nameIn struct {
	Name string `json:"name"`
}

type exportIn struct {
	Format string `json:"format,omitempty"`
}

type changeIn struct {
	ExpectedRevision string            `json:"expectedRevision,omitempty"`
	IdempotencyKey   string            `json:"idempotencyKey,omitempty"`
	Reason           string            `json:"reason,omitempty"`
	Force            bool              `json:"force,omitempty"`
	Operations       []model.Operation `json:"operations,omitempty"`
}

type validateIn struct {
	State      json.RawMessage   `json:"state,omitempty"`
	Operations []model.Operation `json:"operations,omitempty"`
}

type resetIn struct {
	Reason string `json:"reason,omitempty"`
}

type mapQueryIn struct {
	Name           string   `json:"name"`
	PDU            string   `json:"pdu"`
	OIDs           []string `json:"oids"`
	NonRepeaters   int      `json:"nonRepeaters,omitempty"`
	MaxRepetitions int      `json:"maxRepetitions,omitempty"`
}

type oidGetIn struct {
	Name string `json:"name"`
	OID  string `json:"oid"`
}

type oidSetIn struct {
	Name  string `json:"name"`
	OID   string `json:"oid"`
	Value any    `json:"value"`
}

type previewIn struct {
	Community string `json:"community,omitempty"`
	User      string `json:"user,omitempty"`
	OID       string `json:"oid"`
}

type trapListIn struct {
	Limit           int    `json:"limit,omitempty"`
	After           string `json:"after,omitempty"`
	Version         string `json:"version,omitempty"`
	PDUType         string `json:"pduType,omitempty"`
	Community       string `json:"community,omitempty"`
	User            string `json:"user,omitempty"`
	NotificationOID string `json:"notificationOID,omitempty"`
	Since           string `json:"since,omitempty"`
}

type trapWaitIn struct {
	Timeout         string `json:"timeout,omitempty"`
	Version         string `json:"version,omitempty"`
	PDUType         string `json:"pduType,omitempty"`
	Community       string `json:"community,omitempty"`
	User            string `json:"user,omitempty"`
	NotificationOID string `json:"notificationOID,omitempty"`
	Since           string `json:"since,omitempty"`
}

type auditQueryIn struct {
	Limit int `json:"limit,omitempty"`
}

func (in changeIn) toChange() app.ChangeIn {
	return app.ChangeIn{
		ExpectedRevision: model.Revision(in.ExpectedRevision),
		IdempotencyKey:   in.IdempotencyKey,
		Reason:           in.Reason,
		Force:            in.Force,
		Operations:       in.Operations,
	}
}

func (in validateIn) toValidate() (app.ValidateIn, error) {
	st, err := decodeCandidateState(in.State)
	if err != nil {
		return app.ValidateIn{}, err
	}
	return app.ValidateIn{State: st, Operations: in.Operations}, nil
}

func decodeCandidateState(raw json.RawMessage) (*model.State, error) {
	raw = json.RawMessage(strings.TrimSpace(string(raw)))
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	return config.DecodeJSON(raw)
}

func requireName(name string) error {
	if name == "" {
		return domainerr.ValidationFailed("name is required",
			domainerr.FieldViolation{Path: "name", Code: "required", Message: "name is required"})
	}
	return nil
}

func requireID(id string) error {
	if id == "" {
		return domainerr.ValidationFailed("id is required",
			domainerr.FieldViolation{Path: "id", Code: "required", Message: "id is required"})
	}
	return nil
}

type versionJSON struct {
	Version   string           `json:"version"`
	Commit    string           `json:"commit"`
	BuildTime string           `json:"buildTime"`
	Protocols versionProtocols `json:"protocols"`
}

type versionProtocols struct {
	ConfigAPI string `json:"configAPI"`
	REST      string `json:"rest"`
	MCP       string `json:"mcp"`
}

type capabilityViewJSON struct {
	Capabilities []capabilityInfoJSON `json:"capabilities"`
}

type capabilityInfoJSON struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Mutating    bool   `json:"mutating"`
	Idempotent  bool   `json:"idempotent"`
}

type statusJSON struct {
	Ready     bool            `json:"ready"`
	Revisions json.RawMessage `json:"revisions"`
	Listeners []listenerJSON  `json:"listeners"`
	HostTime  string          `json:"hostTime"`
	Warnings  []app.Warning   `json:"warnings,omitempty"`
}

type listenerJSON struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

type stateViewJSON struct {
	BootstrapRevision string          `json:"bootstrapRevision"`
	RuntimeRevision   string          `json:"runtimeRevision"`
	Generation        uint64          `json:"generation"`
	StoreGeneration   uint64          `json:"storeGeneration"`
	Drifted           bool            `json:"drifted"`
	LoadedAt          string          `json:"loadedAt,omitempty"`
	Canonical         json.RawMessage `json:"canonical"`
}

type planJSON struct {
	PreviousRevision  string            `json:"previousRevision"`
	CandidateRevision string            `json:"candidateRevision"`
	Drifted           bool              `json:"drifted"`
	Diff              []app.DiffEntry   `json:"diff"`
	Warnings          []app.Warning     `json:"warnings,omitempty"`
	Operations        []model.Operation `json:"operations,omitempty"`
	Applied           bool              `json:"applied,omitempty"`
	Generation        uint64            `json:"generation,omitempty"`
	RuntimeRevision   string            `json:"runtimeRevision,omitempty"`
	StoreGeneration   uint64            `json:"storeGeneration,omitempty"`
	AuditEventID      string            `json:"auditEventId,omitempty"`
}

type exportJSON struct {
	Format            string `json:"format"`
	Revision          string `json:"revision"`
	BootstrapRevision string `json:"bootstrapRevision"`
	Drifted           bool   `json:"drifted"`
	Body              string `json:"body"`
	HumanDiff         string `json:"humanDiff,omitempty"`
}

type oidResultJSON struct {
	OID       string `json:"oid"`
	Type      string `json:"type,omitempty"`
	Value     any    `json:"value,omitempty"`
	Exception string `json:"exception,omitempty"`
	Overlay   bool   `json:"overlay,omitempty"`
}

type trapJSON struct {
	ID              string        `json:"id"`
	ReceivedAt      string        `json:"receivedAt,omitempty"`
	Version         string        `json:"version,omitempty"`
	PDUType         string        `json:"pduType,omitempty"`
	Community       string        `json:"community,omitempty"`
	User            string        `json:"user,omitempty"`
	RemoteAddr      string        `json:"remoteAddr,omitempty"`
	Enterprise      string        `json:"enterprise,omitempty"`
	NotificationOID string        `json:"notificationOID,omitempty"`
	VarBinds        []varBindJSON `json:"varBinds,omitempty"`
	ParseWarning    string        `json:"parseWarning,omitempty"`
	Size            int64         `json:"size,omitempty"`
}

type varBindJSON struct {
	OID      string `json:"oid"`
	Type     string `json:"type,omitempty"`
	Integer  int64  `json:"integer,omitempty"`
	Unsigned uint64 `json:"unsigned,omitempty"`
	Bytes    string `json:"bytes,omitempty"`
	OIDValue string `json:"oidValue,omitempty"`
}

type statsJSON struct {
	Traps             trapStatsJSON `json:"traps"`
	OverlayGeneration uint64        `json:"overlayGeneration"`
	Queries           int           `json:"queries"`
}

type trapStatsJSON struct {
	Messages   int    `json:"messages"`
	Bytes      int64  `json:"bytes"`
	Generation uint64 `json:"generation"`
	Dropped    int64  `json:"dropped"`
}

type rawBodyJSON struct {
	ID          string `json:"id"`
	ContentType string `json:"contentType"`
	Body        string `json:"body"`
}

func fromVersion(info buildinfo.Info) versionJSON {
	return versionJSON{
		Version:   info.Version,
		Commit:    info.Commit,
		BuildTime: info.BuildTime,
		Protocols: versionProtocols{
			ConfigAPI: info.Protocols.ConfigAPI,
			REST:      info.Protocols.REST,
			MCP:       info.Protocols.MCP,
		},
	}
}

func fromCapabilities(view *app.CapabilityView) capabilityViewJSON {
	if view == nil {
		return capabilityViewJSON{Capabilities: []capabilityInfoJSON{}}
	}
	out := make([]capabilityInfoJSON, 0, len(view.Capabilities))
	for _, d := range view.Capabilities {
		out = append(out, capabilityInfoJSON{
			Name: d.Name, Version: d.Version, Description: d.Description,
			Mutating: d.Mutating, Idempotent: d.Idempotent,
		})
	}
	return capabilityViewJSON{Capabilities: out}
}

func fromStatus(st *app.Status) (statusJSON, error) {
	if st == nil {
		return statusJSON{Listeners: []listenerJSON{}}, nil
	}
	rev, err := marshalAPI(st.Revisions)
	if err != nil {
		return statusJSON{}, err
	}
	listeners := make([]listenerJSON, 0, len(st.Listeners))
	for _, l := range st.Listeners {
		listeners = append(listeners, listenerJSON{Name: l.Name, Address: l.Address})
	}
	return statusJSON{
		Ready:     st.Ready,
		Revisions: rev,
		Listeners: listeners,
		HostTime:  rfc3339(st.HostTime),
		Warnings:  st.Warnings,
	}, nil
}

func fromStateView(v *app.StateView) (stateViewJSON, error) {
	if v == nil {
		return stateViewJSON{}, nil
	}
	canon, err := marshalAPI(v.Canonical)
	if err != nil {
		return stateViewJSON{}, err
	}
	return stateViewJSON{
		BootstrapRevision: string(v.BootstrapRevision),
		RuntimeRevision:   string(v.RuntimeRevision),
		Generation:        uint64(v.Generation),
		StoreGeneration:   v.StoreGeneration,
		Drifted:           v.Drifted,
		LoadedAt:          rfc3339(v.LoadedAt),
		Canonical:         canon,
	}, nil
}

func fromPlan(p *app.Plan) planJSON {
	if p == nil {
		return planJSON{Diff: []app.DiffEntry{}}
	}
	return planJSON{
		PreviousRevision:  string(p.PreviousRevision),
		CandidateRevision: string(p.CandidateRevision),
		Drifted:           p.Drifted,
		Diff:              p.Diff,
		Warnings:          p.Warnings,
		Operations:        p.Operations,
	}
}

func fromApply(r *app.ApplyResult) planJSON {
	if r == nil {
		return planJSON{Diff: []app.DiffEntry{}}
	}
	out := fromPlan(&r.Plan)
	out.Applied = r.Applied
	out.Generation = uint64(r.Generation)
	out.RuntimeRevision = string(r.RuntimeRevision)
	out.StoreGeneration = r.StoreGeneration
	out.AuditEventID = r.AuditEventID
	return out
}

func fromExport(exp *app.Export) exportJSON {
	if exp == nil {
		return exportJSON{}
	}
	return exportJSON{
		Format:            string(exp.Format),
		Revision:          string(exp.Revision),
		BootstrapRevision: string(exp.BootstrapRevision),
		Drifted:           exp.Drifted,
		Body:              string(exp.Body),
		HumanDiff:         exp.HumanDiff,
	}
}

func fromOIDResult(r *app.OIDResult) oidResultJSON {
	if r == nil {
		return oidResultJSON{}
	}
	out := oidResultJSON{
		OID:       r.OID,
		Exception: r.Exception,
		Overlay:   r.Overlay,
	}
	if r.Exception == "" || r.Exception == "noError" {
		out.Exception = ""
		out.Type = r.Value.Type
		out.Value = valueJSON(r.Value)
	}
	return out
}

func fromTrap(rec *store.TrapRecord) trapJSON {
	if rec == nil {
		return trapJSON{}
	}
	out := trapJSON{
		ID:              rec.ID,
		ReceivedAt:      rfc3339(rec.ReceivedAt),
		Version:         rec.Version,
		PDUType:         rec.PDUType,
		Community:       rec.Community,
		User:            rec.User,
		RemoteAddr:      rec.RemoteAddr,
		Enterprise:      rec.Enterprise,
		NotificationOID: rec.NotificationOID,
		ParseWarning:    rec.ParseWarning,
		Size:            rec.Size,
	}
	for _, vb := range rec.VarBinds {
		item := varBindJSON{OID: vb.OID, Type: vb.Type, Integer: vb.Integer, Unsigned: vb.Unsigned, OIDValue: vb.OIDValue}
		if len(vb.Bytes) > 0 {
			if isPrintable(vb.Bytes) {
				item.Bytes = string(vb.Bytes)
			} else {
				item.Bytes = base64.StdEncoding.EncodeToString(vb.Bytes)
			}
		}
		out.VarBinds = append(out.VarBinds, item)
	}
	return out
}

func fromStats(st *app.Stats) statsJSON {
	if st == nil {
		return statsJSON{}
	}
	return statsJSON{
		Traps: trapStatsJSON{
			Messages:   st.Traps.Messages,
			Bytes:      st.Traps.Bytes,
			Generation: st.Traps.Generation,
			Dropped:    st.Traps.Dropped,
		},
		OverlayGeneration: st.OverlayGeneration,
		Queries:           st.Queries,
	}
}

func fromAuditList(list *app.AuditList) any {
	events := []app.AuditEvent{}
	if list != nil && list.Events != nil {
		events = list.Events
	}
	return map[string]any{"events": events}
}

func valueJSON(v mibtree.Value) any {
	switch v.Type {
	case model.TypeInteger:
		return v.Signed
	case model.TypeCounter32, model.TypeGauge32, model.TypeUnsigned32, model.TypeTimeTicks, model.TypeCounter64:
		return json.Number(strconv.FormatUint(v.Unsigned, 10))
	case model.TypeOctetString, model.TypeOpaque:
		if isPrintable(v.Bytes) {
			return string(v.Bytes)
		}
		return base64.StdEncoding.EncodeToString(v.Bytes)
	case model.TypeIPAddress:
		if len(v.Bytes) == 4 {
			return fmt.Sprintf("%d.%d.%d.%d", v.Bytes[0], v.Bytes[1], v.Bytes[2], v.Bytes[3])
		}
		return v.Bytes
	case model.TypeObjectIdentifier:
		return v.OID.String()
	case model.TypeNull:
		return nil
	default:
		return nil
	}
}

func isPrintable(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

func coerceJSONValue(raw json.RawMessage, leafType string) (mibtree.Value, error) {
	raw = json.RawMessage(strings.TrimSpace(string(raw)))
	if len(raw) == 0 || string(raw) == "null" {
		return mibtree.Value{Type: leafType}, nil
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return mibtree.Value{}, domainerr.ValidationFailed("invalid value",
			domainerr.FieldViolation{Path: "value", Code: "invalid_value", Message: "value is not valid JSON"})
	}
	if obj, ok := v.(map[string]any); ok {
		typ, _ := obj["type"].(string)
		if typ == "" {
			typ = leafType
		}
		for k := range obj {
			switch k {
			case "type", "value", "integer", "unsigned", "bytes", "text", "oid":
			default:
				return mibtree.Value{}, domainerr.UnknownField("unknown field",
					domainerr.FieldViolation{Path: "value." + k, Code: "unknown_field", Message: "unknown field"})
			}
		}
		if inner, ok := obj["value"]; ok {
			return scalarToValue(inner, typ)
		}
		if n, ok := obj["integer"]; ok {
			return scalarToValue(n, model.TypeInteger)
		}
		if n, ok := obj["unsigned"]; ok {
			if typ == "" {
				typ = model.TypeUnsigned32
			}
			return scalarToValue(n, typ)
		}
		if s, ok := obj["text"].(string); ok {
			return mibtree.Value{Type: model.TypeOctetString, Bytes: []byte(s)}, nil
		}
		if s, ok := obj["bytes"].(string); ok {
			b, err := base64.StdEncoding.DecodeString(s)
			if err != nil {
				return mibtree.Value{}, domainerr.ValidationFailed("invalid bytes",
					domainerr.FieldViolation{Path: "value.bytes", Code: "invalid_value", Message: "bytes must be base64"})
			}
			return mibtree.Value{Type: model.TypeOctetString, Bytes: b}, nil
		}
		if s, ok := obj["oid"].(string); ok {
			oid, err := mibtree.ParseOID(s)
			if err != nil {
				return mibtree.Value{}, domainerr.ValidationFailed("invalid oid value",
					domainerr.FieldViolation{Path: "value.oid", Code: "invalid_value", Message: err.Error()})
			}
			return mibtree.Value{Type: model.TypeObjectIdentifier, OID: oid}, nil
		}
		return mibtree.Value{Type: typ}, nil
	}
	return scalarToValue(v, leafType)
}

func scalarToValue(v any, typ string) (mibtree.Value, error) {
	switch typ {
	case model.TypeInteger:
		n, err := asInt64(v)
		if err != nil {
			return mibtree.Value{}, domainerr.ValidationFailed("invalid integer",
				domainerr.FieldViolation{Path: "value", Code: "invalid_value", Message: "value must be an integer"})
		}
		return mibtree.Value{Type: typ, Signed: n}, nil
	case model.TypeCounter32, model.TypeGauge32, model.TypeUnsigned32, model.TypeTimeTicks, model.TypeCounter64:
		n, err := asUint64(v)
		if err != nil {
			return mibtree.Value{}, domainerr.ValidationFailed("invalid unsigned",
				domainerr.FieldViolation{Path: "value", Code: "invalid_value", Message: "value must be an unsigned integer"})
		}
		return mibtree.Value{Type: typ, Unsigned: n}, nil
	case model.TypeOctetString, model.TypeOpaque:
		s, ok := v.(string)
		if !ok {
			return mibtree.Value{}, domainerr.ValidationFailed("invalid octetString",
				domainerr.FieldViolation{Path: "value", Code: "invalid_value", Message: "value must be a string"})
		}
		return mibtree.Value{Type: typ, Bytes: []byte(s)}, nil
	case model.TypeIPAddress:
		s, ok := v.(string)
		if !ok {
			return mibtree.Value{}, domainerr.ValidationFailed("invalid ipAddress",
				domainerr.FieldViolation{Path: "value", Code: "invalid_value", Message: "value must be a dotted IPv4 string"})
		}
		parts := strings.Split(s, ".")
		if len(parts) != 4 {
			return mibtree.Value{}, domainerr.ValidationFailed("invalid ipAddress",
				domainerr.FieldViolation{Path: "value", Code: "invalid_value", Message: "value must be a dotted IPv4 string"})
		}
		b := make([]byte, 4)
		for i, p := range parts {
			n, err := strconv.Atoi(p)
			if err != nil || n < 0 || n > 255 {
				return mibtree.Value{}, domainerr.ValidationFailed("invalid ipAddress",
					domainerr.FieldViolation{Path: "value", Code: "invalid_value", Message: "value must be a dotted IPv4 string"})
			}
			b[i] = byte(n)
		}
		return mibtree.Value{Type: typ, Bytes: b}, nil
	case model.TypeObjectIdentifier:
		s, ok := v.(string)
		if !ok {
			return mibtree.Value{}, domainerr.ValidationFailed("invalid objectIdentifier",
				domainerr.FieldViolation{Path: "value", Code: "invalid_value", Message: "value must be a dotted OID"})
		}
		oid, err := mibtree.ParseOID(s)
		if err != nil {
			return mibtree.Value{}, domainerr.ValidationFailed("invalid objectIdentifier",
				domainerr.FieldViolation{Path: "value", Code: "invalid_value", Message: err.Error()})
		}
		return mibtree.Value{Type: typ, OID: oid}, nil
	case model.TypeNull, "":
		return mibtree.Value{Type: typ}, nil
	default:
		return scalarGuess(v, typ)
	}
}

func scalarGuess(v any, typ string) (mibtree.Value, error) {
	switch n := v.(type) {
	case json.Number:
		if strings.ContainsAny(n.String(), ".") {
			return mibtree.Value{}, domainerr.ValidationFailed("invalid value",
				domainerr.FieldViolation{Path: "value", Code: "invalid_value", Message: "value must be an integer"})
		}
		if strings.HasPrefix(n.String(), "-") {
			i, err := n.Int64()
			if err != nil {
				return mibtree.Value{}, domainerr.ValidationFailed("invalid integer",
					domainerr.FieldViolation{Path: "value", Code: "invalid_value", Message: err.Error()})
			}
			if typ == "" {
				typ = model.TypeInteger
			}
			return mibtree.Value{Type: typ, Signed: i}, nil
		}
		u, err := strconv.ParseUint(n.String(), 10, 64)
		if err != nil {
			return mibtree.Value{}, domainerr.ValidationFailed("invalid unsigned",
				domainerr.FieldViolation{Path: "value", Code: "invalid_value", Message: err.Error()})
		}
		if typ == "" {
			typ = model.TypeInteger
			return mibtree.Value{Type: typ, Signed: int64(u)}, nil
		}
		return mibtree.Value{Type: typ, Unsigned: u}, nil
	case string:
		if typ == "" {
			typ = model.TypeOctetString
		}
		return mibtree.Value{Type: typ, Bytes: []byte(n)}, nil
	default:
		return mibtree.Value{}, domainerr.ValidationFailed("invalid value",
			domainerr.FieldViolation{Path: "value", Code: "invalid_value", Message: "unsupported value type"})
	}
}

func asInt64(v any) (int64, error) {
	switch n := v.(type) {
	case json.Number:
		return n.Int64()
	case float64:
		return int64(n), nil
	case int:
		return int64(n), nil
	case int64:
		return n, nil
	default:
		return 0, strconv.ErrSyntax
	}
}

func asUint64(v any) (uint64, error) {
	switch n := v.(type) {
	case json.Number:
		return strconv.ParseUint(n.String(), 10, 64)
	case float64:
		if n < 0 {
			return 0, strconv.ErrRange
		}
		return uint64(n), nil
	case int:
		if n < 0 {
			return 0, strconv.ErrRange
		}
		return uint64(n), nil
	case int64:
		if n < 0 {
			return 0, strconv.ErrRange
		}
		return uint64(n), nil
	case uint64:
		return n, nil
	default:
		return 0, strconv.ErrSyntax
	}
}

func parseOptionalTime(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		t, err = time.Parse(time.RFC3339, raw)
	}
	if err != nil {
		return time.Time{}, domainerr.ValidationFailed("invalid since",
			domainerr.FieldViolation{Path: "since", Code: "invalid_value", Message: "since must be RFC3339"})
	}
	return t, nil
}

func (in trapListIn) toListQuery() (store.ListQuery, error) {
	q := store.ListQuery{
		Limit: in.Limit,
		After: in.After,
		Filter: store.TrapFilter{
			Version:         in.Version,
			PDUType:         in.PDUType,
			Community:       in.Community,
			User:            in.User,
			NotificationOID: in.NotificationOID,
		},
	}
	since, err := parseOptionalTime(in.Since)
	if err != nil {
		return store.ListQuery{}, err
	}
	q.Filter.Since = since
	return q, nil
}

func (in trapWaitIn) toWait() (app.TrapWaitIn, error) {
	timeout := time.Duration(0)
	if strings.TrimSpace(in.Timeout) != "" {
		d, err := time.ParseDuration(in.Timeout)
		if err != nil {
			return app.TrapWaitIn{}, domainerr.ValidationFailed("invalid timeout",
				domainerr.FieldViolation{Path: "timeout", Code: "invalid_value", Message: "timeout must use Go duration syntax"})
		}
		timeout = d
	}
	since, err := parseOptionalTime(in.Since)
	if err != nil {
		return app.TrapWaitIn{}, err
	}
	return app.TrapWaitIn{
		Timeout: timeout,
		Filter: store.TrapFilter{
			Version:         in.Version,
			PDUType:         in.PDUType,
			Community:       in.Community,
			User:            in.User,
			NotificationOID: in.NotificationOID,
			Since:           since,
		},
	}, nil
}
