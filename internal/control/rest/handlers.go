package rest

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hilather/go-lab-snmp/internal/app"
	"github.com/hilather/go-lab-snmp/internal/capabilities"
	"github.com/hilather/go-lab-snmp/internal/domainerr"
	"github.com/hilather/go-lab-snmp/internal/observability"
	"github.com/hilather/go-lab-snmp/internal/store"
)

func (s *Server) dispatch(w http.ResponseWriter, r *http.Request, instance string, actor app.Actor, rt compiledRoute, params map[string]string) {
	ctx := r.Context()
	if err := ctx.Err(); err != nil {
		s.writeProblem(w, r, instance, domainerr.Internal("request canceled"))
		return
	}
	switch rt.cap.ID {
	case capabilities.HealthLive:
		s.handleHealthLive(w, r)
	case capabilities.HealthReady:
		s.handleHealthReady(w, r, ctx)
	case capabilities.VersionGet:
		s.handleVersion(w, r, instance, ctx, actor)
	case capabilities.CapabilitiesGet:
		s.handleCapabilities(w, r, instance, ctx, actor)
	case capabilities.StatusGet:
		s.handleStatus(w, r, instance, ctx, actor)
	case capabilities.SchemaGet:
		s.handleSchema(w, r, instance, ctx, actor)
	case capabilities.FeaturesList:
		s.handleFeatures(w, r, instance, ctx, actor)
	case capabilities.StateGet:
		s.handleGetState(w, r, instance, ctx, actor)
	case capabilities.StateValidate:
		s.handleValidate(w, r, instance, ctx, actor)
	case capabilities.ChangesPlan:
		s.handlePlan(w, r, instance, ctx, actor)
	case capabilities.ChangesApply:
		s.handleApply(w, r, instance, ctx, actor)
	case capabilities.SessionCreate:
		s.handleSessionCreate(w, r, instance, actor)
	case capabilities.SessionGet:
		s.handleSessionGet(w, r, instance, actor)
	case capabilities.SessionDelete:
		s.handleSessionDelete(w, r, instance, actor)
	case capabilities.StateExport:
		s.handleExport(w, r, instance, ctx, actor)
	case capabilities.StateReset:
		s.handleReset(w, r, instance, ctx, actor)
	case capabilities.MapsList:
		s.handleMapsList(w, r, instance, ctx, actor)
	case capabilities.MapsGet:
		s.handleMapsGet(w, r, instance, ctx, actor, params["name"])
	case capabilities.MapsQuery:
		s.handleMapsQuery(w, r, instance, ctx, actor, params["name"])
	case capabilities.OIDsSet:
		s.handleOIDSet(w, r, instance, ctx, actor, params["name"])
	case capabilities.OIDsGet:
		s.handleOIDGet(w, r, instance, ctx, actor, params["name"])
	case capabilities.QueriesList:
		s.handleQueries(w, r, instance, ctx, actor)
	case capabilities.PreviewGet:
		s.handlePreview(w, r, instance, ctx, actor)
	case capabilities.CommunitiesList:
		s.handleCommunities(w, r, instance, ctx, actor)
	case capabilities.UsersList:
		s.handleUsers(w, r, instance, ctx, actor)
	case capabilities.TrapsList:
		s.handleTrapsList(w, r, instance, ctx, actor)
	case capabilities.TrapsGet:
		s.handleTrapsGet(w, r, instance, ctx, actor, params["id"])
	case capabilities.TrapsRaw:
		s.handleTrapsRaw(w, r, instance, ctx, actor, params["id"])
	case capabilities.TrapsWait:
		s.handleTrapsWait(w, r, instance, ctx, actor)
	case capabilities.TrapsClear:
		s.handleTrapsClear(w, r, instance, ctx, actor)
	case capabilities.StatsGet:
		s.handleStats(w, r, instance, ctx, actor)
	case capabilities.AuditList:
		s.handleAuditList(w, r, instance, ctx, actor)
	case capabilities.AuditGet:
		s.handleAuditGet(w, r, instance, ctx, actor, params["id"])
	case capabilities.MetricsGet:
		s.handleMetrics(w, r, instance)
	default:
		s.writeProblem(w, r, instance, domainerr.NotFound("not found"))
	}
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request, instance string, ctx context.Context, actor app.Actor) {
	info, err := s.svc.Version(ctx, actor)
	if err != nil {
		s.writeProblem(w, r, instance, asDomain(err))
		return
	}
	if info == nil {
		s.writeProblem(w, r, instance, domainerr.Internal("version unavailable"))
		return
	}
	s.writeJSON(w, http.StatusOK, fromVersion(*info))
}

func (s *Server) handleCapabilities(w http.ResponseWriter, r *http.Request, instance string, ctx context.Context, actor app.Actor) {
	view, err := s.svc.Capabilities(ctx, actor)
	if err != nil {
		s.writeProblem(w, r, instance, asDomain(err))
		return
	}
	s.writeJSON(w, http.StatusOK, fromCapabilities(view))
	_ = r
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request, instance string) {
	if !s.publicMetrics(r.Context()) {
		s.writeProblem(w, r, instance, domainerr.NotFound("not found"))
		return
	}
	if s.metrics != nil {
		if st, err := s.svc.Stats(r.Context(), app.Actor{ID: "probe", Class: "startup", Transport: "rest"}); err == nil && st != nil {
			s.metrics.Set(observability.MetricStoreMessages, nil, float64(st.Traps.Messages))
			s.metrics.Set(observability.MetricStoreBytes, nil, float64(st.Traps.Bytes))
		}
	}
	w.Header().Set("Content-Type", observability.OpenMetricsContentType)
	w.Header().Set("Cache-Control", "no-store")
	if s.metrics == nil {
		_, _ = w.Write([]byte("# EOF\n"))
		return
	}
	_ = s.metrics.WriteOpenMetrics(w)
	_ = r
}

func (s *Server) handleHealthLive(w http.ResponseWriter, r *http.Request) {
	if !s.isLive() {
		s.writeJSON(w, http.StatusServiceUnavailable, healthResponse{Status: "down"})
		return
	}
	s.writeJSON(w, http.StatusOK, healthResponse{Status: "ok"})
	_ = r
}

func (s *Server) handleHealthReady(w http.ResponseWriter, r *http.Request, ctx context.Context) {
	if !s.isReady(ctx) {
		s.writeJSON(w, http.StatusServiceUnavailable, healthResponse{Status: "not ready"})
		return
	}
	s.writeJSON(w, http.StatusOK, healthResponse{Status: "ok"})
	_ = r
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request, instance string, ctx context.Context, actor app.Actor) {
	st, err := s.svc.Status(ctx, actor)
	if err != nil {
		s.writeProblem(w, r, instance, asDomain(err))
		return
	}
	rev, err := marshalAPI(st.Revisions)
	if err != nil {
		s.writeProblem(w, r, instance, domainerr.Internal("internal error"))
		return
	}
	listeners := make([]listenerJSON, 0, len(st.Listeners))
	for _, l := range st.Listeners {
		listeners = append(listeners, listenerJSON{Name: l.Name, Address: l.Address})
	}
	s.writeJSON(w, http.StatusOK, statusResponse{
		Ready:     s.isReady(ctx),
		Revisions: rev,
		Listeners: listeners,
		HostTime:  rfc3339(st.HostTime),
		Warnings:  st.Warnings,
	})
	_ = r
}

func (s *Server) handleSchema(w http.ResponseWriter, r *http.Request, instance string, ctx context.Context, actor app.Actor) {
	b, err := s.svc.ConfigSchema(ctx, actor)
	if err != nil {
		s.writeProblem(w, r, instance, asDomain(err))
		return
	}
	s.writeBytes(w, http.StatusOK, "application/schema+json", b)
	_ = r
}

func (s *Server) handleFeatures(w http.ResponseWriter, r *http.Request, instance string, ctx context.Context, actor app.Actor) {
	list, err := s.svc.Features(ctx, actor)
	if err != nil {
		s.writeProblem(w, r, instance, asDomain(err))
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"items": list.Items})
	_ = r
}

func (s *Server) handleGetState(w http.ResponseWriter, r *http.Request, instance string, ctx context.Context, actor app.Actor) {
	v, err := s.svc.GetState(ctx, actor)
	if err != nil {
		s.writeProblem(w, r, instance, asDomain(err))
		return
	}
	canon, err := marshalAPI(v.Canonical)
	if err != nil {
		s.writeProblem(w, r, instance, domainerr.Internal("internal error"))
		return
	}
	if v.RuntimeRevision != "" {
		w.Header().Set(headerRevision, string(v.RuntimeRevision))
	}
	s.writeJSON(w, http.StatusOK, stateViewJSON{
		BootstrapRevision: string(v.BootstrapRevision),
		RuntimeRevision:   string(v.RuntimeRevision),
		Generation:        uint64(v.Generation),
		StoreGeneration:   v.StoreGeneration,
		Drifted:           v.Drifted,
		LoadedAt:          rfc3339(v.LoadedAt),
		Canonical:         canon,
	})
	_ = r
}

func (s *Server) handleValidate(w http.ResponseWriter, r *http.Request, instance string, ctx context.Context, actor app.Actor) {
	var in changeRequest
	if !s.decodeJSON(w, r, instance, &in) {
		return
	}
	st, err := decodeCandidateState(in.State)
	if err != nil {
		s.writeProblem(w, r, instance, asDomain(err))
		return
	}
	plan, err := s.svc.Validate(ctx, actor, app.ValidateIn{State: st, Operations: in.Operations})
	if err != nil {
		s.writeProblem(w, r, instance, asDomain(err))
		return
	}
	s.writeJSON(w, http.StatusOK, fromPlan(plan))
}

func (s *Server) handlePlan(w http.ResponseWriter, r *http.Request, instance string, ctx context.Context, actor app.Actor) {
	in, ok := s.readChange(w, r, instance)
	if !ok {
		return
	}
	plan, err := s.svc.Plan(ctx, actor, in)
	if err != nil {
		s.writeProblem(w, r, instance, asDomain(err))
		return
	}
	s.writeJSON(w, http.StatusOK, fromPlan(plan))
}

func (s *Server) handleApply(w http.ResponseWriter, r *http.Request, instance string, ctx context.Context, actor app.Actor) {
	in, ok := s.readChange(w, r, instance)
	if !ok {
		return
	}
	res, err := s.svc.Apply(ctx, actor, in)
	if err != nil {
		s.writeProblem(w, r, instance, asDomain(err))
		return
	}
	if res != nil && res.RuntimeRevision != "" {
		w.Header().Set(headerRevision, string(res.RuntimeRevision))
	}
	s.writeJSON(w, http.StatusOK, fromApply(res))
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request, instance string, ctx context.Context, actor app.Actor) {
	format := app.ExportYAML
	switch strings.ToLower(r.URL.Query().Get("format")) {
	case "", "yaml", "yml":
	case "json":
		format = app.ExportJSON
	default:
		s.writeProblem(w, r, instance, domainerr.ValidationFailed("unknown export format",
			domainerr.FieldViolation{Path: "format", Code: "invalid_value", Message: "format must be yaml or json"}))
		return
	}
	exp, err := s.svc.Export(ctx, actor, format)
	if err != nil {
		s.writeProblem(w, r, instance, asDomain(err))
		return
	}
	if exp.Revision != "" {
		w.Header().Set(headerRevision, string(exp.Revision))
	}
	if format == app.ExportYAML {
		s.writeBytes(w, http.StatusOK, "application/yaml", exp.Body)
		return
	}
	s.writeBytes(w, http.StatusOK, "application/json; charset=utf-8", exp.Body)
}

func (s *Server) handleReset(w http.ResponseWriter, r *http.Request, instance string, ctx context.Context, actor app.Actor) {
	var in resetRequest
	if !s.decodeJSONOptional(w, r, instance, &in) {
		return
	}
	res, err := s.svc.Reset(ctx, actor, app.ResetIn{Reason: in.Reason})
	if err != nil {
		s.writeProblem(w, r, instance, asDomain(err))
		return
	}
	s.writeJSON(w, http.StatusOK, fromApply(res))
}

func (s *Server) handleMapsList(w http.ResponseWriter, r *http.Request, instance string, ctx context.Context, actor app.Actor) {
	list, err := s.svc.ListMaps(ctx, actor)
	if err != nil {
		s.writeProblem(w, r, instance, asDomain(err))
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"items": list.Items})
	_ = r
}

func (s *Server) handleMapsGet(w http.ResponseWriter, r *http.Request, instance string, ctx context.Context, actor app.Actor, name string) {
	m, err := s.svc.GetMap(ctx, actor, name)
	if err != nil {
		s.writeProblem(w, r, instance, asDomain(err))
		return
	}
	s.writeJSON(w, http.StatusOK, m)
}

func (s *Server) handleMapsQuery(w http.ResponseWriter, r *http.Request, instance string, ctx context.Context, actor app.Actor, name string) {
	var in mapQueryRequest
	if !s.decodeJSON(w, r, instance, &in) {
		return
	}
	res, err := s.svc.QueryMap(ctx, actor, name, app.MapQueryIn{
		PDU:            in.PDU,
		OIDs:           in.OIDs,
		NonRepeaters:   in.NonRepeaters,
		MaxRepetitions: in.MaxRepetitions,
	})
	if err != nil {
		s.writeProblem(w, r, instance, asDomain(err))
		return
	}
	items := make([]oidResultJSON, 0, len(res.Bindings))
	for i := range res.Bindings {
		items = append(items, fromOIDResult(&res.Bindings[i]))
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"bindings": items})
}

func (s *Server) handleOIDSet(w http.ResponseWriter, r *http.Request, instance string, ctx context.Context, actor app.Actor, name string) {
	var in oidWriteRequest
	if !s.decodeJSON(w, r, instance, &in) {
		return
	}
	if in.OID == "" {
		s.writeProblem(w, r, instance, domainerr.ValidationFailed("oid is required",
			domainerr.FieldViolation{Path: "oid", Code: "required", Message: "oids:set body is a single {oid, value}"}))
		return
	}
	leafType := ""
	if got, err := s.svc.GetOID(ctx, actor, app.OIDGetIn{Map: name, OID: in.OID}); err == nil {
		leafType = got.Value.Type
	}
	val, err := coerceJSONValue(in.Value, leafType)
	if err != nil {
		s.writeProblem(w, r, instance, asDomain(err))
		return
	}
	res, err := s.svc.SetOID(ctx, actor, app.OIDSetIn{Map: name, OID: in.OID, Value: val})
	if err != nil {
		s.writeProblem(w, r, instance, asDomain(err))
		return
	}
	s.writeJSON(w, http.StatusOK, fromOIDResult(res))
}

func (s *Server) handleOIDGet(w http.ResponseWriter, r *http.Request, instance string, ctx context.Context, actor app.Actor, name string) {
	var in oidWriteRequest
	if !s.decodeJSON(w, r, instance, &in) {
		return
	}
	if in.OID == "" {
		s.writeProblem(w, r, instance, domainerr.ValidationFailed("oid is required",
			domainerr.FieldViolation{Path: "oid", Code: "required", Message: "oid is required"}))
		return
	}
	res, err := s.svc.GetOID(ctx, actor, app.OIDGetIn{Map: name, OID: in.OID})
	if err != nil {
		s.writeProblem(w, r, instance, asDomain(err))
		return
	}
	if err := exceptionError(res.Exception); err != nil {
		s.writeProblem(w, r, instance, err)
		return
	}
	s.writeJSON(w, http.StatusOK, fromOIDResult(res))
}

func (s *Server) handleQueries(w http.ResponseWriter, r *http.Request, instance string, ctx context.Context, actor app.Actor) {
	list, err := s.svc.ListQueries(ctx, actor)
	if err != nil {
		s.writeProblem(w, r, instance, asDomain(err))
		return
	}
	items := make([]queryJSON, 0, len(list.Items))
	for _, q := range list.Items {
		items = append(items, fromQuery(q))
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"items": items})
	_ = r
}

func (s *Server) handlePreview(w http.ResponseWriter, r *http.Request, instance string, ctx context.Context, actor app.Actor) {
	res, err := s.svc.Preview(ctx, actor, app.PreviewIn{
		Community: r.URL.Query().Get("community"),
		User:      r.URL.Query().Get("user"),
		OID:       r.URL.Query().Get("oid"),
	})
	if err != nil {
		s.writeProblem(w, r, instance, asDomain(err))
		return
	}
	if err := exceptionError(res.Exception); err != nil {
		s.writeProblem(w, r, instance, err)
		return
	}
	s.writeJSON(w, http.StatusOK, fromOIDResult(res))
}

func (s *Server) handleCommunities(w http.ResponseWriter, r *http.Request, instance string, ctx context.Context, actor app.Actor) {
	list, err := s.svc.ListCommunities(ctx, actor)
	if err != nil {
		s.writeProblem(w, r, instance, asDomain(err))
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"items": list.Items})
	_ = r
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request, instance string, ctx context.Context, actor app.Actor) {
	list, err := s.svc.ListUsers(ctx, actor)
	if err != nil {
		s.writeProblem(w, r, instance, asDomain(err))
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"items": list.Items})
	_ = r
}

func (s *Server) handleTrapsList(w http.ResponseWriter, r *http.Request, instance string, ctx context.Context, actor app.Actor) {
	q, err := parseTrapListQuery(r)
	if err != nil {
		s.writeProblem(w, r, instance, err)
		return
	}
	list, err := s.svc.ListTraps(ctx, actor, q)
	if err != nil {
		s.writeProblem(w, r, instance, asDomain(err))
		return
	}
	items := make([]trapJSON, 0, len(list.Items))
	for i := range list.Items {
		items = append(items, fromTrap(&list.Items[i]))
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"items": items, "next": list.Next})
}

func (s *Server) handleTrapsGet(w http.ResponseWriter, r *http.Request, instance string, ctx context.Context, actor app.Actor, id string) {
	rec, err := s.svc.GetTrap(ctx, actor, id)
	if err != nil {
		s.writeProblem(w, r, instance, asDomain(err))
		return
	}
	s.writeJSON(w, http.StatusOK, fromTrap(rec))
}

func (s *Server) handleTrapsRaw(w http.ResponseWriter, r *http.Request, instance string, ctx context.Context, actor app.Actor, id string) {
	raw, err := s.svc.GetTrapRaw(ctx, actor, id)
	if err != nil {
		s.writeProblem(w, r, instance, asDomain(err))
		return
	}
	s.writeBytes(w, http.StatusOK, "application/octet-stream", raw)
}

func (s *Server) handleTrapsWait(w http.ResponseWriter, r *http.Request, instance string, ctx context.Context, actor app.Actor) {
	var in trapWaitRequest
	if !s.decodeJSONOptional(w, r, instance, &in) {
		return
	}
	timeout := time.Duration(0)
	if strings.TrimSpace(in.Timeout) != "" {
		d, err := time.ParseDuration(in.Timeout)
		if err != nil {
			s.writeProblem(w, r, instance, domainerr.ValidationFailed("invalid timeout",
				domainerr.FieldViolation{Path: "timeout", Code: "invalid_value", Message: "timeout must use Go duration syntax"}))
			return
		}
		timeout = d
	}
	since, err := parseOptionalTime(in.Since)
	if err != nil {
		s.writeProblem(w, r, instance, err)
		return
	}
	rec, err := s.svc.WaitTraps(ctx, actor, app.TrapWaitIn{
		Timeout: timeout,
		Filter: store.TrapFilter{
			Version:         in.Version,
			PDUType:         in.PDUType,
			Community:       in.Community,
			User:            in.User,
			NotificationOID: in.NotificationOID,
			Since:           since,
		},
	})
	if err != nil {
		s.writeProblem(w, r, instance, asDomain(err))
		return
	}
	s.writeJSON(w, http.StatusOK, fromTrap(rec))
}

func (s *Server) handleTrapsClear(w http.ResponseWriter, r *http.Request, instance string, ctx context.Context, actor app.Actor) {
	if !s.decodeJSONOptional(w, r, instance, &struct{}{}) {
		return
	}
	if err := s.svc.ClearTraps(ctx, actor); err != nil {
		s.writeProblem(w, r, instance, asDomain(err))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request, instance string, ctx context.Context, actor app.Actor) {
	st, err := s.svc.Stats(ctx, actor)
	if err != nil {
		s.writeProblem(w, r, instance, asDomain(err))
		return
	}
	s.writeJSON(w, http.StatusOK, fromStats(st))
	_ = r
}

func (s *Server) handleAuditList(w http.ResponseWriter, r *http.Request, instance string, ctx context.Context, actor app.Actor) {
	limit := 0
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			s.writeProblem(w, r, instance, domainerr.ValidationFailed("invalid limit",
				domainerr.FieldViolation{Path: "limit", Code: "invalid_value", Message: "limit must be a non-negative integer"}))
			return
		}
		limit = n
	}
	list, err := s.svc.QueryAudit(ctx, actor, app.AuditQuery{Limit: limit})
	if err != nil {
		s.writeProblem(w, r, instance, asDomain(err))
		return
	}
	events := list.Events
	if events == nil {
		events = []app.AuditEvent{}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (s *Server) handleAuditGet(w http.ResponseWriter, r *http.Request, instance string, ctx context.Context, actor app.Actor, id string) {
	ev, err := s.svc.GetAudit(ctx, actor, id)
	if err != nil {
		s.writeProblem(w, r, instance, asDomain(err))
		return
	}
	s.writeJSON(w, http.StatusOK, ev)
}

func parseTrapListQuery(r *http.Request) (store.ListQuery, error) {
	q := store.ListQuery{
		After: r.URL.Query().Get("after"),
		Filter: store.TrapFilter{
			Version:         r.URL.Query().Get("version"),
			PDUType:         r.URL.Query().Get("pduType"),
			Community:       r.URL.Query().Get("community"),
			User:            r.URL.Query().Get("user"),
			NotificationOID: r.URL.Query().Get("notificationOID"),
		},
	}
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			return store.ListQuery{}, domainerr.ValidationFailed("invalid limit",
				domainerr.FieldViolation{Path: "limit", Code: "invalid_value", Message: "limit must be a non-negative integer"})
		}
		q.Limit = n
	}
	since, err := parseOptionalTime(r.URL.Query().Get("since"))
	if err != nil {
		return store.ListQuery{}, err
	}
	q.Filter.Since = since
	return q, nil
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
