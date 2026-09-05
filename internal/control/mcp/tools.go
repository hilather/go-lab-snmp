package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/hilather/go-lab-snmp/internal/app"
	"github.com/hilather/go-lab-snmp/internal/capabilities"
	"github.com/hilather/go-lab-snmp/internal/domainerr"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func (s *Server) registerTools() {
	addTool(s, "snmp_version_get", versionDesc, false, true, func(ctx context.Context, actor app.Actor, _ emptyIn) (any, error) {
		info, err := s.svc.Version(ctx, actor)
		if err != nil {
			return nil, err
		}
		if info == nil {
			return nil, domainerr.Internal("version unavailable")
		}
		return fromVersion(*info), nil
	})
	addTool(s, "snmp_capabilities_get", capDesc, false, true, func(ctx context.Context, actor app.Actor, _ emptyIn) (any, error) {
		view, err := s.svc.Capabilities(ctx, actor)
		if err != nil {
			return nil, err
		}
		return fromCapabilities(view), nil
	})
	addTool(s, "snmp_status_get", statusDesc, false, true, func(ctx context.Context, actor app.Actor, _ emptyIn) (any, error) {
		st, err := s.svc.Status(ctx, actor)
		if err != nil {
			return nil, err
		}
		return fromStatus(st)
	})
	addTool(s, "snmp_schema_get", schemaDesc, false, true, func(ctx context.Context, actor app.Actor, _ emptyIn) (any, error) {
		b, err := s.svc.ConfigSchema(ctx, actor)
		if err != nil {
			return nil, err
		}
		var doc any
		if err := json.Unmarshal(b, &doc); err != nil {
			return nil, domainerr.Internal("internal error")
		}
		return doc, nil
	})
	addTool(s, "snmp_features_list", featuresDesc, false, true, func(ctx context.Context, actor app.Actor, _ emptyIn) (any, error) {
		list, err := s.svc.Features(ctx, actor)
		if err != nil {
			return nil, err
		}
		return map[string]any{"items": list.Items}, nil
	})
	addTool(s, "snmp_state_get", stateGetDesc, false, true, func(ctx context.Context, actor app.Actor, _ emptyIn) (any, error) {
		v, err := s.svc.GetState(ctx, actor)
		if err != nil {
			return nil, err
		}
		return fromStateView(v)
	})
	addTool(s, "snmp_state_validate", validateDesc, false, true, func(ctx context.Context, actor app.Actor, in validateIn) (any, error) {
		vin, err := in.toValidate()
		if err != nil {
			return nil, asDomain(err)
		}
		p, err := s.svc.Validate(ctx, actor, vin)
		if err != nil {
			return nil, err
		}
		return fromPlan(p), nil
	})
	addTool(s, "snmp_state_export", exportDesc, false, true, func(ctx context.Context, actor app.Actor, in exportIn) (any, error) {
		format := app.ExportYAML
		switch strings.ToLower(in.Format) {
		case "", "yaml", "yml":
		case "json":
			format = app.ExportJSON
		default:
			return nil, domainerr.ValidationFailed("unknown export format",
				domainerr.FieldViolation{Path: "format", Code: "invalid_value", Message: "format must be yaml or json"})
		}
		exp, err := s.svc.Export(ctx, actor, format)
		if err != nil {
			return nil, err
		}
		return fromExport(exp), nil
	})
	addTool(s, "snmp_state_reset", resetDesc, true, false, func(ctx context.Context, actor app.Actor, in resetIn) (any, error) {
		r, err := s.svc.Reset(ctx, actor, app.ResetIn{Reason: in.Reason})
		if err != nil {
			return nil, err
		}
		return fromApply(r), nil
	})
	addTool(s, "snmp_change_plan", planDesc, false, true, func(ctx context.Context, actor app.Actor, in changeIn) (any, error) {
		p, err := s.svc.Plan(ctx, actor, in.toChange())
		if err != nil {
			return nil, err
		}
		return fromPlan(p), nil
	})
	addTool(s, "snmp_change_apply", applyDesc, true, true, func(ctx context.Context, actor app.Actor, in changeIn) (any, error) {
		r, err := s.svc.Apply(ctx, actor, in.toChange())
		if err != nil {
			return nil, err
		}
		return fromApply(r), nil
	})
	addTool(s, "snmp_maps_list", mapsListDesc, false, true, func(ctx context.Context, actor app.Actor, _ emptyIn) (any, error) {
		list, err := s.svc.ListMaps(ctx, actor)
		if err != nil {
			return nil, err
		}
		return map[string]any{"items": list.Items}, nil
	})
	addTool(s, "snmp_map_get", mapGetDesc, false, true, func(ctx context.Context, actor app.Actor, in nameIn) (any, error) {
		if err := requireName(in.Name); err != nil {
			return nil, err
		}
		return s.svc.GetMap(ctx, actor, in.Name)
	})
	addTool(s, "snmp_map_query", mapQueryDesc, false, true, func(ctx context.Context, actor app.Actor, in mapQueryIn) (any, error) {
		if err := requireName(in.Name); err != nil {
			return nil, err
		}
		res, err := s.svc.QueryMap(ctx, actor, in.Name, app.MapQueryIn{
			PDU:            in.PDU,
			OIDs:           in.OIDs,
			NonRepeaters:   in.NonRepeaters,
			MaxRepetitions: in.MaxRepetitions,
		})
		if err != nil {
			return nil, err
		}
		items := make([]oidResultJSON, 0, len(res.Bindings))
		for i := range res.Bindings {
			items = append(items, fromOIDResult(&res.Bindings[i]))
		}
		return map[string]any{"bindings": items}, nil
	})
	addTool(s, "snmp_oid_set", oidSetDesc, true, false, func(ctx context.Context, actor app.Actor, in oidSetIn) (any, error) {
		if err := requireName(in.Name); err != nil {
			return nil, err
		}
		if in.OID == "" {
			return nil, domainerr.ValidationFailed("oid is required",
				domainerr.FieldViolation{Path: "oid", Code: "required", Message: "oids:set body is a single {oid, value}"})
		}
		leafType := ""
		if got, err := s.svc.GetOID(ctx, actor, app.OIDGetIn{Map: in.Name, OID: in.OID}); err == nil {
			leafType = got.Value.Type
		}
		raw, err := json.Marshal(in.Value)
		if err != nil {
			return nil, domainerr.ValidationFailed("invalid value",
				domainerr.FieldViolation{Path: "value", Code: "invalid_value", Message: "value is not valid JSON"})
		}
		val, err := coerceJSONValue(raw, leafType)
		if err != nil {
			return nil, err
		}
		res, err := s.svc.SetOID(ctx, actor, app.OIDSetIn{Map: in.Name, OID: in.OID, Value: val})
		if err != nil {
			return nil, err
		}
		return fromOIDResult(res), nil
	})
	addTool(s, "snmp_oid_get", oidGetDesc, false, true, func(ctx context.Context, actor app.Actor, in oidGetIn) (any, error) {
		if err := requireName(in.Name); err != nil {
			return nil, err
		}
		if in.OID == "" {
			return nil, domainerr.ValidationFailed("oid is required",
				domainerr.FieldViolation{Path: "oid", Code: "required", Message: "oid is required"})
		}
		res, err := s.svc.GetOID(ctx, actor, app.OIDGetIn{Map: in.Name, OID: in.OID})
		if err != nil {
			return nil, err
		}
		if err := exceptionError(res.Exception); err != nil {
			return nil, err
		}
		return fromOIDResult(res), nil
	})
	addTool(s, "snmp_queries_list", queriesDesc, false, true, func(ctx context.Context, actor app.Actor, _ emptyIn) (any, error) {
		list, err := s.svc.ListQueries(ctx, actor)
		if err != nil {
			return nil, err
		}
		return map[string]any{"items": list.Items}, nil
	})
	addTool(s, "snmp_preview_get", previewDesc, false, true, func(ctx context.Context, actor app.Actor, in previewIn) (any, error) {
		res, err := s.svc.Preview(ctx, actor, app.PreviewIn{
			Community: in.Community,
			User:      in.User,
			OID:       in.OID,
		})
		if err != nil {
			return nil, err
		}
		if err := exceptionError(res.Exception); err != nil {
			return nil, err
		}
		return fromOIDResult(res), nil
	})
	addTool(s, "snmp_communities_list", communitiesDesc, false, true, func(ctx context.Context, actor app.Actor, _ emptyIn) (any, error) {
		list, err := s.svc.ListCommunities(ctx, actor)
		if err != nil {
			return nil, err
		}
		return map[string]any{"items": list.Items}, nil
	})
	addTool(s, "snmp_users_list", usersDesc, false, true, func(ctx context.Context, actor app.Actor, _ emptyIn) (any, error) {
		list, err := s.svc.ListUsers(ctx, actor)
		if err != nil {
			return nil, err
		}
		return map[string]any{"items": list.Items}, nil
	})
	addTool(s, "snmp_traps_list", trapsListDesc, false, true, func(ctx context.Context, actor app.Actor, in trapListIn) (any, error) {
		q, err := in.toListQuery()
		if err != nil {
			return nil, err
		}
		list, err := s.svc.ListTraps(ctx, actor, q)
		if err != nil {
			return nil, err
		}
		items := make([]trapJSON, 0, len(list.Items))
		for i := range list.Items {
			items = append(items, fromTrap(&list.Items[i]))
		}
		return map[string]any{"items": items, "next": list.Next}, nil
	})
	addTool(s, "snmp_trap_get", trapGetDesc, false, true, func(ctx context.Context, actor app.Actor, in idIn) (any, error) {
		if err := requireID(in.ID); err != nil {
			return nil, err
		}
		rec, err := s.svc.GetTrap(ctx, actor, in.ID)
		if err != nil {
			return nil, err
		}
		return fromTrap(rec), nil
	})
	addTool(s, "snmp_trap_raw_get", trapRawDesc, false, true, func(ctx context.Context, actor app.Actor, in idIn) (any, error) {
		if err := requireID(in.ID); err != nil {
			return nil, err
		}
		raw, err := s.svc.GetTrapRaw(ctx, actor, in.ID)
		if err != nil {
			return nil, err
		}
		return rawBodyJSON{
			ID:          in.ID,
			ContentType: "application/octet-stream",
			Body:        base64.StdEncoding.EncodeToString(raw),
		}, nil
	})
	addTool(s, "snmp_traps_wait", trapsWaitDesc, false, true, func(ctx context.Context, actor app.Actor, in trapWaitIn) (any, error) {
		win, err := in.toWait()
		if err != nil {
			return nil, err
		}
		rec, err := s.svc.WaitTraps(ctx, actor, win)
		if err != nil {
			return nil, err
		}
		return fromTrap(rec), nil
	})
	addTool(s, "snmp_traps_clear", trapsClearDesc, true, false, func(ctx context.Context, actor app.Actor, _ emptyIn) (any, error) {
		if err := s.svc.ClearTraps(ctx, actor); err != nil {
			return nil, err
		}
		return map[string]any{"ok": true}, nil
	})
	addTool(s, "snmp_stats_get", statsDesc, false, true, func(ctx context.Context, actor app.Actor, _ emptyIn) (any, error) {
		st, err := s.svc.Stats(ctx, actor)
		if err != nil {
			return nil, err
		}
		return fromStats(st), nil
	})
	addTool(s, "snmp_audit_query", auditQueryDesc, false, true, func(ctx context.Context, actor app.Actor, in auditQueryIn) (any, error) {
		list, err := s.svc.QueryAudit(ctx, actor, app.AuditQuery{Limit: in.Limit})
		if err != nil {
			return nil, err
		}
		return fromAuditList(list), nil
	})
	addTool(s, "snmp_audit_get", auditGetDesc, false, true, func(ctx context.Context, actor app.Actor, in idIn) (any, error) {
		if err := requireID(in.ID); err != nil {
			return nil, err
		}
		return s.svc.GetAudit(ctx, actor, in.ID)
	})
}

func addTool[In any](s *Server, name, desc string, mutating, idempotent bool, h func(context.Context, app.Actor, In) (any, error)) {
	caps := capabilities.LookupTool(name)
	title := name
	if len(caps) > 0 && caps[0].Title != "" {
		title = caps[0].Title
		if desc == "" {
			desc = caps[0].Description
		}
	}
	readOnly := !mutating
	ann := &sdk.ToolAnnotations{
		Title:           title,
		ReadOnlyHint:    readOnly,
		IdempotentHint:  idempotent,
		DestructiveHint: boolPtr(mutating && !idempotent),
		OpenWorldHint:   boolPtr(false),
	}
	sdk.AddTool(s.sdk, &sdk.Tool{
		Name:        name,
		Title:       title,
		Description: desc,
		Annotations: ann,
	}, func(ctx context.Context, _ *sdk.CallToolRequest, in In) (*sdk.CallToolResult, any, error) {
		if err := ctx.Err(); err != nil {
			return toolErrorResult(canceledError(err)), nil, nil
		}
		actor := s.actorFrom(ctx)
		if err := s.authorizeTool(actor, name); err != nil {
			return toolErrorResult(err), nil, nil
		}
		out, err := h(ctx, actor, in)
		if err != nil {
			return toolErrorResult(err), nil, nil
		}
		structured, err := asStructured(out)
		if err != nil {
			return nil, nil, rpcError(domainerr.Internal("internal error"))
		}
		return nil, structured, nil
	})
}

func boolPtr(v bool) *bool { return &v }

func canceledError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return domainerr.Timeout("request deadline exceeded")
	}
	return domainerr.Internal("request canceled")
}

const (
	versionDesc     = "Read-only. Build and protocol versions (MCP " + ProtocolVersion + ")."
	capDesc         = "Read-only. Capability list and protocol metadata."
	statusDesc      = "Read-only. Listeners, revisions, hostTime, and ready."
	schemaDesc      = "Read-only. Published v1alpha1 config JSON Schema."
	featuresDesc    = "Read-only. Frozen live vs reset-only catalog."
	stateGetDesc    = "Read-only. Redacted spec plus revision metadata."
	validateDesc    = "Read-only dry-run. Validate a candidate document and/or operations without writing."
	planDesc        = "Read-only dry-run. Plan operations against the active snapshot."
	applyDesc       = "State-changing. Apply operations with expectedRevision. High-impact."
	exportDesc      = "Read-only. Canonical desired-state export plus drift material."
	resetDesc       = "State-changing, high-impact. Reread the bootstrap mount, drop overlay, wipe traps and queries, and swap. Never writes the file."
	mapsListDesc    = "Read-only. List named OID maps."
	mapGetDesc      = "Read-only. Get one named OID map."
	mapQueryDesc    = "Read-only. Simulate GET/GETNEXT/GETBULK against a named map without sending a datagram."
	oidSetDesc      = "State-changing. Write one overlay value. Same overlay as SNMP SET. Body is a single {oid, value}."
	oidGetDesc      = "Read-only. Read one oid from a named map plus overlay."
	queriesDesc     = "Read-only. Last-N PDU ring (request type, identity, decision, error status)."
	previewDesc     = "Read-only. Evaluate a community or user plus oid against the compiled tree without a wire packet."
	communitiesDesc = "Read-only. List communities. Wire strings never appear; communityFile paths may."
	usersDesc       = "Read-only. List v3 users. Secret bytes never appear; secretFile paths may."
	trapsListDesc   = "Read-only. List the ephemeral trap/inform inbox."
	trapGetDesc     = "Read-only. Get one trap/inform by ULID."
	trapRawDesc     = "Read-only. Get the retained trap/inform datagram (base64)."
	trapsWaitDesc   = "Read-only. Wait for an existing or later matching trap. wait_timeout or store_wiped."
	trapsClearDesc  = "State-changing. Wipe the trap inbox. Waiters receive store_wiped."
	statsDesc       = "Read-only. Trap store occupancy, overlay generation, and query ring length."
	auditQueryDesc  = "Read-only. Query recent in-memory audit events."
	auditGetDesc    = "Read-only. Get one audit event by id."
)
