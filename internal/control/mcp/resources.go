package mcp

import (
	"context"
	"strings"

	"github.com/hilather/go-lab-snmp/internal/app"
	"github.com/hilather/go-lab-snmp/internal/domainerr"
	"github.com/hilather/go-lab-snmp/internal/store"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func (s *Server) registerResources() {
	h := s.readResource
	s.sdk.AddResource(&sdk.Resource{
		URI: "labsnmp://capabilities", Name: "capabilities",
		Description: "Capability list and protocol metadata.",
		MIMEType:    "application/json",
	}, h)
	s.sdk.AddResource(&sdk.Resource{
		URI: "labsnmp://status", Name: "status",
		Description: "Listeners, revisions, hostTime, and ready.",
		MIMEType:    "application/json",
	}, h)
	s.sdk.AddResource(&sdk.Resource{
		URI: "labsnmp://features", Name: "features",
		Description: "Frozen live vs reset-only catalog.",
		MIMEType:    "application/json",
	}, h)
	s.sdk.AddResource(&sdk.Resource{
		URI: "labsnmp://state", Name: "state",
		Description: "Redacted spec plus revision metadata (same as GET /v1/state).",
		MIMEType:    "application/json",
	}, h)
	s.sdk.AddResource(&sdk.Resource{
		URI: "labsnmp://maps", Name: "maps",
		Description: "Named OID maps.",
		MIMEType:    "application/json",
	}, h)
	s.sdk.AddResourceTemplate(&sdk.ResourceTemplate{
		URITemplate: "labsnmp://maps/{name}", Name: "map",
		Description: "One named OID map.",
		MIMEType:    "application/json",
	}, h)
	s.sdk.AddResource(&sdk.Resource{
		URI: "labsnmp://queries", Name: "queries",
		Description: "Last-N PDU ring.",
		MIMEType:    "application/json",
	}, h)
	s.sdk.AddResource(&sdk.Resource{
		URI: "labsnmp://traps", Name: "traps",
		Description: "Ephemeral trap/inform inbox.",
		MIMEType:    "application/json",
	}, h)
	s.sdk.AddResourceTemplate(&sdk.ResourceTemplate{
		URITemplate: "labsnmp://traps/{id}", Name: "trap",
		Description: "One trap/inform by ULID.",
		MIMEType:    "application/json",
	}, h)
	s.sdk.AddResource(&sdk.Resource{
		URI: "labsnmp://stats", Name: "stats",
		Description: "Trap store occupancy, overlay generation, and query ring length.",
		MIMEType:    "application/json",
	}, h)
}

func (s *Server) readResource(ctx context.Context, req *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, rpcError(domainerr.Internal("request canceled"))
	}
	actor := s.actorFrom(ctx)
	uri := ""
	if req != nil && req.Params != nil {
		uri = req.Params.URI
	}
	if err := s.authorizeResource(actor, uri); err != nil {
		return nil, rpcError(err)
	}
	body, mime, err := s.resourceBody(ctx, actor, uri)
	if err != nil {
		return nil, rpcError(err)
	}
	return &sdk.ReadResourceResult{
		Contents: []*sdk.ResourceContents{{
			URI:      uri,
			MIMEType: mime,
			Text:     string(body),
		}},
	}, nil
}

func (s *Server) resourceBody(ctx context.Context, actor app.Actor, uri string) ([]byte, string, error) {
	switch {
	case uri == "labsnmp://capabilities":
		view, err := s.svc.Capabilities(ctx, actor)
		if err != nil {
			return nil, "", err
		}
		b, err := marshalAPI(fromCapabilities(view))
		return b, "application/json", err
	case uri == "labsnmp://status":
		st, err := s.svc.Status(ctx, actor)
		if err != nil {
			return nil, "", err
		}
		dto, err := fromStatus(st)
		if err != nil {
			return nil, "", err
		}
		b, err := marshalAPI(dto)
		return b, "application/json", err
	case uri == "labsnmp://features":
		list, err := s.svc.Features(ctx, actor)
		if err != nil {
			return nil, "", err
		}
		b, err := marshalAPI(map[string]any{"items": list.Items})
		return b, "application/json", err
	case uri == "labsnmp://state":
		v, err := s.svc.GetState(ctx, actor)
		if err != nil {
			return nil, "", err
		}
		view, err := fromStateView(v)
		if err != nil {
			return nil, "", err
		}
		b, err := marshalAPI(view)
		return b, "application/json", err
	case uri == "labsnmp://maps":
		list, err := s.svc.ListMaps(ctx, actor)
		if err != nil {
			return nil, "", err
		}
		b, err := marshalAPI(map[string]any{"items": list.Items})
		return b, "application/json", err
	case strings.HasPrefix(uri, "labsnmp://maps/"):
		name := strings.TrimPrefix(uri, "labsnmp://maps/")
		if name == "" || strings.Contains(name, "/") {
			return nil, "", domainerr.NotFound("not found")
		}
		m, err := s.svc.GetMap(ctx, actor, name)
		if err != nil {
			return nil, "", err
		}
		b, err := marshalAPI(m)
		return b, "application/json", err
	case uri == "labsnmp://queries":
		list, err := s.svc.ListQueries(ctx, actor)
		if err != nil {
			return nil, "", err
		}
		b, err := marshalAPI(map[string]any{"items": list.Items})
		return b, "application/json", err
	case uri == "labsnmp://traps":
		list, err := s.svc.ListTraps(ctx, actor, store.ListQuery{})
		if err != nil {
			return nil, "", err
		}
		items := make([]trapJSON, 0, len(list.Items))
		for i := range list.Items {
			items = append(items, fromTrap(&list.Items[i]))
		}
		b, err := marshalAPI(map[string]any{"items": items, "next": list.Next})
		return b, "application/json", err
	case strings.HasPrefix(uri, "labsnmp://traps/"):
		id := strings.TrimPrefix(uri, "labsnmp://traps/")
		if id == "" || strings.Contains(id, "/") {
			return nil, "", domainerr.NotFound("not found")
		}
		rec, err := s.svc.GetTrap(ctx, actor, id)
		if err != nil {
			return nil, "", err
		}
		b, err := marshalAPI(fromTrap(rec))
		return b, "application/json", err
	case uri == "labsnmp://stats":
		st, err := s.svc.Stats(ctx, actor)
		if err != nil {
			return nil, "", err
		}
		b, err := marshalAPI(fromStats(st))
		return b, "application/json", err
	default:
		return nil, "", domainerr.NotFound("not found")
	}
}
