package app

import (
	"context"

	"github.com/hilather/go-lab-snmp/internal/buildinfo"
	"github.com/hilather/go-lab-snmp/internal/model"
	"github.com/hilather/go-lab-snmp/internal/store"
)

// Service is the HTTP-less capability surface. REST and MCP must call these
// methods rather than implementing mutation or query logic.
type Service interface {
	Version(ctx context.Context, actor Actor) (*buildinfo.Info, error)
	Features(ctx context.Context, actor Actor) (*FeatureList, error)
	Status(ctx context.Context, actor Actor) (*Status, error)
	ConfigSchema(ctx context.Context, actor Actor) ([]byte, error)

	GetState(ctx context.Context, actor Actor) (*StateView, error)
	Validate(ctx context.Context, actor Actor, in ValidateIn) (*Plan, error)
	Plan(ctx context.Context, actor Actor, in ChangeIn) (*Plan, error)
	Apply(ctx context.Context, actor Actor, in ChangeIn) (*ApplyResult, error)
	Export(ctx context.Context, actor Actor, format ExportFormat) (*Export, error)
	Reset(ctx context.Context, actor Actor, in ResetIn) (*ApplyResult, error)

	ListMaps(ctx context.Context, actor Actor) (*MapList, error)
	GetMap(ctx context.Context, actor Actor, name string) (*model.MapSpec, error)
	ListCommunities(ctx context.Context, actor Actor) (*CommunityList, error)
	ListUsers(ctx context.Context, actor Actor) (*UserList, error)

	SetOID(ctx context.Context, actor Actor, in OIDSetIn) (*OIDResult, error)
	GetOID(ctx context.Context, actor Actor, in OIDGetIn) (*OIDResult, error)

	ListQueries(ctx context.Context, actor Actor) (*QueryList, error)

	ListTraps(ctx context.Context, actor Actor, q store.ListQuery) (*TrapList, error)
	GetTrap(ctx context.Context, actor Actor, id string) (*store.TrapRecord, error)
	WaitTraps(ctx context.Context, actor Actor, in TrapWaitIn) (*store.TrapRecord, error)
	ClearTraps(ctx context.Context, actor Actor) error
}
