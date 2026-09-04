package config

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/hilather/go-lab-snmp/internal/domainerr"
	"github.com/hilather/go-lab-snmp/internal/model"
)

// Normalize returns a copy of st with defaults materialized. omitted
// allowClientCidrs becomes loopback only.
func Normalize(st *model.State) (*model.State, []Warning, error) {
	if st == nil {
		return nil, nil, domainerr.ValidationFailed("nil state",
			domainerr.FieldViolation{Path: "", Code: violationRequired, Message: "state is nil"})
	}
	out, err := cloneState(st)
	if err != nil {
		return nil, nil, err
	}
	var warns []Warning
	materializeDefaults(&out.Spec)
	return out, warns, nil
}

func cloneState(st *model.State) (*model.State, error) {
	b, err := json.Marshal(st)
	if err != nil {
		return nil, domainerr.Internal("clone marshal: " + err.Error())
	}
	var out model.State
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, domainerr.Internal("clone unmarshal: " + err.Error())
	}
	return &out, nil
}

func materializeDefaults(sp *model.Spec) {
	if strings.TrimSpace(sp.Listeners.Agent.Address) == "" {
		sp.Listeners.Agent.Address = DefaultAgentAddress
	}
	if strings.TrimSpace(sp.Listeners.Traps.Address) == "" {
		sp.Listeners.Traps.Address = DefaultTrapAddress
	}
	if strings.TrimSpace(sp.Listeners.Management.RESTPath) == "" {
		sp.Listeners.Management.RESTPath = DefaultRESTPath
	}
	if strings.TrimSpace(sp.Listeners.Management.MCPPath) == "" {
		sp.Listeners.Management.MCPPath = DefaultMCPPath
	}
	if strings.TrimSpace(sp.Auth.Mode) == "" {
		sp.Auth.Mode = model.MgmtAuthBearer
	}
	if sp.Auth.Tokens == nil {
		sp.Auth.Tokens = []model.TokenSpec{}
	}
	if sp.Management.AllowedOrigins == nil {
		sp.Management.AllowedOrigins = []string{}
	}
	if sp.Engine.EngineBoots == 0 {
		sp.Engine.EngineBoots = DefaultEngineBoots
	}
	if len(sp.Agent.Versions) == 0 {
		sp.Agent.Versions = []string{model.VersionV1, model.VersionV2c, model.VersionV3}
	}
	if sp.Agent.MaxVarBinds == 0 {
		sp.Agent.MaxVarBinds = DefaultMaxVarBinds
	}
	if sp.Agent.MaxRepetitions == 0 {
		sp.Agent.MaxRepetitions = DefaultMaxRepetitions
	}
	if sp.Agent.MaxMessageBytes == 0 {
		sp.Agent.MaxMessageBytes = DefaultMaxMessageBytes
	}
	if sp.Admission.AllowClientCidrs == nil {
		sp.Admission.AllowClientCidrs = []string{"127.0.0.0/8", "::1/128"}
	}
	if sp.Admission.MaxDatagramsPerSec == 0 {
		sp.Admission.MaxDatagramsPerSec = DefaultMaxDatagramsPerSec
	}
	if sp.Admission.MaxDatagramsPerIP == 0 {
		sp.Admission.MaxDatagramsPerIP = DefaultMaxDatagramsPerIP
	}
	if sp.Maps == nil {
		sp.Maps = []model.MapSpec{}
	}
	for i := range sp.Maps {
		if sp.Maps[i].Objects == nil {
			sp.Maps[i].Objects = []model.ObjectSpec{}
		}
		for j := range sp.Maps[i].Objects {
			if strings.TrimSpace(sp.Maps[i].Objects[j].Access) == "" {
				sp.Maps[i].Objects[j].Access = model.AccessRead
			}
		}
	}
	if sp.Communities == nil {
		sp.Communities = []model.CommunitySpec{}
	}
	defCommVers := communityDefaultVersions(sp.Agent.Versions)
	for i := range sp.Communities {
		if sp.Communities[i].Versions == nil {
			sp.Communities[i].Versions = append([]string(nil), defCommVers...)
		}
		if strings.TrimSpace(sp.Communities[i].Access) == "" {
			sp.Communities[i].Access = model.AccessRead
		}
	}
	if sp.Users == nil {
		sp.Users = []model.UserSpec{}
	}
	for i := range sp.Users {
		if strings.TrimSpace(sp.Users[i].Access) == "" {
			sp.Users[i].Access = model.AccessRead
		}
	}
	if sp.Traps.MaxMessages == 0 {
		sp.Traps.MaxMessages = DefaultMaxMessages
	}
	if sp.Traps.MaxBytes == 0 {
		sp.Traps.MaxBytes = DefaultMaxTrapBytes
	}
	if strings.TrimSpace(sp.Traps.FullPolicy) == "" {
		sp.Traps.FullPolicy = model.FullPolicyEvictOldest
	}
	if sp.Traps.MaxWait == 0 {
		if d, err := time.ParseDuration(DefaultMaxWait); err == nil {
			sp.Traps.MaxWait = d
		} else {
			sp.Traps.MaxWait = 60 * time.Second
		}
	}
	if strings.TrimSpace(sp.Observability.LogLevel) == "" {
		sp.Observability.LogLevel = model.LogLevelInfo
	}
}

func communityDefaultVersions(agent []string) []string {
	out := make([]string, 0, len(agent))
	for _, v := range agent {
		if v != model.VersionV3 {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return []string{model.VersionV1, model.VersionV2c}
	}
	return out
}
