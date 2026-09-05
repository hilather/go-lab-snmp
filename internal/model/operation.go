package model

// Closed plan/apply verbs. Listen/auth/engine/dtls/tcp/ui are reset-only.
const (
	OpReplaceMaps            = "replaceMaps"
	OpUpsertMap              = "upsertMap"
	OpRemoveMap              = "removeMap"
	OpReplaceCommunities     = "replaceCommunities"
	OpUpsertCommunity        = "upsertCommunity"
	OpRemoveCommunity        = "removeCommunity"
	OpReplaceUsers           = "replaceUsers"
	OpUpsertUser             = "upsertUser"
	OpRemoveUser             = "removeUser"
	OpReplaceTrapStorePolicy = "replaceTrapStorePolicy"
	OpReplaceAdmission       = "replaceAdmission"
	OpReplaceAgentCaps       = "replaceAgentCaps"
	OpReplaceObservability   = "replaceObservability"
)

// ChangeSet is the plan/apply envelope.
type ChangeSet struct {
	ExpectedRevision string      `json:"expectedRevision"`
	IdempotencyKey   string      `json:"idempotencyKey"`
	Reason           string      `json:"reason"`
	Force            bool        `json:"force"`
	Operations       []Operation `json:"operations"`
}

// Operation is one typed config mutation.
type Operation struct {
	Op              string             `json:"op"`
	Maps            []MapSpec          `json:"maps,omitempty"`
	Map             *MapSpec           `json:"map,omitempty"`
	Name            string             `json:"name,omitempty"`
	Communities     []CommunitySpec    `json:"communities,omitempty"`
	Community       *CommunitySpec     `json:"community,omitempty"`
	Users           []UserSpec         `json:"users,omitempty"`
	User            *UserSpec          `json:"user,omitempty"`
	TrapStorePolicy *TrapStoreSpec     `json:"trapStorePolicy,omitempty"`
	Admission       *AdmissionSpec     `json:"admission,omitempty"`
	AgentCaps       *AgentSpec         `json:"agentCaps,omitempty"`
	Observability   *ObservabilitySpec `json:"observability,omitempty"`
}

// KnownOp reports whether op is a v1alpha1 plan/apply verb.
func KnownOp(op string) bool {
	switch op {
	case OpReplaceMaps, OpUpsertMap, OpRemoveMap,
		OpReplaceCommunities, OpUpsertCommunity, OpRemoveCommunity,
		OpReplaceUsers, OpUpsertUser, OpRemoveUser,
		OpReplaceTrapStorePolicy, OpReplaceAdmission, OpReplaceAgentCaps,
		OpReplaceObservability:
		return true
	default:
		return false
	}
}
