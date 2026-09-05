package app

// Features is the frozen operator catalog from docs/04 live vs reset-only
// rows (K20). Do not list ui.enabled. Do not mint dtls/tcp feature ids.
func Features() []Feature {
	return []Feature{
		{ID: "maps", Apply: FeatureApplyLive, Path: "spec.maps"},
		{ID: "communities", Apply: FeatureApplyLive, Path: "spec.communities"},
		{ID: "users", Apply: FeatureApplyLive, Path: "spec.users"},
		{ID: "trapStorePolicy", Apply: FeatureApplyLive, Path: "spec.traps"},
		{ID: "admission", Apply: FeatureApplyLive, Path: "spec.admission"},
		{ID: "agentCaps", Apply: FeatureApplyLive, Path: "spec.agent"},
		{ID: "observability", Apply: FeatureApplyLive, Path: "spec.observability"},
		{ID: "listeners.agent.address", Apply: FeatureApplyResetOnly, Path: "spec.listeners.agent.address"},
		{ID: "listeners.traps.address", Apply: FeatureApplyResetOnly, Path: "spec.listeners.traps.address"},
		{ID: "listeners.management.address", Apply: FeatureApplyResetOnly, Path: "spec.listeners.management.address"},
		{ID: "auth", Apply: FeatureApplyResetOnly, Path: "spec.auth"},
		{ID: "engine", Apply: FeatureApplyResetOnly, Path: "spec.engine"},
		{ID: "management.allowedOrigins", Apply: FeatureApplyResetOnly, Path: "spec.management.allowedOrigins"},
		{ID: "management.mcp.allowLegacyClients", Apply: FeatureApplyResetOnly, Path: "spec.management.mcp.allowLegacyClients"},
		{ID: "management.bodyLimit", Apply: FeatureApplyResetOnly, Path: "spec.management.bodyLimit"},
	}
}
