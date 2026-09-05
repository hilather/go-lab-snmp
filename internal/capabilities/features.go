package capabilities

// FeatureApplyLive and FeatureApplyResetOnly are the only apply values.
const (
	FeatureApplyLive      = "live"
	FeatureApplyResetOnly = "reset-only"
)

// Feature is one frozen live vs reset-only row (K20).
type Feature struct {
	ID    string `json:"id"`
	Apply string `json:"apply"`
	Path  string `json:"path"`
}

// Features is the frozen operator catalog. Do not list ui.enabled.
// Do not mint dtls/tcp feature ids.
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
		{ID: "engine", Apply: FeatureApplyResetOnly, Path: "spec.engine"},
		{ID: "auth", Apply: FeatureApplyResetOnly, Path: "spec.auth"},
	}
}

// FeatureIDs is the frozen id list in catalog order.
func FeatureIDs() []string {
	fs := Features()
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.ID
	}
	return out
}
