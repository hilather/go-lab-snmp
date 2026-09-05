package store

// ResetEphemeral drops SET overlay, trap inbox, and the query ring.
// Each collection increments its own generation. Reset never writes YAML.
func ResetEphemeral(overlay *Overlay, traps *TrapRing, queries *QueryRing) {
	overlay.Clear()
	traps.Wipe()
	queries.Clear()
}
