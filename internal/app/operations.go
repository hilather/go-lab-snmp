package app

import (
	"encoding/json"
	"strconv"

	"github.com/hilather/go-lab-snmp/internal/domainerr"
	"github.com/hilather/go-lab-snmp/internal/model"
)

func applyOperations(st *model.State, ops []model.Operation) error {
	if st == nil {
		return domainerr.ValidationFailed("nil state",
			domainerr.FieldViolation{Path: "", Code: "required", Message: "state is nil"})
	}
	for i, op := range ops {
		if err := applyOne(st, op, i); err != nil {
			return err
		}
	}
	return nil
}

func applyOne(st *model.State, op model.Operation, i int) error {
	path := "operations[" + strconv.Itoa(i) + "]"
	if !model.KnownOp(op.Op) {
		return domainerr.ValidationFailed("unknown operation",
			domainerr.FieldViolation{Path: path + ".op", Code: "invalid_value", Message: "unknown op; listen/auth/engine/ui/management are reset-only"}).
			WithRemediation("reset-only; rewrite bootstrap and POST /v1/state:reset")
	}
	switch op.Op {
	case model.OpReplaceMaps:
		st.Spec.Maps = append([]model.MapSpec(nil), op.Maps...)
	case model.OpUpsertMap:
		if op.Map == nil {
			return domainerr.ValidationFailed("missing map",
				domainerr.FieldViolation{Path: path + ".map", Code: "required", Message: "upsertMap requires map"})
		}
		upsertNamed(&st.Spec.Maps, *op.Map, func(m model.MapSpec) string { return m.Name })
	case model.OpRemoveMap:
		if op.Name == "" {
			return domainerr.ValidationFailed("missing name",
				domainerr.FieldViolation{Path: path + ".name", Code: "required", Message: "removeMap requires name"})
		}
		if !removeNamed(&st.Spec.Maps, op.Name, func(m model.MapSpec) string { return m.Name }) {
			return domainerr.NotFound("map " + op.Name + " not found")
		}
	case model.OpReplaceCommunities:
		st.Spec.Communities = append([]model.CommunitySpec(nil), op.Communities...)
	case model.OpUpsertCommunity:
		if op.Community == nil {
			return domainerr.ValidationFailed("missing community",
				domainerr.FieldViolation{Path: path + ".community", Code: "required", Message: "upsertCommunity requires community"})
		}
		upsertNamed(&st.Spec.Communities, *op.Community, func(c model.CommunitySpec) string { return c.Name })
	case model.OpRemoveCommunity:
		if op.Name == "" {
			return domainerr.ValidationFailed("missing name",
				domainerr.FieldViolation{Path: path + ".name", Code: "required", Message: "removeCommunity requires name"})
		}
		if !removeNamed(&st.Spec.Communities, op.Name, func(c model.CommunitySpec) string { return c.Name }) {
			return domainerr.NotFound("community " + op.Name + " not found")
		}
	case model.OpReplaceUsers:
		st.Spec.Users = append([]model.UserSpec(nil), op.Users...)
	case model.OpUpsertUser:
		if op.User == nil {
			return domainerr.ValidationFailed("missing user",
				domainerr.FieldViolation{Path: path + ".user", Code: "required", Message: "upsertUser requires user"})
		}
		upsertNamed(&st.Spec.Users, *op.User, func(u model.UserSpec) string { return u.Name })
	case model.OpRemoveUser:
		if op.Name == "" {
			return domainerr.ValidationFailed("missing name",
				domainerr.FieldViolation{Path: path + ".name", Code: "required", Message: "removeUser requires name"})
		}
		if !removeNamed(&st.Spec.Users, op.Name, func(u model.UserSpec) string { return u.Name }) {
			return domainerr.NotFound("user " + op.Name + " not found")
		}
	case model.OpReplaceTrapStorePolicy:
		if op.TrapStorePolicy == nil {
			return domainerr.ValidationFailed("missing trapStorePolicy",
				domainerr.FieldViolation{Path: path + ".trapStorePolicy", Code: "required", Message: "replaceTrapStorePolicy requires trapStorePolicy"})
		}
		st.Spec.Traps = *op.TrapStorePolicy
	case model.OpReplaceAdmission:
		if op.Admission == nil {
			return domainerr.ValidationFailed("missing admission",
				domainerr.FieldViolation{Path: path + ".admission", Code: "required", Message: "replaceAdmission requires admission"})
		}
		st.Spec.Admission = *op.Admission
	case model.OpReplaceAgentCaps:
		if op.AgentCaps == nil {
			return domainerr.ValidationFailed("missing agentCaps",
				domainerr.FieldViolation{Path: path + ".agentCaps", Code: "required", Message: "replaceAgentCaps requires agentCaps"})
		}
		st.Spec.Agent = *op.AgentCaps
	case model.OpReplaceObservability:
		if op.Observability == nil {
			return domainerr.ValidationFailed("missing observability",
				domainerr.FieldViolation{Path: path + ".observability", Code: "required", Message: "replaceObservability requires observability"})
		}
		st.Spec.Observability = *op.Observability
	}
	return nil
}

func upsertNamed[T any](list *[]T, item T, name func(T) string) {
	want := name(item)
	for i := range *list {
		if name((*list)[i]) == want {
			(*list)[i] = item
			return
		}
	}
	*list = append(*list, item)
}

func removeNamed[T any](list *[]T, name string, of func(T) string) bool {
	dst := (*list)[:0]
	found := false
	for _, item := range *list {
		if of(item) == name {
			found = true
			continue
		}
		dst = append(dst, item)
	}
	*list = dst
	return found
}

func rejectResetOnly(before, after *model.State) error {
	if before == nil || after == nil {
		return nil
	}
	rem := "reset-only; rewrite bootstrap and POST /v1/state:reset"
	if !jsonEqual(before.Spec.Listeners, after.Spec.Listeners) {
		return domainerr.ValidationFailed("listeners are reset-only",
			domainerr.FieldViolation{Path: "spec.listeners", Code: "invalid_value", Message: "listen addresses cannot change via Apply"}).
			WithRemediation(rem)
	}
	if !jsonEqual(before.Spec.Auth, after.Spec.Auth) {
		return domainerr.ValidationFailed("spec.auth is reset-only",
			domainerr.FieldViolation{Path: "spec.auth", Code: "invalid_value", Message: "auth cannot change via Apply"}).
			WithRemediation(rem)
	}
	if !jsonEqual(before.Spec.Engine, after.Spec.Engine) {
		return domainerr.ValidationFailed("spec.engine is reset-only",
			domainerr.FieldViolation{Path: "spec.engine", Code: "invalid_value", Message: "engineID/boots cannot change via Apply"}).
			WithRemediation(rem)
	}
	if !jsonEqual(before.Spec.UI, after.Spec.UI) {
		return domainerr.ValidationFailed("spec.ui is reset-only",
			domainerr.FieldViolation{Path: "spec.ui", Code: "invalid_value", Message: "ui.enabled cannot change via Apply"}).
			WithRemediation(rem)
	}
	if !jsonEqual(before.Spec.Management, after.Spec.Management) {
		return domainerr.ValidationFailed("spec.management is reset-only",
			domainerr.FieldViolation{Path: "spec.management", Code: "invalid_value", Message: "management address/paths/origins/bodyLimit cannot change via Apply"}).
			WithRemediation(rem)
	}
	return nil
}

func jsonEqual(a, b any) bool {
	ab, err := json.Marshal(a)
	if err != nil {
		return false
	}
	bb, err := json.Marshal(b)
	if err != nil {
		return false
	}
	return string(ab) == string(bb)
}
