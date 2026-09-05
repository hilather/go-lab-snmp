package auth

import "github.com/hilather/go-lab-snmp/internal/model"

// DefaultScopes returns the frozen role → scope set. 1.0 has no token
// scopes field; role expands to the catalog.
func DefaultScopes(role string) []string {
	return model.ScopesForRole(role)
}

func expandRole(role string) (string, []string) {
	if role == "" {
		role = model.RoleAdministrator
	}
	return role, DefaultScopes(role)
}
