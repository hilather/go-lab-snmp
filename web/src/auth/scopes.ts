export const SCOPE_READ = "snmp.read";
export const SCOPE_WRITE = "snmp.write";
export const SCOPE_ADMIN = "snmp.admin";
export const SCOPE_AUDIT = "snmp.audit.read";

export function hasScope(scopes: readonly string[], need: string): boolean {
  return scopes.includes(SCOPE_ADMIN) || scopes.includes(need);
}
