export type NavItem = { to: string; label: string };

export function navItems(opts: { canPlan: boolean; canAudit: boolean; canReset: boolean }): NavItem[] {
  const items: NavItem[] = [
    { to: "/", label: "Overview" },
    { to: "/maps", label: "Maps" },
    { to: "/communities", label: "Communities" },
    { to: "/users", label: "Users" },
    { to: "/traps", label: "Traps" },
    { to: "/queries", label: "Queries" },
  ];
  if (opts.canPlan) {
    items.push({ to: "/plan", label: "Plan" });
  }
  if (opts.canReset) {
    items.push({ to: "/reset", label: "Reset" });
  }
  if (opts.canAudit) {
    items.push({ to: "/audit", label: "Audit" });
  }
  items.push({ to: "/features", label: "Features" }, { to: "/status", label: "Status" });
  return items;
}
