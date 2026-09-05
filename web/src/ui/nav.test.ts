import { describe, expect, it } from "vitest";
import { navItems } from "./nav";
import { canSubmitReset } from "./reset";

describe("operator nav", () => {
  it("lists docs/12 pages and omits gated links without scopes", () => {
    const labels = navItems({ canPlan: false, canAudit: false, canReset: false }).map((i) => i.label);
    expect(labels).toEqual([
      "Overview",
      "Maps",
      "Communities",
      "Users",
      "Traps",
      "Queries",
      "Features",
      "Status",
    ]);
    expect(labels).not.toContain("Send trap");
    expect(labels).not.toContain("Plan");
    expect(labels).not.toContain("Reset");
    expect(labels).not.toContain("Audit");
  });

  it("includes plan, reset, and audit when allowed", () => {
    const labels = navItems({ canPlan: true, canAudit: true, canReset: true }).map((i) => i.label);
    expect(labels).toContain("Plan");
    expect(labels).toContain("Reset");
    expect(labels).toContain("Audit");
    expect(labels).not.toContain("Send trap");
  });

  it("gates reset on the exact phrase and confirmation", () => {
    expect(canSubmitReset("RESET", true, true)).toBe(true);
    expect(canSubmitReset("reset", true, true)).toBe(false);
    expect(canSubmitReset("RESET", false, true)).toBe(false);
    expect(canSubmitReset("RESET", true, false)).toBe(false);
  });
});
