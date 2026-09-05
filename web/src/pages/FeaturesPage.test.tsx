import { screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { json, problem, renderApp, resetClientState, sessionView } from "../test/render";
import { FeaturesPage } from "./FeaturesPage";

const FROZEN = [
  { id: "maps", apply: "live", path: "spec.maps" },
  { id: "communities", apply: "live", path: "spec.communities" },
  { id: "users", apply: "live", path: "spec.users" },
  { id: "trapStorePolicy", apply: "live", path: "spec.traps" },
  { id: "admission", apply: "live", path: "spec.admission" },
  { id: "agentCaps", apply: "live", path: "spec.agent" },
  { id: "observability", apply: "live", path: "spec.observability" },
  { id: "listeners.agent.address", apply: "reset-only", path: "spec.listeners.agent.address" },
  { id: "listeners.traps.address", apply: "reset-only", path: "spec.listeners.traps.address" },
  { id: "listeners.management.address", apply: "reset-only", path: "spec.listeners.management.address" },
  { id: "engine", apply: "reset-only", path: "spec.engine" },
  { id: "auth", apply: "reset-only", path: "spec.auth" },
];

describe("FeaturesPage", () => {
  afterEach(() => {
    resetClientState();
    vi.unstubAllGlobals();
  });

  it("renders live and reset-only chips for the frozen twelve ids", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/v1/session")) {
          return json(200, sessionView());
        }
        if (url.endsWith("/v1/features")) {
          return json(200, { items: FROZEN });
        }
        return problem(404, "not_found", "not found");
      }),
    );
    renderApp(<FeaturesPage />, { route: "/features" });
    expect((await screen.findAllByText("live")).length).toBeGreaterThan(0);
    expect(screen.getAllByText("reset-only").length).toBeGreaterThan(0);
    expect(FROZEN).toHaveLength(12);
    for (const f of FROZEN) {
      expect(screen.getByText(f.id)).toBeInTheDocument();
    }
    for (const id of ["ui.enabled", "dtls", "tcp"]) {
      expect(FROZEN.map((f) => f.id)).not.toContain(id);
      expect(screen.queryByText(id)).toBeNull();
    }
    expect(
      screen.getByText(/UI enablement is bootstrap YAML; reread with Reset. Not a features.list id./),
    ).toBeInTheDocument();
  });
});
