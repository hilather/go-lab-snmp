import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import { json, problem, resetClientState, sessionView } from "./test/render";

describe("App nav", () => {
  afterEach(() => {
    resetClientState();
    vi.unstubAllGlobals();
  });

  it("shows docs/12 pages and hides Reset without snmp.admin", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/v1/session")) {
          return json(200, sessionView(["snmp.read"]));
        }
        if (url.endsWith("/v1/status")) {
          return json(200, { ready: true, hostTime: "2026-09-05T00:00:00Z", listeners: [] });
        }
        if (url.endsWith("/v1/state")) {
          return json(200, {
            bootstrapRevision: "sha256:boot",
            runtimeRevision: "sha256:runtime",
            generation: 1,
            drifted: false,
          });
        }
        if (url.endsWith("/v1/stats")) {
          return json(200, { traps: { messages: 0, bytes: 0, generation: 0, dropped: 0 }, overlayGeneration: 0, queries: 0 });
        }
        return problem(404, "not_found", "not found");
      }),
    );
    render(<App />);
    expect(await screen.findByRole("link", { name: "Overview" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Maps" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Communities" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Users" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Traps" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Queries" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Features" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Status" })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Reset" })).toBeNull();
    expect(screen.queryByRole("link", { name: "Plan" })).toBeNull();
    expect(screen.queryByRole("link", { name: /send trap/i })).toBeNull();
  });
});
