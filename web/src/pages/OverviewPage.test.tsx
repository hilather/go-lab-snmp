import { screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { json, problem, renderApp, resetClientState, sessionView } from "../test/render";
import { OverviewPage } from "./OverviewPage";

const UDP = [
  { name: "agent", address: ":161" },
  { name: "traps", address: ":162" },
  { name: "management", address: "off" },
];

const WITH_TCP_DTLS = [
  ...UDP,
  { name: "agent-tcp", address: ":1161" },
  { name: "traps-tcp", address: ":1162" },
  { name: "agent-dtls", address: ":10161" },
  { name: "traps-dtls", address: ":10162" },
];

function stubOverview(listeners: { name: string; address: string }[]) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/v1/session")) {
        return json(200, sessionView());
      }
      if (url.endsWith("/v1/status")) {
        return json(200, { ready: true, hostTime: "2026-09-05T00:00:00Z", listeners });
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
        return json(200, {
          traps: { messages: 0, bytes: 0, generation: 0, dropped: 0 },
          overlayGeneration: 0,
          queries: 0,
        });
      }
      return problem(404, "not_found", "not found");
    }),
  );
}

describe("OverviewPage", () => {
  afterEach(() => {
    resetClientState();
    vi.unstubAllGlobals();
  });

  it("shows Agent TCP and Agent DTLS dt/dd when those listeners are present", async () => {
    stubOverview(WITH_TCP_DTLS);
    renderApp(<OverviewPage />, { route: "/" });
    expect(await screen.findByText("Agent TCP")).toBeInTheDocument();
    expect(screen.getByText("Agent TCP").nextElementSibling).toHaveTextContent(":1161");
    expect(screen.getByText("Agent DTLS")).toBeInTheDocument();
    expect(screen.getByText("Agent DTLS").nextElementSibling).toHaveTextContent(":10161");
    expect(screen.getByText(/agent-tcp:/)).toBeInTheDocument();
    expect(screen.getByText(/traps-tcp:/)).toBeInTheDocument();
    expect(screen.getByText(/agent-dtls:/)).toBeInTheDocument();
    expect(screen.getByText(/traps-dtls:/)).toBeInTheDocument();
  });

  it("omits Agent TCP and Agent DTLS dt/dd when those listeners are absent", async () => {
    stubOverview(UDP);
    renderApp(<OverviewPage />, { route: "/" });
    expect(await screen.findByText("Ready")).toBeInTheDocument();
    expect(screen.queryByText("Agent TCP")).toBeNull();
    expect(screen.queryByText("Agent DTLS")).toBeNull();
    expect(screen.queryByText(/agent-tcp:/)).toBeNull();
    expect(screen.queryByText(/agent-dtls:/)).toBeNull();
  });
});
