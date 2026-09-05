import { screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { json, problem, renderApp, resetClientState, sessionView } from "../test/render";
import { AuditPage } from "./AuditPage";
import { CommunitiesPage } from "./CommunitiesPage";
import { MapsPage } from "./MapsPage";
import { QueriesPage } from "./QueriesPage";
import { TrapsPage } from "./TrapsPage";
import { UsersPage } from "./UsersPage";

function stubList(path: string, body: unknown) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/v1/session")) {
        return json(200, sessionView());
      }
      if (url.includes(path)) {
        return json(200, body);
      }
      return problem(404, "not_found", "not found");
    }),
  );
}

describe("empty states", () => {
  afterEach(() => {
    resetClientState();
    vi.unstubAllGlobals();
  });

  it("maps", async () => {
    stubList("/v1/maps", { items: [] });
    renderApp(<MapsPage />, { route: "/maps" });
    expect(await screen.findByText("No maps in the live snapshot.")).toBeInTheDocument();
  });

  it("communities", async () => {
    stubList("/v1/communities", { items: [] });
    renderApp(<CommunitiesPage />, { route: "/communities" });
    expect(await screen.findByText("No communities in the live snapshot.")).toBeInTheDocument();
  });

  it("users", async () => {
    stubList("/v1/users", { items: [] });
    renderApp(<UsersPage />, { route: "/users" });
    expect(await screen.findByText("No USM users in the live snapshot.")).toBeInTheDocument();
  });

  it("traps", async () => {
    stubList("/v1/traps", { items: [] });
    renderApp(<TrapsPage />, { route: "/traps" });
    expect(await screen.findByText(/Trap inbox is empty/)).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /send trap/i })).toBeNull();
  });

  it("queries", async () => {
    stubList("/v1/queries", { items: [] });
    renderApp(<QueriesPage />, { route: "/queries" });
    expect(await screen.findByText("No recent PDUs in the query ring.")).toBeInTheDocument();
  });

  it("audit", async () => {
    stubList("/v1/audit", { events: [] });
    renderApp(<AuditPage />, { route: "/audit" });
    expect(await screen.findByText("No audit events in the in-memory ring.")).toBeInTheDocument();
  });
});
