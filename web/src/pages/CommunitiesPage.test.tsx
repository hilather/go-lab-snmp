import { screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { json, problem, renderApp, resetClientState, sessionView } from "../test/render";
import { CommunitiesPage } from "./CommunitiesPage";

describe("CommunitiesPage", () => {
  afterEach(() => {
    resetClientState();
    vi.unstubAllGlobals();
  });

  it("shows communityFile paths and never wire strings", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/v1/session")) {
          return json(200, sessionView());
        }
        if (url.endsWith("/v1/communities")) {
          return json(200, {
            items: [
              {
                name: "public",
                communityFile: "testdata/secrets/snmp-public",
                versions: ["v2c"],
                access: "read",
                map: "public-if",
              },
            ],
          });
        }
        return problem(404, "not_found", "not found");
      }),
    );
    renderApp(<CommunitiesPage />, { route: "/communities" });
    expect(await screen.findByText("public")).toBeInTheDocument();
    expect(screen.getByText("testdata/secrets/snmp-public")).toBeInTheDocument();
    expect(screen.queryByText(/publicwire/i)).toBeNull();
    expect(screen.getByText(/Wire strings and file contents are never shown/)).toBeInTheDocument();
  });
});
