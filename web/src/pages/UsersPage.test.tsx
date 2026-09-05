import { screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { json, problem, renderApp, resetClientState, sessionView } from "../test/render";
import { UsersPage } from "./UsersPage";

describe("UsersPage", () => {
  afterEach(() => {
    resetClientState();
    vi.unstubAllGlobals();
  });

  it("shows secretFile paths and never secret bytes", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/v1/session")) {
          return json(200, sessionView());
        }
        if (url.endsWith("/v1/users")) {
          return json(200, {
            items: [
              {
                name: "alice",
                level: "authPriv",
                auth: { protocol: "sha256", secretFile: "testdata/secrets/snmp-alice-auth" },
                priv: { protocol: "aes128", secretFile: "testdata/secrets/snmp-alice-priv" },
                access: "read-write",
                map: "private-if",
              },
            ],
          });
        }
        return problem(404, "not_found", "not found");
      }),
    );
    renderApp(<UsersPage />, { route: "/users" });
    expect(await screen.findByText("alice")).toBeInTheDocument();
    expect(screen.getByText("testdata/secrets/snmp-alice-auth")).toBeInTheDocument();
    expect(screen.queryByText(/passphrase/i)).toBeNull();
  });
});
