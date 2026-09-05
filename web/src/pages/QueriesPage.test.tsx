import { screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { json, problem, renderApp, resetClientState, sessionView } from "../test/render";
import { QueriesPage } from "./QueriesPage";

describe("QueriesPage", () => {
  afterEach(() => {
    resetClientState();
    vi.unstubAllGlobals();
  });

  it("renders camelCase query columns from GET /v1/queries", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/v1/session")) {
          return json(200, sessionView());
        }
        if (url.endsWith("/v1/queries")) {
          return json(200, {
            items: [{ type: "get", identity: "public", decision: "ok", errorStatus: 0 }],
          });
        }
        return problem(404, "not_found", "not found");
      }),
    );
    renderApp(<QueriesPage />, { route: "/queries" });
    expect(await screen.findByText("get")).toBeInTheDocument();
    expect(screen.getByText("public")).toBeInTheDocument();
    expect(screen.getByText("ok")).toBeInTheDocument();
    expect(screen.getByText("0")).toBeInTheDocument();
  });
});
