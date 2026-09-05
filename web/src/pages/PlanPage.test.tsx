import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CSRF_HEADER } from "../api/client";
import { json, problem, renderApp, resetClientState, seedCSRF, sessionView } from "../test/render";
import { PlanPage } from "./PlanPage";

describe("PlanPage", () => {
  afterEach(() => {
    resetClientState();
    vi.unstubAllGlobals();
  });

  it("applies with runtimeRevision and CSRF", async () => {
    const user = userEvent.setup();
    seedCSRF();
    const posts: Array<{ url: string; init: RequestInit | undefined }> = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = (init?.method ?? "GET").toUpperCase();
        if (url.endsWith("/v1/session") && method === "GET") {
          return json(200, sessionView());
        }
        if (url.endsWith("/v1/state") && method === "GET") {
          return json(200, {
            bootstrapRevision: "sha256:boot",
            runtimeRevision: "sha256:runtime",
            generation: 1,
            drifted: false,
          });
        }
        if (url.endsWith("/v1/changes:apply") && method === "POST") {
          posts.push({ url, init });
          return json(200, { applied: true, runtimeRevision: "sha256:next", diff: [] });
        }
        return problem(404, "not_found", "not found");
      }),
    );

    renderApp(<PlanPage />, { route: "/plan" });
    await user.click(await screen.findByRole("button", { name: /^Apply$/i }));
    await waitFor(() => {
      expect(posts).toHaveLength(1);
    });
    const init = posts[0]?.init;
    if (!init) {
      throw new Error("expected POST");
    }
    expect(new Headers(init.headers).get(CSRF_HEADER)).toBe("csrf-test");
    const body = JSON.parse(String(init.body)) as { expectedRevision: string; operations: unknown[] };
    expect(body.expectedRevision).toBe("sha256:runtime");
    expect(body.operations.length).toBeGreaterThan(0);
    expect(localStorage.length).toBe(0);
  });
});
