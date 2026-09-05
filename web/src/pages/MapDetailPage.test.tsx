import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CSRF_HEADER } from "../api/client";
import type { MapSpec } from "../api/types";
import { json, problem, renderApp, resetClientState, seedCSRF, sessionView } from "../test/render";
import { MapDetailPage } from "./MapDetailPage";

const sample: MapSpec = {
  name: "public-if",
  objects: [
    { oid: "1.3.6.1.2.1.2.2.1.8.1", name: "ifOperStatus.1", type: "integer", access: "write", value: 1 },
  ],
};

describe("MapDetailPage", () => {
  afterEach(() => {
    resetClientState();
    vi.unstubAllGlobals();
  });

  it("posts oids:set with CSRF and does not store tokens", async () => {
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
        if (url.endsWith("/v1/maps/public-if") && method === "GET") {
          return json(200, sample);
        }
        if (url.includes("/oids:set") && method === "POST") {
          posts.push({ url, init });
          return json(200, { oid: "1.3.6.1.2.1.2.2.1.8.1", type: "integer", value: 2, overlay: true });
        }
        return problem(404, "not_found", "not found");
      }),
    );

    renderApp(<MapDetailPage />, { route: "/maps/public-if", path: "/maps/:name" });
    await screen.findByRole("heading", { name: "public-if" });
    await user.type(screen.getByLabelText(/^OID$/i), "1.3.6.1.2.1.2.2.1.8.1");
    await user.type(screen.getByLabelText(/^Value$/i), "2");
    await user.click(screen.getByRole("button", { name: /Set overlay/i }));

    await waitFor(() => {
      expect(posts).toHaveLength(1);
    });
    const init = posts[0]?.init;
    if (!init) {
      throw new Error("expected POST");
    }
    expect(new Headers(init.headers).get(CSRF_HEADER)).toBe("csrf-test");
    const body = JSON.parse(String(init.body)) as { oid: string; value: unknown };
    expect(body.value).toBe(2);
    expect(typeof body.value).toBe("number");
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
    expect(await screen.findByText("2 (overlay)")).toBeInTheDocument();
  });

  it("keeps digit-only octetString as a JSON string", async () => {
    const user = userEvent.setup();
    seedCSRF();
    const posts: Array<RequestInit | undefined> = [];
    const octetMap: MapSpec = {
      name: "public-if",
      objects: [{ oid: "1.3.6.1.2.1.1.1.0", name: "sysDescr", type: "octetString", access: "write", value: "x" }],
    };
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = (init?.method ?? "GET").toUpperCase();
        if (url.endsWith("/v1/session") && method === "GET") {
          return json(200, sessionView());
        }
        if (url.endsWith("/v1/maps/public-if") && method === "GET") {
          return json(200, octetMap);
        }
        if (url.includes("/oids:set") && method === "POST") {
          posts.push(init);
          return json(200, { oid: "1.3.6.1.2.1.1.1.0", type: "octetString", value: "123", overlay: true });
        }
        return problem(404, "not_found", "not found");
      }),
    );
    renderApp(<MapDetailPage />, { route: "/maps/public-if", path: "/maps/:name" });
    await screen.findByRole("heading", { name: "public-if" });
    await user.type(screen.getByLabelText(/^OID$/i), "1.3.6.1.2.1.1.1.0");
    await user.type(screen.getByLabelText(/^Value$/i), "123");
    await user.click(screen.getByRole("button", { name: /Set overlay/i }));
    await waitFor(() => {
      expect(posts).toHaveLength(1);
    });
    const body = JSON.parse(String(posts[0]?.body)) as { value: unknown };
    expect(body.value).toBe("123");
    expect(typeof body.value).toBe("string");
  });

  it("sends counter64 above 2^53 as a digit string", async () => {
    const user = userEvent.setup();
    seedCSRF();
    const posts: Array<RequestInit | undefined> = [];
    const c64: MapSpec = {
      name: "public-if",
      objects: [
        { oid: "1.3.6.1.4.1.99999.2.0", name: "labCounter64", type: "counter64", access: "write", value: 0 },
      ],
    };
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = (init?.method ?? "GET").toUpperCase();
        if (url.endsWith("/v1/session") && method === "GET") {
          return json(200, sessionView());
        }
        if (url.endsWith("/v1/maps/public-if") && method === "GET") {
          return json(200, c64);
        }
        if (url.includes("/oids:set") && method === "POST") {
          posts.push(init);
          return json(200, {
            oid: "1.3.6.1.4.1.99999.2.0",
            type: "counter64",
            value: "18446744073709551615",
            overlay: true,
          });
        }
        return problem(404, "not_found", "not found");
      }),
    );
    renderApp(<MapDetailPage />, { route: "/maps/public-if", path: "/maps/:name" });
    await screen.findByRole("heading", { name: "public-if" });
    await user.type(screen.getByLabelText(/^OID$/i), "1.3.6.1.4.1.99999.2.0");
    await user.type(screen.getByLabelText(/^Value$/i), "18446744073709551615");
    await user.click(screen.getByRole("button", { name: /Set overlay/i }));
    await waitFor(() => {
      expect(posts).toHaveLength(1);
    });
    const body = JSON.parse(String(posts[0]?.body)) as { value: unknown };
    expect(body.value).toBe("18446744073709551615");
    expect(typeof body.value).toBe("string");
  });

  it("disables overlay write without snmp.write", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = (init?.method ?? "GET").toUpperCase();
        if (url.endsWith("/v1/session") && method === "GET") {
          return json(200, sessionView(["snmp.read"]));
        }
        if (url.endsWith("/v1/maps/public-if") && method === "GET") {
          return json(200, sample);
        }
        return problem(404, "not_found", "not found");
      }),
    );
    renderApp(<MapDetailPage />, { route: "/maps/public-if", path: "/maps/:name" });
    const submit = await screen.findByRole("button", { name: /Set overlay/i });
    expect(submit).toBeDisabled();
  });
});
