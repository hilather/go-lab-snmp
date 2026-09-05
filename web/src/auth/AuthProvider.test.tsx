import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { json, problem, resetClientState, seedCSRF, sessionView } from "../test/render";
import { AuthProvider, useAuth } from "./AuthProvider";

function Probe() {
  const { state, logout } = useAuth();
  return (
    <div>
      <p>{state.status}</p>
      <button type="button" onClick={() => void logout()}>
        Sign out
      </button>
    </div>
  );
}

describe("AuthProvider logout", () => {
  afterEach(() => {
    resetClientState();
    vi.unstubAllGlobals();
  });

  it("clears the session locally when DELETE /v1/session returns 403", async () => {
    const user = userEvent.setup();
    seedCSRF();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = (init?.method ?? "GET").toUpperCase();
        if (url.endsWith("/v1/session") && method === "GET") {
          return json(200, sessionView());
        }
        if (url.endsWith("/v1/session") && method === "DELETE") {
          return problem(403, "forbidden", "CSRF token is missing or invalid");
        }
        return problem(404, "not_found", "not found");
      }),
    );
    render(
      <AuthProvider>
        <Probe />
      </AuthProvider>,
    );
    expect(await screen.findByText("signed_in")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Sign out/i }));
    await waitFor(() => {
      expect(screen.getByText("anonymous")).toBeInTheDocument();
    });
  });
});
