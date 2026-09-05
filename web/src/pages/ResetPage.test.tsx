import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { json, problem, renderApp, resetClientState, sessionView } from "../test/render";
import { ResetPage } from "./ResetPage";

describe("ResetPage", () => {
  afterEach(() => {
    resetClientState();
    vi.unstubAllGlobals();
  });

  it("keeps reset disabled until RESET is typed and confirmed", async () => {
    const user = userEvent.setup();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (String(input).endsWith("/v1/session")) {
          return json(200, sessionView());
        }
        return problem(404, "not_found", "not found");
      }),
    );
    renderApp(<ResetPage />, { route: "/reset" });
    const submit = await screen.findByRole("button", { name: /Reset LabSNMP/i });
    expect(submit).toBeDisabled();
    await user.type(screen.getByLabelText(/Confirmation phrase/i), "RESET");
    expect(submit).toBeDisabled();
    await user.click(screen.getByLabelText(/Wipe overlay/i));
    expect(submit).toBeEnabled();
  });

  it("keeps reset disabled without snmp.admin", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (String(input).endsWith("/v1/session")) {
          return json(200, sessionView(["snmp.read", "snmp.write"]));
        }
        return problem(404, "not_found", "not found");
      }),
    );
    renderApp(<ResetPage />, { route: "/reset" });
    const submit = await screen.findByRole("button", { name: /Reset LabSNMP/i });
    expect(submit).toBeDisabled();
  });
});
