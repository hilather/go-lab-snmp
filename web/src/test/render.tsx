import { render, type RenderOptions } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import type { ReactElement, ReactNode } from "react";
import { clearMemoryCSRF, setMemoryCSRF } from "../api/client";
import { assertNoTokenStorage } from "../api/storage";
import type { SessionView } from "../api/types";
import { AuthProvider } from "../auth/AuthProvider";

export const ALL_SCOPES = ["snmp.read", "snmp.write", "snmp.admin", "snmp.audit.read"];

export function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": status >= 400 ? "application/problem+json" : "application/json" },
  });
}

export function sessionView(scopes: string[] = ALL_SCOPES): SessionView {
  return {
    id: "admin",
    role: "administrator",
    scopes,
    csrf: "csrf-test",
    expiresAt: "2099-01-01T00:00:00Z",
  };
}

export function seedCSRF(): void {
  setMemoryCSRF("csrf-test");
}

export function problem(status: number, code: string, detail: string): Response {
  return json(status, {
    status,
    title: code,
    detail,
    code,
    type: `urn:labsnmp:error:${code.replaceAll("_", "-")}`,
  });
}

export function renderApp(
  ui: ReactElement,
  options?: Omit<RenderOptions, "wrapper"> & { route?: string; path?: string },
) {
  const route = options?.route ?? "/";
  const path = options?.path;
  function Wrapper({ children }: { children: ReactNode }) {
    const inner = path ? (
      <Routes>
        <Route path={path} element={children} />
      </Routes>
    ) : (
      children
    );
    return (
      <MemoryRouter initialEntries={[route]}>
        <AuthProvider>{inner}</AuthProvider>
      </MemoryRouter>
    );
  }
  return render(ui, { wrapper: Wrapper });
}

export function resetClientState(): void {
  try {
    assertNoTokenStorage();
  } finally {
    clearMemoryCSRF();
    localStorage.clear();
    sessionStorage.clear();
  }
}
