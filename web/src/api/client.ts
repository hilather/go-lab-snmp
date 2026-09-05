import { assertNoTokenStorage } from "./storage";
import type {
  AuditList,
  ChangeIn,
  CommunityList,
  FeatureList,
  MapList,
  MapSpec,
  OIDResult,
  Plan,
  Problem,
  QueryList,
  SessionCreated,
  SessionView,
  StateView,
  Stats,
  Status,
  Trap,
  TrapList,
  UserList,
} from "./types";

export const CSRF_HEADER = "X-LabSNMP-CSRF";
export const AUDIT_LIMIT = 128;

export class APIError extends Error {
  readonly problem: Problem;

  constructor(problem: Problem) {
    super(problem.detail || problem.title || "request failed");
    this.name = "APIError";
    this.problem = problem;
  }
}

let memoryCSRF = "";

export function setMemoryCSRF(value: string): void {
  memoryCSRF = value;
}

export function getMemoryCSRF(): string {
  return memoryCSRF;
}

export function clearMemoryCSRF(): void {
  memoryCSRF = "";
}

function problemFrom(status: number, statusText: string, body: unknown): Problem {
  const fallback: Problem = {
    type: "urn:labsnmp:error:internal-error",
    title: statusText || "error",
    status,
    detail: statusText || "request failed",
    code: status === 401 ? "unauthenticated" : status === 403 ? "forbidden" : "internal_error",
  };
  if (!body || typeof body !== "object") {
    return fallback;
  }
  const rec = body as Record<string, unknown>;
  return {
    type: typeof rec.type === "string" ? rec.type : fallback.type,
    title: typeof rec.title === "string" ? rec.title : fallback.title,
    status: typeof rec.status === "number" ? rec.status : fallback.status,
    detail: typeof rec.detail === "string" ? rec.detail : fallback.detail,
    code: typeof rec.code === "string" ? rec.code : fallback.code,
  };
}

export async function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  assertNoTokenStorage();
  const headers = new Headers(init.headers);
  const method = (init.method ?? "GET").toUpperCase();
  if (method !== "GET" && method !== "HEAD" && !headers.has(CSRF_HEADER)) {
    const csrf = getMemoryCSRF();
    if (csrf !== "") {
      headers.set(CSRF_HEADER, csrf);
    }
  }
  if (!headers.has("Accept")) {
    headers.set("Accept", "application/json");
  }
  return fetch(path, {
    ...init,
    credentials: "same-origin",
    headers,
  });
}

async function readJSON<T>(resp: Response): Promise<T> {
  const text = await resp.text();
  let parsed: unknown;
  if (text !== "") {
    try {
      parsed = JSON.parse(text) as unknown;
    } catch {
      parsed = undefined;
    }
  }
  if (!resp.ok) {
    throw new APIError(problemFrom(resp.status, resp.statusText, parsed));
  }
  return parsed as T;
}

export async function createSession(authorization: string): Promise<SessionCreated> {
  const resp = await apiFetch("/v1/session", {
    method: "POST",
    headers: { Authorization: authorization },
  });
  const created = await readJSON<SessionCreated>(resp);
  setMemoryCSRF(created.csrf);
  assertNoTokenStorage();
  return created;
}

export function bearerAuthorization(token: string): string {
  return `Bearer ${token}`;
}

export async function getSession(): Promise<SessionView> {
  const view = await readJSON<SessionView>(await apiFetch("/v1/session"));
  if (typeof view.csrf === "string" && view.csrf !== "") {
    setMemoryCSRF(view.csrf);
  }
  return view;
}

export async function deleteSession(): Promise<void> {
  const resp = await apiFetch("/v1/session", { method: "DELETE" });
  if (resp.status === 401 || resp.status === 204) {
    clearMemoryCSRF();
    return;
  }
  await readJSON<unknown>(resp);
  clearMemoryCSRF();
}

export async function getState(): Promise<StateView> {
  return readJSON<StateView>(await apiFetch("/v1/state"));
}

export async function getStatus(): Promise<Status> {
  return readJSON<Status>(await apiFetch("/v1/status"));
}

export async function getStats(): Promise<Stats> {
  return readJSON<Stats>(await apiFetch("/v1/stats"));
}

export async function listMaps(): Promise<MapList> {
  return readJSON<MapList>(await apiFetch("/v1/maps"));
}

export async function getMap(name: string): Promise<MapSpec> {
  return readJSON<MapSpec>(await apiFetch(`/v1/maps/${encodeURIComponent(name)}`));
}

export async function setOID(map: string, oid: string, value: unknown): Promise<OIDResult> {
  return readJSON<OIDResult>(
    await apiFetch(`/v1/maps/${encodeURIComponent(map)}/oids:set`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ oid, value }),
    }),
  );
}

export async function queryMap(name: string, pdu: string, oids: string[]): Promise<{ bindings: OIDResult[] }> {
  return readJSON<{ bindings: OIDResult[] }>(
    await apiFetch(`/v1/maps/${encodeURIComponent(name)}:query`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pdu, oids }),
    }),
  );
}

export async function listCommunities(): Promise<CommunityList> {
  return readJSON<CommunityList>(await apiFetch("/v1/communities"));
}

export async function listUsers(): Promise<UserList> {
  return readJSON<UserList>(await apiFetch("/v1/users"));
}

export async function listTraps(): Promise<TrapList> {
  return readJSON<TrapList>(await apiFetch("/v1/traps"));
}

export async function getTrap(id: string): Promise<Trap> {
  return readJSON<Trap>(await apiFetch(`/v1/traps/${encodeURIComponent(id)}`));
}

export async function getTrapRaw(id: string): Promise<ArrayBuffer> {
  const resp = await apiFetch(`/v1/traps/${encodeURIComponent(id)}/raw`, {
    headers: { Accept: "application/octet-stream" },
  });
  if (!resp.ok) {
    const text = await resp.text();
    let parsed: unknown;
    try {
      parsed = JSON.parse(text) as unknown;
    } catch {
      parsed = undefined;
    }
    throw new APIError(problemFrom(resp.status, resp.statusText, parsed));
  }
  return resp.arrayBuffer();
}

export async function clearTraps(): Promise<void> {
  const resp = await apiFetch("/v1/traps:clear", { method: "POST" });
  if (resp.status === 204) {
    return;
  }
  await readJSON<unknown>(resp);
}

export async function listQueries(): Promise<QueryList> {
  return readJSON<QueryList>(await apiFetch("/v1/queries"));
}

export async function listFeatures(): Promise<FeatureList> {
  return readJSON<FeatureList>(await apiFetch("/v1/features"));
}

export async function listAudit(limit = AUDIT_LIMIT): Promise<AuditList> {
  const params = new URLSearchParams();
  params.set("limit", String(limit));
  return readJSON<AuditList>(await apiFetch(`/v1/audit?${params.toString()}`));
}

export async function planChanges(body: ChangeIn): Promise<Plan> {
  return readJSON<Plan>(
    await apiFetch("/v1/changes:plan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  );
}

export async function applyChanges(body: ChangeIn): Promise<Plan> {
  return readJSON<Plan>(
    await apiFetch("/v1/changes:apply", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  );
}

export async function resetState(reason: string): Promise<unknown> {
  return readJSON<unknown>(
    await apiFetch("/v1/state:reset", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason }),
    }),
  );
}
