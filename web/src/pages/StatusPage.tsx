import { useEffect, useState } from "react";
import { APIError, getState, getStatus } from "../api/client";
import type { StateView, Status } from "../api/types";

export function StatusPage() {
  const [status, setStatus] = useState<Status | null>(null);
  const [state, setState] = useState<StateView | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const [st, sv] = await Promise.all([getStatus(), getState()]);
        if (!cancelled) {
          setStatus(st);
          setState(sv);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof APIError ? err.message : "Could not load status.");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  if (error !== "") {
    return (
      <main className="page">
        <p className="banner-error" role="alert">
          {error}
        </p>
      </main>
    );
  }
  if (status === null || state === null) {
    return (
      <main className="page">
        <p role="status">Loading status…</p>
      </main>
    );
  }

  const agent = status.listeners?.find((l) => l.name === "agent" || l.name === "snmp");
  const traps = status.listeners?.find((l) => l.name === "traps" || l.name === "trap");

  return (
    <main className="page">
      <h1>Status</h1>
      <p className="banner-warn">LabSNMP is laboratory software. It is not a production SNMP agent.</p>
      <dl>
        <div>
          <dt>Ready</dt>
          <dd>
            <strong>{status.ready ? "yes" : "no"}</strong>
          </dd>
        </div>
        <div>
          <dt>Agent</dt>
          <dd>
            {agent ? <code>{agent.address}</code> : "—"}
          </dd>
        </div>
        <div>
          <dt>Traps</dt>
          <dd>
            {traps ? <code>{traps.address}</code> : "—"}
          </dd>
        </div>
        <div>
          <dt>Drifted</dt>
          <dd>
            <strong>{state.drifted ? "yes" : "no"}</strong>
          </dd>
        </div>
        <div>
          <dt>HostTime</dt>
          <dd>
            <code>{status.hostTime || "—"}</code>
          </dd>
        </div>
      </dl>
      <h2>Listeners</h2>
      <ul>
        {(status.listeners ?? []).map((l) => (
          <li key={l.name}>
            {l.name}: <code>{l.address}</code>
          </li>
        ))}
      </ul>
      <h2>Revisions</h2>
      <dl>
        <div>
          <dt>Bootstrap</dt>
          <dd>
            <code>{state.bootstrapRevision}</code>
          </dd>
        </div>
        <div>
          <dt>Runtime</dt>
          <dd>
            <code>{state.runtimeRevision}</code>
          </dd>
        </div>
        <div>
          <dt>Generation</dt>
          <dd>{state.generation}</dd>
        </div>
        <div>
          <dt>Store generation</dt>
          <dd>{state.storeGeneration ?? "—"}</dd>
        </div>
      </dl>
      <h2>Warnings</h2>
      {(status.warnings ?? []).length === 0 ? (
        <p className="muted">None.</p>
      ) : (
        <ul>
          {(status.warnings ?? []).map((w, i) => (
            <li key={`${w.Code ?? "w"}-${i}`}>
              <code>{w.Code || "warning"}</code> {w.Message || ""}
            </li>
          ))}
        </ul>
      )}
    </main>
  );
}
