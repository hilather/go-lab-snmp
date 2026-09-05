import { useEffect, useState } from "react";
import { APIError, getState, getStats, getStatus } from "../api/client";
import type { StateView, Stats, Status } from "../api/types";
import { EmptyState } from "../ui/empty";

export function OverviewPage() {
  const [status, setStatus] = useState<Status | null>(null);
  const [state, setState] = useState<StateView | null>(null);
  const [stats, setStats] = useState<Stats | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const [st, sv, ss] = await Promise.all([getStatus(), getState(), getStats()]);
        if (!cancelled) {
          setStatus(st);
          setState(sv);
          setStats(ss);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof APIError ? err.message : "Could not load overview.");
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
  if (status === null || state === null || stats === null) {
    return (
      <main className="page">
        <p role="status">Loading overview…</p>
      </main>
    );
  }

  const tcp = status.listeners?.find((l) => l.name === "agent-tcp");
  const dtls = status.listeners?.find((l) => l.name === "agent-dtls");

  return (
    <main className="page">
      <h1>Overview</h1>
      <p className="banner-warn">LabSNMP is laboratory software. It is not a production SNMP agent.</p>
      <dl>
        <div>
          <dt>Ready</dt>
          <dd>
            <strong>{status.ready ? "yes" : "no"}</strong>
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
        {tcp ? (
          <div>
            <dt>Agent TCP</dt>
            <dd>
              <code>{tcp.address}</code>
            </dd>
          </div>
        ) : null}
        {dtls ? (
          <div>
            <dt>Agent DTLS</dt>
            <dd>
              <code>{dtls.address}</code>
            </dd>
          </div>
        ) : null}
      </dl>
      <h2>Listeners</h2>
      {(status.listeners ?? []).length === 0 ? (
        <EmptyState>No listeners reported.</EmptyState>
      ) : (
        <ul>
          {(status.listeners ?? []).map((l) => (
            <li key={l.name}>
              {l.name}: <code>{l.address}</code>
            </li>
          ))}
        </ul>
      )}
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
      </dl>
      <h2>Store</h2>
      <dl>
        <div>
          <dt>Trap messages</dt>
          <dd>{stats.traps?.messages ?? 0}</dd>
        </div>
        <div>
          <dt>Trap bytes</dt>
          <dd>{stats.traps?.bytes ?? 0}</dd>
        </div>
        <div>
          <dt>Overlay generation</dt>
          <dd>{stats.overlayGeneration}</dd>
        </div>
        <div>
          <dt>Queries</dt>
          <dd>{stats.queries}</dd>
        </div>
      </dl>
    </main>
  );
}
