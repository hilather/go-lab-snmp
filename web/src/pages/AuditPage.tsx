import { useEffect, useState } from "react";
import { APIError, listAudit } from "../api/client";
import type { AuditEvent } from "../api/types";
import { useAuth } from "../auth/AuthProvider";
import { SCOPE_AUDIT } from "../auth/scopes";
import { EmptyState } from "../ui/empty";

export function AuditPage() {
  const { hasScope } = useAuth();
  const allowed = hasScope(SCOPE_AUDIT);
  const [items, setItems] = useState<AuditEvent[] | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!allowed) {
      setItems([]);
      return;
    }
    let cancelled = false;
    void (async () => {
      try {
        const list = await listAudit();
        if (!cancelled) {
          setItems(list.events ?? []);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof APIError ? err.message : "Could not load audit.");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [allowed]);

  if (!allowed) {
    return (
      <main className="page">
        <h1>Audit</h1>
        <p>Requires scope snmp.audit.read.</p>
      </main>
    );
  }

  if (items === null && error === "") {
    return (
      <main className="page">
        <p role="status">Loading audit…</p>
      </main>
    );
  }

  return (
    <main className="page">
      <h1>Audit</h1>
      <p className="muted">In-memory ring. Secret bytes are redacted.</p>
      {error !== "" ? (
        <p className="banner-error" role="alert">
          {error}
        </p>
      ) : null}
      {(items ?? []).length === 0 ? (
        <EmptyState>No audit events in the in-memory ring.</EmptyState>
      ) : (
        <table className="data">
          <caption>In-memory audit ring.</caption>
          <thead>
            <tr>
              <th>Time</th>
              <th>Actor</th>
              <th>Capability</th>
              <th>Result</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody>
            {(items ?? []).map((e) => (
              <tr key={e.id}>
                <td>
                  <code>{e.time ?? "—"}</code>
                </td>
                <td>{e.actorId || "—"}</td>
                <td>
                  <code>{e.capability || "—"}</code>
                </td>
                <td>
                  <span className="chip">{e.result || "—"}</span>
                </td>
                <td>{e.reason || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </main>
  );
}
