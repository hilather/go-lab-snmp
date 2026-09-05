import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { APIError, clearTraps, listTraps } from "../api/client";
import type { Trap } from "../api/types";
import { useAuth } from "../auth/AuthProvider";
import { SCOPE_WRITE } from "../auth/scopes";
import { EmptyState } from "../ui/empty";

export function TrapsPage() {
  const { hasScope } = useAuth();
  const canWrite = hasScope(SCOPE_WRITE);
  const [items, setItems] = useState<Trap[] | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const reload = useCallback(async () => {
    const list = await listTraps();
    setItems(list.items ?? []);
  }, []);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        await reload();
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof APIError ? err.message : "Could not load traps.");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [reload]);

  async function onClear() {
    if (!canWrite) {
      return;
    }
    setBusy(true);
    setError("");
    try {
      await clearTraps();
      await reload();
    } catch (err) {
      setError(err instanceof APIError ? err.message : "Could not clear traps.");
    } finally {
      setBusy(false);
    }
  }

  if (items === null && error === "") {
    return (
      <main className="page">
        <p role="status">Loading traps…</p>
      </main>
    );
  }

  return (
    <main className="page">
      <h1>Traps</h1>
      <p>
        Receive-only inbox. LabSNMP never originates or forwards traps. There is no send-trap control.
      </p>
      {error !== "" ? (
        <p className="banner-error" role="alert">
          {error}
        </p>
      ) : null}
      <p>
        <button type="button" onClick={() => void onClear()} disabled={!canWrite || busy}>
          {busy ? "Clearing…" : "Clear inbox"}
        </button>
      </p>
      {(items ?? []).length === 0 ? (
        <EmptyState>Trap inbox is empty. Receive-only; LabSNMP never originates or forwards traps.</EmptyState>
      ) : (
        <table className="data">
          <caption>Receive-only trap inbox.</caption>
          <thead>
            <tr>
              <th>ID</th>
              <th>Received</th>
              <th>Version</th>
              <th>PDU</th>
              <th>Identity</th>
              <th>Notification</th>
            </tr>
          </thead>
          <tbody>
            {(items ?? []).map((t) => (
              <tr key={t.id}>
                <td>
                  <Link to={`/traps/${encodeURIComponent(t.id)}`}>
                    <code>{t.id}</code>
                  </Link>
                </td>
                <td>
                  <code>{t.receivedAt ?? "—"}</code>
                </td>
                <td>{t.version || "—"}</td>
                <td>{t.pduType || "—"}</td>
                <td>{t.community || t.user || "—"}</td>
                <td>
                  <code>{t.notificationOID || "—"}</code>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </main>
  );
}
