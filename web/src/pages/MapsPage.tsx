import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { APIError, listMaps } from "../api/client";
import type { MapSpec } from "../api/types";
import { EmptyState } from "../ui/empty";

export function MapsPage() {
  const [items, setItems] = useState<MapSpec[] | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const list = await listMaps();
        if (!cancelled) {
          setItems(list.items ?? []);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof APIError ? err.message : "Could not load maps.");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  if (items === null && error === "") {
    return (
      <main className="page">
        <p role="status">Loading maps…</p>
      </main>
    );
  }

  return (
    <main className="page">
      <h1>Maps</h1>
      <p>Named OID maps. Identity is community or v3 user, not client IP.</p>
      {error !== "" ? (
        <p className="banner-error" role="alert">
          {error}
        </p>
      ) : null}
      {(items ?? []).length === 0 ? (
        <EmptyState>No maps in the live snapshot.</EmptyState>
      ) : (
        <table className="data">
          <caption>OID maps in the live snapshot.</caption>
          <thead>
            <tr>
              <th>Name</th>
              <th>Objects</th>
            </tr>
          </thead>
          <tbody>
            {(items ?? []).map((m) => (
              <tr key={m.name}>
                <td>
                  <Link to={`/maps/${encodeURIComponent(m.name)}`}>{m.name}</Link>
                </td>
                <td>{(m.objects ?? []).length}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </main>
  );
}
