import { useEffect, useState } from "react";
import { APIError, listQueries } from "../api/client";
import type { QueryEntry } from "../api/types";

const POLL_MS = 5000;

export function QueriesPage() {
  const [items, setItems] = useState<QueryEntry[] | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const list = await listQueries();
        if (!cancelled) {
          setItems(list.items ?? []);
          setError("");
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof APIError ? err.message : "Could not load queries.");
        }
      }
    }
    void load();
    const id = window.setInterval(() => {
      void load();
    }, POLL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, []);

  if (items === null && error === "") {
    return (
      <main className="page">
        <p role="status">Loading queries…</p>
      </main>
    );
  }

  return (
    <main className="page">
      <h1>Queries</h1>
      <p className="muted">Last-N PDU ring. Identity is the community or user row name, never a wire secret.</p>
      {error !== "" ? (
        <p className="banner-error" role="alert">
          {error}
        </p>
      ) : null}
      <table className="data">
        <thead>
          <tr>
            <th>Type</th>
            <th>Identity</th>
            <th>Decision</th>
            <th>Error status</th>
          </tr>
        </thead>
        <tbody>
          {(items ?? []).map((q, i) => (
            <tr key={`${q.type}-${q.identity}-${i}`}>
              <td>
                <span className="chip">{q.type}</span>
              </td>
              <td>{q.identity || "—"}</td>
              <td>{q.decision || "—"}</td>
              <td>{q.errorStatus}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </main>
  );
}
