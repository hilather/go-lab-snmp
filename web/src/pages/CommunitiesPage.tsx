import { useEffect, useState } from "react";
import { APIError, listCommunities } from "../api/client";
import type { CommunitySpec } from "../api/types";

export function CommunitiesPage() {
  const [items, setItems] = useState<CommunitySpec[] | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const list = await listCommunities();
        if (!cancelled) {
          setItems(list.items ?? []);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof APIError ? err.message : "Could not load communities.");
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
        <p role="status">Loading communities…</p>
      </main>
    );
  }

  return (
    <main className="page">
      <h1>Communities</h1>
      <p>Wire strings and file contents are never shown. <code>communityFile</code> paths may appear.</p>
      {error !== "" ? (
        <p className="banner-error" role="alert">
          {error}
        </p>
      ) : null}
      <table className="data">
        <thead>
          <tr>
            <th>Name</th>
            <th>communityFile</th>
            <th>Versions</th>
            <th>Access</th>
            <th>Map</th>
          </tr>
        </thead>
        <tbody>
          {(items ?? []).map((c) => (
            <tr key={c.name}>
              <td>{c.name}</td>
              <td>
                <code>{c.communityFile}</code>
              </td>
              <td>{(c.versions ?? []).join(", ") || "—"}</td>
              <td>
                <span className="chip">{c.access}</span>
              </td>
              <td>{c.map}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </main>
  );
}
