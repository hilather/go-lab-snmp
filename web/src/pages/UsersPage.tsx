import { useEffect, useState } from "react";
import { APIError, listUsers } from "../api/client";
import type { UserSpec } from "../api/types";

export function UsersPage() {
  const [items, setItems] = useState<UserSpec[] | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const list = await listUsers();
        if (!cancelled) {
          setItems(list.items ?? []);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof APIError ? err.message : "Could not load users.");
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
        <p role="status">Loading users…</p>
      </main>
    );
  }

  return (
    <main className="page">
      <h1>Users</h1>
      <p>USM secret bytes never appear. <code>secretFile</code> paths may.</p>
      {error !== "" ? (
        <p className="banner-error" role="alert">
          {error}
        </p>
      ) : null}
      <table className="data">
        <thead>
          <tr>
            <th>Name</th>
            <th>Level</th>
            <th>Auth</th>
            <th>Priv</th>
            <th>Access</th>
            <th>Map</th>
          </tr>
        </thead>
        <tbody>
          {(items ?? []).map((u) => (
            <tr key={u.name}>
              <td>{u.name}</td>
              <td>
                <span className="chip">{u.level}</span>
              </td>
              <td>
                {u.auth ? (
                  <>
                    <span className="chip">{u.auth.protocol}</span> <code>{u.auth.secretFile}</code>
                  </>
                ) : (
                  "—"
                )}
              </td>
              <td>
                {u.priv ? (
                  <>
                    <span className="chip">{u.priv.protocol}</span> <code>{u.priv.secretFile}</code>
                  </>
                ) : (
                  "—"
                )}
              </td>
              <td>
                <span className="chip">{u.access}</span>
              </td>
              <td>{u.map}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </main>
  );
}
