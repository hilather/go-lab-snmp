import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { APIError, getTrap, getTrapRaw } from "../api/client";
import type { Trap } from "../api/types";

export function TrapDetailPage() {
  const { id = "" } = useParams();
  const [trap, setTrap] = useState<Trap | null>(null);
  const [raw, setRaw] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const rec = await getTrap(id);
        if (!cancelled) {
          setTrap(rec);
        }
        try {
          const buf = await getTrapRaw(id);
          if (!cancelled) {
            setRaw(hexDump(new Uint8Array(buf)));
          }
        } catch {
          if (!cancelled) {
            setRaw("");
          }
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof APIError ? err.message : "Could not load trap.");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [id]);

  if (trap === null && error === "") {
    return (
      <main className="page">
        <p role="status">Loading trap…</p>
      </main>
    );
  }

  return (
    <main className="page">
      <p className="muted">
        <Link to="/traps">Traps</Link>
      </p>
      <h1>Trap {id}</h1>
      {error !== "" ? (
        <p className="banner-error" role="alert">
          {error}
        </p>
      ) : null}
      {trap ? (
        <>
          <dl>
            <div>
              <dt>Received</dt>
              <dd>
                <code>{trap.receivedAt ?? "—"}</code>
              </dd>
            </div>
            <div>
              <dt>Version</dt>
              <dd>{trap.version || "—"}</dd>
            </div>
            <div>
              <dt>PDU</dt>
              <dd>{trap.pduType || "—"}</dd>
            </div>
            <div>
              <dt>Community</dt>
              <dd>{trap.community || "—"}</dd>
            </div>
            <div>
              <dt>User</dt>
              <dd>{trap.user || "—"}</dd>
            </div>
            <div>
              <dt>Remote</dt>
              <dd>
                <code>{trap.remoteAddr || "—"}</code>
              </dd>
            </div>
            <div>
              <dt>Notification</dt>
              <dd>
                <code>{trap.notificationOID || "—"}</code>
              </dd>
            </div>
          </dl>
          <h2>VarBinds</h2>
          <table className="data">
            <thead>
              <tr>
                <th>OID</th>
                <th>Type</th>
                <th>Value</th>
              </tr>
            </thead>
            <tbody>
              {(trap.varBinds ?? []).map((vb, i) => (
                <tr key={`${vb.oid}-${i}`}>
                  <td>
                    <code>{vb.oid}</code>
                  </td>
                  <td>{vb.type || "—"}</td>
                  <td>
                    <code>
                      {vb.oidValue ||
                        vb.bytes ||
                        (vb.integer !== undefined && vb.integer !== 0 ? String(vb.integer) : "") ||
                        (vb.unsigned !== undefined ? String(vb.unsigned) : "—")}
                    </code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <h2>Raw</h2>
          {raw !== "" ? <pre className="raw">{raw}</pre> : <p className="muted">Raw datagram not retained.</p>}
        </>
      ) : null}
    </main>
  );
}

function hexDump(bytes: Uint8Array): string {
  const lines: string[] = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const slice = bytes.slice(i, i + 16);
    const hex = Array.from(slice, (b) => b.toString(16).padStart(2, "0")).join(" ");
    lines.push(`${i.toString(16).padStart(4, "0")}  ${hex}`);
  }
  return lines.join("\n");
}
