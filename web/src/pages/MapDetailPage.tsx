import { FormEvent, useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { APIError, getMap, queryMap, setOID } from "../api/client";
import type { MapSpec, OIDResult } from "../api/types";
import { useAuth } from "../auth/AuthProvider";
import { SCOPE_WRITE } from "../auth/scopes";
import { leafTypeForOID, overlayJSONValue } from "../ui/overlay";

export function MapDetailPage() {
  const { name = "" } = useParams();
  const { hasScope } = useAuth();
  const canWrite = hasScope(SCOPE_WRITE);
  const [map, setMap] = useState<MapSpec | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [queryResult, setQueryResult] = useState<OIDResult[] | null>(null);
  const [live, setLive] = useState<Record<string, OIDResult>>({});

  const reload = useCallback(async () => {
    const spec = await getMap(name);
    setMap(spec);
    const oids = (spec.objects ?? []).map((o) => o.oid).filter(Boolean);
    if (oids.length === 0) {
      return;
    }
    try {
      const res = await queryMap(name, "get", oids);
      const next: Record<string, OIDResult> = {};
      for (const b of res.bindings ?? []) {
        if (b.oid) {
          next[b.oid] = b;
        }
      }
      setLive((prev) => ({ ...prev, ...next }));
    } catch {
      // GET /maps is bootstrap YAML; keep any overlay rows we already have.
    }
  }, [name]);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        await reload();
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof APIError ? err.message : "Could not load map.");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [reload]);

  async function onSet(ev: FormEvent<HTMLFormElement>) {
    ev.preventDefault();
    if (!canWrite) {
      return;
    }
    const fd = new FormData(ev.currentTarget);
    const oid = String(fd.get("oid") ?? "").trim();
    const raw = String(fd.get("value") ?? "").trim();
    if (oid === "") {
      setError("OID is required.");
      return;
    }
    const leafType = leafTypeForOID(map?.objects, oid);
    const value = overlayJSONValue(leafType, raw);
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const res = await setOID(name, oid, value);
      setLive((prev) => ({ ...prev, [res.oid]: res }));
      setNotice(`Overlay write ${res.oid}${res.overlay ? " (overlay)" : ""}.`);
      await reload();
    } catch (err) {
      setError(err instanceof APIError ? err.message : "oids:set failed.");
    } finally {
      setBusy(false);
    }
  }

  async function onQuery(ev: FormEvent<HTMLFormElement>) {
    ev.preventDefault();
    const fd = new FormData(ev.currentTarget);
    const pdu = String(fd.get("pdu") ?? "get");
    const oids = String(fd.get("oids") ?? "")
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    setBusy(true);
    setError("");
    try {
      const res = await queryMap(name, pdu, oids);
      setQueryResult(res.bindings ?? []);
    } catch (err) {
      setError(err instanceof APIError ? err.message : "Map query failed.");
    } finally {
      setBusy(false);
    }
  }

  if (map === null && error === "") {
    return (
      <main className="page">
        <p role="status">Loading map…</p>
      </main>
    );
  }

  return (
    <main className="page">
      <p className="muted">
        <Link to="/maps">Maps</Link>
      </p>
      <h1>{name}</h1>
      <p>Leaf overlay edit uses <code>oids:set</code>. SET is overlay, not apply. There is no send-trap control.</p>
      {error !== "" ? (
        <p className="banner-error" role="alert">
          {error}
        </p>
      ) : null}
      {notice !== "" ? <p role="status">{notice}</p> : null}
      <table className="data">
        <caption>Compiled instance leaves. Value prefers live GET (overlay flag) over bootstrap YAML.</caption>
        <thead>
          <tr>
            <th>OID</th>
            <th>Name</th>
            <th>Type</th>
            <th>Access</th>
            <th>Value</th>
          </tr>
        </thead>
        <tbody>
          {(map?.objects ?? []).map((o) => (
            <tr key={o.oid}>
              <td>
                <code>{o.oid}</code>
              </td>
              <td>{o.name || "—"}</td>
              <td>
                <span className="chip">{o.type}</span>
              </td>
              <td>
                <span className="chip">{o.access}</span>
              </td>
              <td>
                <code>{formatLeaf(o, live[o.oid])}</code>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <h2>Overlay write</h2>
      {!canWrite ? <p>Requires scope snmp.write.</p> : null}
      <form className="row" onSubmit={(e) => void onSet(e)}>
        <div className="field">
          <label htmlFor="set-oid">OID</label>
          <input id="set-oid" name="oid" autoComplete="off" spellCheck={false} required />
        </div>
        <div className="field">
          <label htmlFor="set-value">Value</label>
          <input id="set-value" name="value" autoComplete="off" spellCheck={false} />
        </div>
        <button type="submit" disabled={!canWrite || busy}>
          {busy ? "Writing…" : "Set overlay"}
        </button>
      </form>
      <h2>Simulate GET</h2>
      <p className="muted">Does not send a datagram.</p>
      <form className="row" onSubmit={(e) => void onQuery(e)}>
        <div className="field">
          <label htmlFor="query-pdu">PDU</label>
          <select id="query-pdu" name="pdu" defaultValue="get">
            <option value="get">get</option>
            <option value="getNext">getNext</option>
            <option value="getBulk">getBulk</option>
          </select>
        </div>
        <div className="field">
          <label htmlFor="query-oids">OIDs</label>
          <input id="query-oids" name="oids" autoComplete="off" spellCheck={false} />
        </div>
        <button type="submit" disabled={busy}>
          Query
        </button>
      </form>
      {queryResult ? (
        <table className="data">
          <thead>
            <tr>
              <th>OID</th>
              <th>Type</th>
              <th>Value</th>
              <th>Exception</th>
              <th>Overlay</th>
            </tr>
          </thead>
          <tbody>
            {queryResult.map((b, i) => (
              <tr key={`${b.oid}-${i}`}>
                <td>
                  <code>{b.oid}</code>
                </td>
                <td>{b.type || "—"}</td>
                <td>
                  <code>{formatValue(b.value)}</code>
                </td>
                <td>{b.exception || "—"}</td>
                <td>{b.overlay ? "yes" : "no"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
    </main>
  );
}

function formatValue(v: unknown): string {
  if (v === undefined || v === null) {
    return "—";
  }
  if (typeof v === "string") {
    return v;
  }
  return JSON.stringify(v);
}

function formatLeaf(o: { value?: unknown; valueFrom?: string }, got: OIDResult | undefined): string {
  if (got) {
    const mark = got.overlay ? " (overlay)" : "";
    return `${formatValue(got.value)}${mark}`;
  }
  if (o.valueFrom) {
    return `valueFrom:${o.valueFrom}`;
  }
  return formatValue(o.value);
}
