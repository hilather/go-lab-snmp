import { useState } from "react";
import { APIError, applyChanges, getState, planChanges } from "../api/client";
import type { Operation, Plan } from "../api/types";
import { useAuth } from "../auth/AuthProvider";
import { SCOPE_ADMIN } from "../auth/scopes";

const EXAMPLE = `{
  "operations": [
    {
      "op": "replaceAdmission",
      "admission": {
        "allowClientCidrs": ["127.0.0.0/8", "::1/128"],
        "maxDatagramsPerSec": 10000,
        "maxDatagramsPerIP": 500
      }
    }
  ]
}`;

export function PlanPage() {
  const { hasScope } = useAuth();
  const allowed = hasScope(SCOPE_ADMIN);
  const [raw, setRaw] = useState(EXAMPLE);
  const [reason, setReason] = useState("");
  const [result, setResult] = useState<Plan | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function run(kind: "plan" | "apply") {
    if (!allowed) {
      return;
    }
    setBusy(true);
    setError("");
    setResult(null);
    try {
      const parsed = JSON.parse(raw) as { operations?: Operation[] };
      const operations = parsed.operations;
      if (!Array.isArray(operations) || operations.length === 0) {
        setError("Body must include a non-empty operations array.");
        return;
      }
      const state = await getState();
      const body = {
        expectedRevision: state.runtimeRevision,
        reason: reason.trim(),
        operations,
      };
      const out = kind === "plan" ? await planChanges(body) : await applyChanges(body);
      setResult(out);
    } catch (err) {
      if (err instanceof SyntaxError) {
        setError("Operations JSON is invalid.");
      } else {
        setError(err instanceof APIError ? err.message : "Plan/apply failed.");
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="page">
      <h1>Plan / apply</h1>
      <p>
        Closed apply ops from docs/04. <code>expectedRevision</code> is taken from{" "}
        <code>GET /v1/state</code> <code>runtimeRevision</code>. UI enablement is bootstrap YAML, not an apply
        op.
      </p>
      {!allowed ? <p>Requires scope snmp.admin.</p> : null}
      {error !== "" ? (
        <p className="banner-error" role="alert">
          {error}
        </p>
      ) : null}
      <form className="stack">
        <div className="field">
          <label htmlFor="plan-ops">Operations JSON</label>
          <textarea id="plan-ops" rows={14} value={raw} onChange={(e) => setRaw(e.target.value)} spellCheck={false} />
        </div>
        <div className="field">
          <label htmlFor="plan-reason">Reason (optional)</label>
          <input id="plan-reason" value={reason} onChange={(e) => setReason(e.target.value)} />
        </div>
        <div className="row">
          <button type="button" disabled={!allowed || busy} onClick={() => void run("plan")}>
            {busy ? "Working…" : "Plan"}
          </button>
          <button type="button" disabled={!allowed || busy} onClick={() => void run("apply")}>
            Apply
          </button>
        </div>
      </form>
      {result ? (
        <section>
          <h2>Result</h2>
          <dl>
            <div>
              <dt>Applied</dt>
              <dd>{result.applied ? "yes" : "no"}</dd>
            </div>
            <div>
              <dt>Previous</dt>
              <dd>
                <code>{result.previousRevision || "—"}</code>
              </dd>
            </div>
            <div>
              <dt>Candidate</dt>
              <dd>
                <code>{result.candidateRevision || "—"}</code>
              </dd>
            </div>
            <div>
              <dt>Runtime</dt>
              <dd>
                <code>{result.runtimeRevision || "—"}</code>
              </dd>
            </div>
          </dl>
          <h3>Diff</h3>
          {(result.diff ?? []).length === 0 ? (
            <p className="muted">Empty.</p>
          ) : (
            <table className="data">
              <thead>
                <tr>
                  <th>Path</th>
                  <th>Op</th>
                </tr>
              </thead>
              <tbody>
                {(result.diff ?? []).map((d, i) => (
                  <tr key={`${d.path}-${i}`}>
                    <td>
                      <code>{d.path}</code>
                    </td>
                    <td>{d.op}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      ) : null}
    </main>
  );
}
