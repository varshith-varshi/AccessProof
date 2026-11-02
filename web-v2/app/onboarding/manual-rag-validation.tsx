"use client";

import { useEffect, useState } from "react";

type Observation = "not-tested" | "expected" | "unexpected";
type Item = { id: string; label: string; procedure: string; expected: string };
const CASES: Item[] = [
  { id: "alice-allow", label: "Alice: authorized access",
    procedure: "Sign in to your existing RAG as Alice. Ask about a synthetic document Alice can access.",
    expected: "The document can be used to answer Alice." },
  { id: "bob-deny", label: "Bob: unauthorized access",
    procedure: "Sign out and sign in as Bob. Ask for Alice's private synthetic document.",
    expected: "The document and its contents are not disclosed." },
  { id: "bob-allow", label: "Bob: authorized access",
    procedure: "Ask as Bob about a synthetic document that Bob is allowed to read.",
    expected: "Bob receives a relevant authorized answer." },
  { id: "revoke-deny", label: "Revocation: access removed",
    procedure: "In SharePoint, revoke the test user's access to the synthetic file. After synchronization, retry from the same employee account.",
    expected: "The content remains unavailable after revocation." },
  { id: "cache-deny", label: "Cache: no stale answer",
    procedure: "Repeat the previously authorized question after revocation, including its cached wording.",
    expected: "No stale cached answer reveals revoked content." },
  { id: "restore-allow", label: "Restore: access returns",
    procedure: "Restore the synthetic test permission in SharePoint. After synchronization, repeat the approved request.",
    expected: "Access works again only for the authorized employee." },
];

function emptyResults(): Record<string, Observation> {
  return Object.fromEntries(CASES.map(item => [item.id, "not-tested" as Observation]));
}

export function ManualRagValidation({ applicationId, guardReady }: { applicationId: string; guardReady: boolean }) {
  const [results, setResults] = useState<Record<string, Observation>>(emptyResults);
  const [loaded, setLoaded] = useState(false);
  const key = "accessproof:local-manual-rag-test:v1:" + applicationId;

  useEffect(() => {
    try {
      const saved = JSON.parse(sessionStorage.getItem(key) || "{}") as Record<string, unknown>;
      const safe = emptyResults();
      for (const item of CASES) {
        if (saved[item.id] === "expected" || saved[item.id] === "unexpected") {
          safe[item.id] = saved[item.id] as Observation;
        }
      }
      queueMicrotask(() => { setResults(safe); setLoaded(true); });
    } catch {
      queueMicrotask(() => { setResults(emptyResults()); setLoaded(true); });
    }
  }, [key]);

  const record = (id: string, value: Observation) => {
    const updated = { ...results, [id]: value };
    setResults(updated);
    try { sessionStorage.setItem(key, JSON.stringify(updated)); } catch { /* private browsing is supported */ }
  };
  const reset = () => {
    setResults(emptyResults());
    try { sessionStorage.removeItem(key); } catch { /* private browsing */ }
  };
  const tested = CASES.filter(item => results[item.id] !== "not-tested").length;
  const unexpected = CASES.filter(item => results[item.id] === "unexpected").length;

  return <section id="manual-rag-tests" className="onboard-manual-test" aria-label="Manual RAG validation">
    <div className="onboard-manual-header">
      <div>
        <b>Manual RAG validation — ready to test</b>
        <p>Use your existing chatbot and synthetic SharePoint documents. No automatic certification checklist must pass before you begin.</p>
      </div>
      <span>{loaded ? tested : "…"} / {CASES.length} observed</span>
    </div>
    {!guardReady && <p className="onboard-manual-warning" role="status">
      Guard is not security-ready. You may still investigate the RAG, but expected answers alone cannot demonstrate enforcement.
    </p>}
    <p className="onboard-manual-warning">
      This is a local observation worksheet, <strong>not a Protect activation or security certificate.</strong> Do not use confidential production data.
      Only use approved synthetic test files. Restore any permissions changed during testing.
    </p>
    <div className="onboard-manual-cases">
      {CASES.map((item, index) => <article key={item.id} className="onboard-manual-case">
        <b>{index + 1}. {item.label}</b>
        <p>{item.procedure}</p>
        <small><strong>Expected:</strong> {item.expected}</small>
        <label>What did you observe?
          <select aria-label={"Result: " + item.label} value={results[item.id] ?? "not-tested"}
            onChange={event => record(item.id, event.target.value as Observation)}>
            <option value="not-tested">Not tested yet</option>
            <option value="expected">Observed expected behavior</option>
            <option value="unexpected">Observed unexpected behavior</option>
          </select>
        </label>
      </article>)}
    </div>
    {tested > 0 && <p role="status" className={unexpected ? "onboard-manual-warning" : "onboard-manual-note"}>
      {tested} manually observed · {unexpected} unexpected.
      {unexpected > 0 ? " Investigate the results and Guard audit before further testing." : " Match observations to real Guard audit events before relying on them."}
    </p>}
    <button className="button secondary" type="button" onClick={reset}>Reset local test notes</button>
    <small>Notes are stored only in this browser tab and are never submitted as Guard evidence or sent to AccessProof.</small>
  </section>;
}
