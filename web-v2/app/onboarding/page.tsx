"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import { api, type AIApplication, type Guard, type ProtectionOverview, type Source } from "../../lib/api";
import { PageHeader } from "../app-shell";
import { ProtectedPage } from "../protected-page";
import "./onboarding.css";
import { GatewayDiscoveryPicker } from "./gateway-discovery-picker";
import { ManualRagValidation } from "./manual-rag-validation";

type Pairing = {
  state: string; expires_at?: string | null;
  deployment_sha256?: string | null; route_sha256?: string | null;
};
type Verification = {
  run_id: string | null; state: string;
  deployment_sha256?: string; route_sha256?: string;
  guard?: { connectivity: string; security_readiness: string; heartbeat_age_seconds: number | null };
};
type Data = { sources: Source[]; guards: Guard[]; apps: AIApplication[]; protection: ProtectionOverview | null; errors: string[] };
const EMPTY: Data = { sources: [], guards: [], apps: [], protection: null, errors: [] };
const installCommand = "python3 ~/Downloads/accessproof-gateway-connector.zip";
const microsoft = (source: Source) => ["sharepoint", "microsoft365", "onedrive"].includes(source.provider);

function downloadJson(filename: string, value: object) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2) + "\n"], { type: "application/json" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 2000);
}

function Pill({ ok, label }: { ok: boolean; label: string }) {
  return <span className={"onboard-pill " + (ok ? "success" : "pending")}>{ok ? "✓ " : "• "}{label}</span>;
}

type DecisionCounts = { l1Allow: number; l1Block: number; l2Allow: number; l2Block: number };
function observedCounts(overview: ProtectionOverview["applications"][number] | undefined): DecisionCounts | null {
  const telemetry = overview?.decision_telemetry;
  if (!telemetry || telemetry.telemetry !== "OBSERVED") return null;
  return {
    l1Allow: telemetry.layer1?.allow ?? 0, l1Block: telemetry.layer1?.block ?? 0,
    l2Allow: telemetry.layer2?.allow ?? 0, l2Block: telemetry.layer2?.block ?? 0,
  };
}

export default function Onboarding() {
  const [data, setData] = useState<Data>(EMPTY);
  const [selectedId, setSelectedId] = useState("");
  const [pairing, setPairing] = useState<Pairing | null>(null);
  const [verification, setVerification] = useState<Verification | null>(null);
  const [presence, setPresence] = useState<{ connectivity: string; security_readiness: string } | null>(null);
  const [observing, setObserving] = useState(false);
  const [baseline, setBaseline] = useState<DecisionCounts | null>(null);
  const [busy, setBusy] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState("");
  const [checkedAt, setCheckedAt] = useState("");

  const refresh = useCallback(async () => {
    const rows = await Promise.allSettled([
      api<Source[]>("/api/v1/current/sources"),
      api<Guard[]>("/api/v1/guards"),
      api<AIApplication[]>("/api/v1/current/ai-applications"),
      api<ProtectionOverview>("/api/v1/current/protection/overview"),
    ]);
    setData({
      sources: rows[0].status === "fulfilled" ? rows[0].value : [],
      guards: rows[1].status === "fulfilled" ? rows[1].value : [],
      apps: rows[2].status === "fulfilled" ? rows[2].value : [],
      protection: rows[3].status === "fulfilled" ? rows[3].value : null,
      errors: rows.flatMap((row, i) => row.status === "rejected"
        ? [(["Sources", "Guards", "Applications", "Protection status"][i]) + " unavailable"]
        : []),
    });
    setLoaded(true);
    setCheckedAt(new Date().toLocaleTimeString());
  }, []);

  useEffect(() => {
    queueMicrotask(() => {
      setSelectedId(new URLSearchParams(location.search).get("application") ?? "");
      void refresh();
    });
    const timer = setInterval(() => void refresh(), 30_000);
    return () => clearInterval(timer);
  }, [refresh]);

  const app = useMemo(
    () => data.apps.find(row => row.application_id === selectedId) ??
      data.apps.find(row => row.adapter_type === "accessproof-gateway" &&
        data.sources.some(s => microsoft(s) && (row.source_id === s.id || row.source_ids?.includes(s.id)))) ??
      data.apps.find(row => row.adapter_type === "accessproof-gateway") ?? null,
    [data.apps, data.sources, selectedId],
  );
  const source = data.sources.find(s => microsoft(s) && (app?.source_id === s.id || app?.source_ids?.includes(s.id))) ??
    data.sources.find(microsoft);
  const guard = data.guards.find(row => row.id === app?.guard_id);
  const bound = !!app && !!source && !!guard && app.adapter_type === "accessproof-gateway" &&
    (app.source_id === source.id || !!app.source_ids?.includes(source.id));
  const id = app ? encodeURIComponent(app.application_id) : null;
  const readiness = data.protection?.applications.find(row => row.application_id === app?.application_id);
  const sourceReady = !!source && source.status === "connected" &&
    source.acl_sync?.fresh === true && source.directory_sync?.fresh === true;
  const reported = !!bound && (pairing?.state === "installation_reported_unverified" || !!verification?.run_id);
  const protectedVerified = readiness?.effective_state === "PROTECTED_VERIFIED";
  const connected = (presence?.connectivity ?? verification?.guard?.connectivity) === "CONNECTED";
  const guardReadiness = presence?.security_readiness ?? verification?.guard?.security_readiness ?? "UNKNOWN";
  const count = Number(sourceReady) + Number(reported) + Number(protectedVerified);
  const counts = observedCounts(readiness);
  // These 24-hour aggregate Guard counters can reflect other employees.
  // Their deltas provide live diagnostic feedback, NEVER certification proof.
  // Without an initial Guard sample, do not mistake existing 24-hour traffic for fresh tests.
  useEffect(() => {
    if (!observing || baseline !== null || counts === null) return;
    // Sample the first nonempty backend telemetry as the baseline. Never
    // count unknown earlier traffic as though the test produced it.
    const snapshot = counts;
    queueMicrotask(() => setBaseline(current => current ?? snapshot));
  }, [observing, baseline, counts]);
  const delta = observing && baseline && counts ? {
    l1Allow: Math.max(0, counts.l1Allow - (baseline?.l1Allow ?? 0)),
    l1Block: Math.max(0, counts.l1Block - (baseline?.l1Block ?? 0)),
    l2Allow: Math.max(0, counts.l2Allow - (baseline?.l2Allow ?? 0)),
    l2Block: Math.max(0, counts.l2Block - (baseline?.l2Block ?? 0)),
  } : null;

  useEffect(() => {
    if (!id) return;
    let active = true;
    const readPairing = async () => {
      try {
        const result = await api<Pairing>(`/api/v1/current/ai-applications/${id}/gateway-pairing`);
        if (active) setPairing(result);
      } catch {
        if (active) setPairing(null);
      }
    };
    queueMicrotask(() => void readPairing());
    const timer = setInterval(() => void readPairing(), 15_000);
    return () => { active = false; clearInterval(timer); setPairing(null); };
  }, [id]);

  const refreshVerification = useCallback(async () => {
    if (!id) return;
    try {
      setVerification(await api<Verification>(`/api/v1/current/ai-applications/${id}/verification-run`));
    } catch {
      setVerification(null);
    }
  }, [id]);

  useEffect(() => {
    if (!id) return;
    queueMicrotask(() => void refreshVerification());
    const fallback = setInterval(() => void refreshVerification(), 30_000);
    // Presence and verification signals are server-authoritative. A live
    // heartbeat is connectivity evidence, NOT a source/route certificate.
    const events = new EventSource(`/api/v1/current/ai-applications/${id}/verification-stream`, { withCredentials: true });
    let lastRefresh = 0;
    events.addEventListener("verification", () => {
      if (Date.now() - lastRefresh > 1200) {
        lastRefresh = Date.now();
        void refreshVerification();
        void refresh();
      }
    });
    events.addEventListener("presence", event => {
      try {
        setPresence(JSON.parse((event as MessageEvent).data) as { connectivity: string; security_readiness: string });
      } catch {
        // Next authenticated server event will restore the connectivity badge.
      }
    });
    return () => { events.close(); clearInterval(fallback); setPresence(null); };
  }, [id, refresh, refreshVerification]);

  useEffect(() => {
    if (!observing || !reported) return;
    const refreshObserved = () => { void refresh(); };
    const timer = setInterval(refreshObserved, 5_000);
    return () => clearInterval(timer);
  }, [observing, reported, refresh]);

  const perform = async (action: () => Promise<void>) => {
    setBusy(true);
    setError("");
    try {
      await action();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Request failed. Check your access and try again.");
    } finally {
      setBusy(false);
    }
  };

  const issuePairing = () => perform(async () => {
    if (!id) return;
    const result = await api<Pairing>(`/api/v1/current/ai-applications/${id}/gateway-pairing`, { method: "POST" });
    downloadJson("accessproof-gateway-pairing.json", result);
    setPairing({ state: "awaiting_customer_install", expires_at: result.expires_at });
  });

  const startObservation = () => {
    setBaseline(counts);
    setObserving(true);
    void refresh();
  };

  return <ProtectedPage><div className="onboard-page">
    <PageHeader eyebrow="GET STARTED" title="Connect your RAG. Validate manually." description="Connect SharePoint and your existing chatbot, then test with real employee identities. Manual testing does not require production certification." action={<button type="button" className="button compact secondary" onClick={() => void refresh()}>Refresh</button>}/>
    <section className="onboard-hero">
      <div><span className="onboard-overline">◈ ACCESSPROOF SETUP</span><h2>Connect. Test.<br/><em>Protect your RAG.</em></h2>
        <p>Use the RAG application you already have. AccessProof watches verified Guard decisions without asking for a RAG URL or exposing private ports.</p>
      </div>
      <div className="onboard-progress"><div><span>Setup progress</span><b>{loaded ? `${count} / 3` : "Checking…"}</b></div>
        <meter min="0" max="3" value={count} aria-label="Completed setup steps"/>
        <small>Step 3 finishes only after verified security evidence and approved production cutover.</small>
      </div>
    </section>
    {data.errors.length > 0 && <p className="onboard-error" role="alert">{data.errors.join("; ")}. Refresh or sign in again.</p>}
    {error && <p className="onboard-error" role="alert">{error}</p>}
    <div className="onboard-grid">
      <section className="onboard-card">
        <header><span>01</span><Pill ok={sourceReady} label={sourceReady ? "Connected" : "Connect source"}/></header>
        <h3>Connect SharePoint</h3>
        <p>Give AccessProof permission to read your approved SharePoint sources and track access changes.</p>
        <div className="onboard-fact"><b>{source?.name ?? "No SharePoint source"}</b>
          <small>{sourceReady ? "Directory and permission sync current" : "Source authorization or synchronization needs attention."}</small>
        </div>
        <Link href="/sources">Manage SharePoint →</Link>
      </section>
      <section className="onboard-card">
        <header><span>02</span><Pill ok={reported} label={reported ? "Installed" : "Install Gateway"}/></header>
        <h3>Connect your RAG</h3>
        <p>An application owner installs Gateway beside a supported Docker RAG. AccessProof does not need a public RAG URL or your credentials.</p>
        <label className="onboard-select">AI application
          <select value={app?.application_id ?? ""} onChange={event => { setSelectedId(event.target.value); setPairing(null); setVerification(null); setObserving(false); setBaseline(null); }}>
            {!app && <option value="">Select application</option>}
            {data.apps.map(item => <option key={item.id} value={item.application_id}>{item.name}</option>)}
          </select>
        </label>
        {app && <div className="onboard-fact"><b>{app.name}</b><small>Guard: {guard?.name ?? "Not bound"} · Policy: {guard?.active_policy_version ?? "None"}</small></div>}
        {!app && <div className="onboard-next-action"><b>Application owner setup needed</b><p>Register your RAG and bind its approved SharePoint source and enrolled Guard.</p><Link href="/applications">Register a Gateway application →</Link><Link href="/guards">Enroll a Guard →</Link></div>}
        {app && !bound && <div className="onboard-next-action"><b>Complete the connection</b><p>Bind a SharePoint source and an enrolled Guard to this Gateway application before installation.</p><Link href="/applications">Review application →</Link><Link href="/guards">Enroll or check Guard →</Link></div>}
        {app && bound && !reported && <div className="onboard-supported-note"><b>Compatibility required</b><p>The installer supports Docker Compose RAGs implementing signed retrieval, identity forwarding, and buffered answer enforcement. An application owner may need to adapt an unsupported RAG first; AccessProof cannot safely convert arbitrary RAG code automatically.</p><Link href="/integrations">Check supported integration →</Link></div>}
        {app && bound && !reported && <div className="onboard-actions">
          <a className="button secondary" href="/downloads/accessproof-gateway-connector.zip?v=dashboard-choice-r15-20261102" download="accessproof-gateway-connector.zip">Download Gateway</a>
          <button type="button" className="button" disabled={busy} onClick={() => void issuePairing()}>Generate one-time pairing file</button>
          <div className="onboard-command"><b>Application owner: run once on your Docker host</b><code>{installCommand}</code>
            <small>Download the one-time pairing file first (valid 15 minutes). The installer discovers your local chatbots and waits for your selection here, without exposing Docker or changing employee routing.</small>
          </div>
        </div>}
        {app && bound && <GatewayDiscoveryPicker key={app.application_id + ":" + (pairing?.expires_at ?? "")} applicationId={app.application_id} installed={reported} />}
        {reported && <div className="onboard-success">✓ Gateway paired. Existing RAG routing and production protection are unchanged; test the guarded route below.</div>}
        <Link href="/integrations">Installation and compatibility help →</Link>
      </section>
      <section className="onboard-card" data-testid="live-rag-test-card">
        <header><span>03</span><Pill ok={!!protectedVerified} label={protectedVerified ? "Protected & verified" : "Test protection"}/></header>
        <h3>Manually test your RAG</h3>
        <p>Start manual tests now using approved synthetic documents. You do not need to pass the production certification checks first. AccessProof can also display observed Guard decisions.</p>
        <div className="onboard-workflow-metrics onboard-live-status" role="status">
          <div><small>Guard connection</small><strong className={connected ? "positive" : "caution"}>{connected ? "Connected" : "Offline / checking"}</strong></div>
          <div><small>Security readiness</small><strong>{guardReadiness.toLowerCase()}</strong></div>
          <div><small>Production protection</small><strong className={protectedVerified ? "positive" : "caution"}>{protectedVerified ? "Verified" : "Not active"}</strong></div>
        </div>
        {!reported && <div className="onboard-next-action" role="status"><b>First, connect your Gateway</b><p>The test view becomes useful after the local installer pairs this application. Your RAG is not exposed or modified from the cloud.</p></div>}
        {reported && app && <ManualRagValidation key={app.application_id} applicationId={app.application_id} guardReady={guardReadiness === "READY"} />}
        {reported && <section className="onboard-live-guide" aria-label="Live RAG test instructions">
          <b>Use your normal RAG application</b>
          <p>On a customer-controlled device, open the RAG your employees already use. No separate test URL or new public endpoint is required.</p>
          <p>Sign in as an approved employee, ask about a document they can access, then repeat with a different employee who must be denied. Use test documents and your existing Microsoft SSO; do not paste tokens or passwords into AccessProof.</p>
          <p>If a legitimate request is blocked while Guard shows <strong>degraded</strong>, investigate source authorization and Guard readiness. Never force-allow it to make the test appear successful.</p>
          <div className="onboard-inline-links">
            <Link href="/blocked-requests">Inspect denied requests →</Link>
            <Link href="/audit">Inspect Guard audit →</Link>
          </div>
        </section>}
        {reported && <section className="onboard-live-results" aria-label="Observed live Guard decisions">
          <b>Observe real Guard decisions</b>
          <p>Start observing before sending approved test questions in your RAG. AccessProof checks the backend decision counters every 5 seconds; no RAG address is required.</p>
          <button className="button" type="button" disabled={busy} onClick={startObservation}>
            {observing ? "Restart observation" : "Start observing test requests"}
          </button>
          {observing ? <>
            <div className="onboard-observations" aria-live="polite">
              <div><small>Layer 1 since observation began</small><strong>{delta ? `${delta.l1Allow} allowed · ${delta.l1Block} blocked` : "Waiting for decisions…"}</strong></div>
              <div><small>Layer 2 since observation began</small><strong>{delta ? `${delta.l2Allow} allowed · ${delta.l2Block} blocked` : "Waiting for decisions…"}</strong></div>
            </div>
            <small>Diagnostics only: application-wide 24-hour counters may include other employees or shift when the reporting window rolls forward. Individual audited decisions—not counter changes or manual RAG answers—provide security evidence.</small>
          </> : <p>No test observation is active yet.</p>}
          <button className="button secondary" type="button" disabled={busy} onClick={() => void perform(async () => { await refresh(); await refreshVerification(); })}>Refresh observed decisions</button>
          {readiness?.latest_decision_at && <small>Most recent recorded decision: {new Date(readiness.latest_decision_at).toLocaleString()}</small>}
          <Link href="/protection">Review independent protection monitoring →</Link>
        </section>}
        {reported && <section className="onboard-live-guide" aria-label="Customer security testing status">
          <b>Production certification — separate from manual testing</b>
          <p>Manual questions help you observe behavior, but they do not certify Layer 1, Layer 2, cache, provenance, or revocation. AccessProof must match actual Guard/Gateway audit evidence for the installed route.</p>
          <div className="onboard-fact"><b>{protectedVerified ? "Production protection verified" : guardReadiness === "READY" ? "Guard ready; route verification still required" : "Source or Guard verification still pending"}</b>
            <small>{protectedVerified ? "The control plane reports verified protection." : "Use protection monitoring to resolve the remaining security prerequisites. No unverified challenge is offered as a one-click pass."}</small></div>
          <Link href="/protection">See verified evidence and next actions →</Link>
        </section>}
        <div className="onboard-cutover"><b>4. Approve production cutover</b>
          <p>An administrator must approve cutover after independent SharePoint effective-permission, employee SSO, Layer 1/2, provenance, cache, and route evidence. A chatbot selection never bypasses these checks; unknown permissions fail closed.</p>
          <Link href="/protection">Review protection status →</Link>
        </div>
      </section>
    </div>
    <footer className="onboard-footer">🔒 Customer-approved cutover and valid source authorization are required for production Protect. Security controls remain enforced in the backend. <span>Updated {checkedAt || "now"}</span></footer>
  </div></ProtectedPage>;
}
