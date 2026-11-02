"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import { api, type AIApplication, type Guard, type ProtectionOverview, type Source } from "../../lib/api";
import { PageHeader } from "../app-shell";
import { ProtectedPage } from "../protected-page";
import "./onboarding.css";

type Pairing = {
  state: string; expires_at?: string | null;
  deployment_sha256?: string | null; route_sha256?: string | null;
};
type Verification = {
  run_id: string | null; state: string;
  deployment_sha256?: string; route_sha256?: string;
  guard?: { connectivity: string; security_readiness: string; heartbeat_age_seconds: number | null };
};
type Challenge = { challenge_id: string | null; state: string; expires_at?: string; verified_at?: string | null; certified_for_reference_route?: boolean };
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

function parseRagUrl(raw: string): string | null {
  try {
    const url = new URL(raw.trim());
    if (url.username || url.password || url.hash) return null;
    if (url.protocol === "https:") return url.href;
    if (url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)) return url.href;
    return null;
  } catch {
    return null;
  }
}

export default function Onboarding() {
  const [data, setData] = useState<Data>(EMPTY);
  const [selectedId, setSelectedId] = useState("");
  const [pairing, setPairing] = useState<Pairing | null>(null);
  const [verification, setVerification] = useState<Verification | null>(null);
  const [presence, setPresence] = useState<{ connectivity: string; security_readiness: string } | null>(null);
  const [challenge, setChallenge] = useState<Challenge | null>(null);
  const [challengeStatus, setChallengeStatus] = useState<Challenge | null>(null);
  const [ragUrl, setRagUrl] = useState("");
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
  const deployment = pairing?.deployment_sha256 ?? verification?.deployment_sha256;
  const route = pairing?.route_sha256 ?? verification?.route_sha256;
  const canIssueChallenge = !!id && reported && !!deployment && !!route;
  const telemetry = readiness?.decision_telemetry;

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
      const [run, lastChallenge] = await Promise.all([
        api<Verification>(`/api/v1/current/ai-applications/${id}/verification-run`),
        api<Challenge>(`/api/v1/current/ai-applications/${id}/protection/challenge`),
      ]);
      setVerification(run);
      setChallengeStatus(lastChallenge);
    } catch {
      setVerification(null);
      setChallengeStatus(null);
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

  const issueChallenge = () => perform(async () => {
    if (!id || !deployment || !route) return;
    // This creates a 10-minute, auditable test challenge only. It does not
    // turn on production Protect or bypass the server's validation gate.
    const result = await api<Challenge>(`/api/v1/current/ai-applications/${id}/protection/challenge`, {
      method: "POST",
      body: JSON.stringify({ deployment_sha256: deployment, route_sha256: route }),
    });
    downloadJson("accessproof-security-challenge.json", result);
    setChallenge(result);
    await refreshVerification();
  });

  const openRag = () => {
    const url = parseRagUrl(ragUrl);
    if (url) window.open(url, "_blank", "noopener,noreferrer");
    else setError("Enter your RAG application's HTTPS URL, or an HTTP localhost URL for a local lab.");
  };

  return <ProtectedPage><div className="onboard-page">
    <PageHeader eyebrow="GET STARTED" title="Connect your RAG. Test real protection." description="Connect SharePoint, install the Gateway, then test actual employee requests before approving cutover." action={<button type="button" className="button compact secondary" onClick={() => void refresh()}>Refresh</button>}/>
    <section className="onboard-hero">
      <div><span className="onboard-overline">◈ ACCESSPROOF SETUP</span><h2>Connect. Test.<br/><em>Protect your RAG.</em></h2>
        <p>Test the real Gateway route with permitted and denied employees. Security evidence is recorded automatically; production protection is never activated by a test.</p>
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
        <p>Install Gateway alongside your RAG. The RAG stays private; the Gateway is the employee-facing route.</p>
        <label className="onboard-select">AI application
          <select value={app?.application_id ?? ""} onChange={event => { setSelectedId(event.target.value); setPairing(null); setVerification(null); setChallenge(null); setChallengeStatus(null); }}>
            {!app && <option value="">Select application</option>}
            {data.apps.map(item => <option key={item.id} value={item.application_id}>{item.name}</option>)}
          </select>
        </label>
        {app && <div className="onboard-fact"><b>{app.name}</b><small>Guard: {guard?.name ?? "Not bound"} · Policy: {guard?.active_policy_version ?? "None"}</small></div>}
        {!app && <Link href="/applications">Register an application →</Link>}
        {app && bound && !reported && <div className="onboard-actions">
          <a className="button secondary" href="/downloads/accessproof-gateway-connector.zip?v=guard-readiness-r10-20261101" download="accessproof-gateway-connector.zip">Download Gateway</a>
          <button type="button" className="button" disabled={busy} onClick={() => void issuePairing()}>Download pairing key</button>
          <div className="onboard-command"><b>Run in your Docker RAG project</b><code>{installCommand}</code>
            <small>Pairing is one-time. An existing installed Gateway does not need reinstalling.</small>
          </div>
        </div>}
        {reported && <div className="onboard-success">✓ Gateway installation reported. You can now test the security route.</div>}
        <Link href="/integrations">Installation and compatibility help →</Link>
      </section>
      <section className="onboard-card" data-testid="live-rag-test-card">
        <header><span>03</span><Pill ok={!!protectedVerified} label={protectedVerified ? "Protected & verified" : "Test protection"}/></header>
        <h3>Test protection in your RAG</h3>
        <p>Use real employee sign-in and questions to observe what your Guard actually allows or blocks.</p>
        <div className="onboard-workflow-metrics onboard-live-status" role="status">
          <div><small>Guard connection</small><strong className={connected ? "positive" : "caution"}>{connected ? "Connected" : "Offline / checking"}</strong></div>
          <div><small>Security readiness</small><strong>{guardReadiness.toLowerCase()}</strong></div>
          <div><small>Production protection</small><strong className={protectedVerified ? "positive" : "caution"}>{protectedVerified ? "Verified" : "Not active"}</strong></div>
        </div>
        <section className="onboard-rag-session" aria-label="Open your own RAG application">
          <b>1. Open your RAG application</b>
          <p>Enter the employee-facing Gateway/RAG URL. Your RAG stays in your environment; AccessProof does not save this URL.</p>
          <label className="onboard-select">RAG application URL
            <input aria-label="RAG application URL" type="url" value={ragUrl}
              placeholder="https://your-rag.example.com"
              onChange={event => setRagUrl(event.target.value)}/>
          </label>
          <button type="button" className="button" onClick={openRag}>Open my RAG →</button>
        </section>
        <section className="onboard-live-guide" aria-label="Real employee security testing">
          <b>2. Test real employee access</b>
          <p>Sign in using your organization&apos;s existing SSO. Ask the RAG about a document the employee <strong>can access</strong>, then one they <strong>cannot access</strong>. Confirm that blocked content never appears in the answer or cache.</p>
          <p>For approved synthetic data, also test permission revocation and restored access. Keep the raw RAG endpoint private.</p>
          <div className="onboard-inline-links"><Link href="/blocked-requests">View blocked requests →</Link><Link href="/audit">View Guard audit →</Link></div>
        </section>
        <section className="onboard-live-guide" aria-label="Gateway verification challenge">
          <b>3. Verify the protected Gateway route</b>
          <p>A signed challenge checks actual Gateway HTTP responses against matching Guard audit decisions. It is a security test, <strong>not</strong> an activation button.</p>
          {reported && <button type="button" className="button" disabled={!canIssueChallenge || busy} onClick={() => void issueChallenge()}>
            {busy ? "Preparing…" : "Generate live Gateway challenge"}
          </button>}
          {!reported && <small>Connect your Gateway first to begin live testing.</small>}
          {reported && !canIssueChallenge && <small>Gateway installation fingerprints are not available yet. Refresh the connection or pair the Gateway.</small>}
          {challenge && <div className="onboard-command"><b>Run the test in your customer RAG project</b>
            <code>{installCommand} --challenge-file ~/Downloads/accessproof-security-challenge.json</code>
            <small>Use only your approved synthetic test resources. Challenge expires {challenge.expires_at ? new Date(challenge.expires_at).toLocaleTimeString() : "soon"}.</small>
          </div>}
          <div className="onboard-fact" aria-live="polite"><b>Gateway challenge: {challengeStatus?.state.replaceAll("_", " ") ?? "not requested"}</b>
            <small>{challengeStatus?.certified_for_reference_route ? "Reference Gateway challenge verified. Production cutover is still separate." : "A real passing challenge and independent source evidence are required before production Protect."}</small>
          </div>
          <button type="button" className="button secondary" disabled={!reported || busy} onClick={() => void perform(async () => { await refreshVerification(); await refresh(); })}>Refresh live test results</button>
        </section>
        <section className="onboard-live-results" aria-label="Observed security decisions">
          <b>Observed Guard decisions</b>
          {telemetry?.telemetry === "OBSERVED" ? <div className="onboard-observations">
            <div><small>Layer 1</small><strong>{telemetry.layer1?.allow ?? 0} allowed · {telemetry.layer1?.block ?? 0} blocked</strong></div>
            <div><small>Layer 2</small><strong>{telemetry.layer2?.allow ?? 0} allowed · {telemetry.layer2?.block ?? 0} blocked</strong></div>
          </div> : <p>No independent Guard decisions observed for this application yet. Run a real request through Gateway to collect evidence.</p>}
          <small>These are observed decisions, not a certification claim. See <Link href="/protection">Protection monitoring →</Link> for source, route and enforcement status.</small>
        </section>
        <div className="onboard-cutover"><b>4. Approve production cutover</b>
          <p>Once your RAG tests pass and AccessProof independently verifies the source and route evidence, your administrator can approve switching employee traffic. Until then, production remains fail-closed.</p>
          <Link href="/protection">Review protection status →</Link>
        </div>
      </section>
    </div>
    <footer className="onboard-footer">🔒 Customer-approved cutover and valid source authorization are required for production Protect. Security controls remain enforced in the backend. <span>Updated {checkedAt || "now"}</span></footer>
  </div></ProtectedPage>;
}
