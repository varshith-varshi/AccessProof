"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import { api, AIApplication, Guard, ProtectionOverview, Source } from "../../lib/api";
import { PageHeader } from "../app-shell";
import { ProtectedPage } from "../protected-page";
import "./onboarding.css";

type Pairing = { state: string; expires_at?: string | null; deployment_sha256?: string | null; route_sha256?: string | null };
type Challenge = { challenge_id: string; state: string; expires_at: string; production_certification: boolean };
type Data = { sources: Source[]; guards: Guard[]; apps: AIApplication[]; protection: ProtectionOverview | null; errors: string[] };
const EMPTY: Data = { sources: [], guards: [], apps: [], protection: null, errors: [] };
const installCommand = "python3 ~/Downloads/accessproof-gateway-connector.zip";
const sourceBlocks = new Set(["MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED", "V1_PROVIDER_SCOPE", "PRODUCTION_OIDC_READY", "PERMISSION_SOURCE_SYNCED", "PERMISSION_DIRECTORY_SYNCED"]);
const microsoft = (s: Source) => ["sharepoint", "microsoft365", "onedrive"].includes(s.provider);
function downloadJson(filename: string, value: object) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2) + "\n"], { type: "application/json" }));
  const link = document.createElement("a"); link.href = url; link.download = filename;
  document.body.append(link); link.click(); link.remove(); window.setTimeout(() => URL.revokeObjectURL(url), 2000);
}
function Pill({ ok, caution, label }: { ok: boolean; caution: boolean; label: string }) {
  return <span className={"onboard-pill " + (ok ? "success" : caution ? "warning" : "pending")}>{ok ? "✓ " : caution ? "! " : "• "}{label}</span>;
}
export default function Onboarding() {
  const [data, setData] = useState<Data>(EMPTY);
  const [selectedId, setSelectedId] = useState("");
  const [pairing, setPairing] = useState<Pairing | null>(null);
  const [challenge, setChallenge] = useState<Challenge | null>(null);
  const [challengeStatus, setChallengeStatus] = useState<Challenge | null>(null);
  const [activation, setActivation] = useState<{ state: string; message: string } | null>(null);
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
      errors: rows.flatMap((r, i) => r.status === "rejected" ? [(["Sources", "Guards", "Applications", "Readiness"][i]) + " unavailable"] : []),
    });
    setLoaded(true); setCheckedAt(new Date().toLocaleTimeString());
  }, []);
  useEffect(() => {
    queueMicrotask(() => {
      setSelectedId(new URLSearchParams(location.search).get("application") ?? "");
      void refresh();
    });
    const timer = setInterval(() => void refresh(), 30_000);
    return () => clearInterval(timer);
  }, [refresh]);
  const app = useMemo(() => data.apps.find(a => a.application_id === selectedId) ??
    data.apps.find(a => a.adapter_type === "accessproof-gateway" && data.sources.some(s => microsoft(s) && (a.source_id === s.id || a.source_ids?.includes(s.id)))) ??
    data.apps.find(a => a.adapter_type === "accessproof-gateway") ?? null,
    [data.apps, data.sources, selectedId]);
  const source = data.sources.find(s => microsoft(s) && (app?.source_id === s.id || app?.source_ids?.includes(s.id))) ?? data.sources.find(microsoft);
  const guard = data.guards.find(g => g.id === app?.guard_id);
  const bound = !!app && !!source && !!guard && app.adapter_type === "accessproof-gateway" && (app.source_id === source.id || !!app.source_ids?.includes(source.id));
  const readiness = data.protection?.applications.find(a => a.application_id === app?.application_id);
  const checks = readiness?.failed_checks ?? [];
  const fresh = !!source && source.status === "connected" && source.acl_sync?.fresh === true && source.directory_sync?.fresh === true;
  const guardConnected = !!guard && guard.health === "online" && (guard.active_policy_version ?? 0) > 0 && !!guard.enrolled_at && !guard.revoked_at;
  const reported = pairing?.state === "installation_reported_unverified" && !!bound && guardConnected;
  const protectedVerified = readiness?.effective_state === "PROTECTED_VERIFIED";
  const count = Number(fresh) + Number(reported) + Number(protectedVerified);
  const blockedChallenge = checks.some(c => sourceBlocks.has(c.code));
  const id = app ? encodeURIComponent(app.application_id) : null;
  useEffect(() => {
    if (!id) return;
    let active = true;
    const read = async () => {
      try {
        const response = await api<Pairing>(`/api/v1/current/ai-applications/${id}/gateway-pairing`);
        if (active) setPairing(response);
      } catch { if (active) setPairing(null); }
    };
    queueMicrotask(() => void read());
    const timer = setInterval(() => void read(), 15_000);
    return () => { active = false; clearInterval(timer); };
  }, [id]);
  async function perform(action: () => Promise<void>) {
    setBusy(true); setError("");
    try { await action(); }
    catch (e) { setError(e instanceof Error ? e.message : "Request failed; retry after verifying authorization."); }
    finally { setBusy(false); }
  }
  const issuePairing = () => perform(async () => {
    if (!id) return;
    const response = await api<Pairing>(`/api/v1/current/ai-applications/${id}/gateway-pairing`, { method: "POST" });
    downloadJson("accessproof-gateway-pairing.json", response);
    setPairing({ state: "awaiting_customer_install", expires_at: response.expires_at });
  });
  const issueChallenge = () => perform(async () => {
    if (!id || !pairing?.deployment_sha256 || !pairing.route_sha256 || blockedChallenge) return;
    const response = await api<Challenge>(`/api/v1/current/ai-applications/${id}/protection/challenge`, {
      method: "POST", body: JSON.stringify({ deployment_sha256: pairing.deployment_sha256, route_sha256: pairing.route_sha256 }),
    });
    downloadJson("accessproof-security-challenge.json", response); setChallenge(response);
  });
  const checkChallenge = () => perform(async () => {
    if (!id) return;
    setChallengeStatus(await api<Challenge>(`/api/v1/current/ai-applications/${id}/protection/challenge`));
    await refresh();
  });
  const checkReadiness = () => perform(async () => {
    if (!id) return;
    setActivation(await api<{ state: string; message: string }>(`/api/v1/current/ai-applications/${id}/protection/enable`, { method: "POST" }));
    await refresh();
  });
  return <ProtectedPage><div className="onboard-page">
    <PageHeader eyebrow="CUSTOMER SETUP" title="Protect your AI application" description="Connect enterprise data, link a supported RAG, then independently verify protection." action={<button className="button compact secondary" onClick={() => void refresh()} type="button">Refresh</button>}/>
    <section className="onboard-hero"><div><span className="onboard-overline">◈ ACCESSPROOF SETUP</span><h2>Connect. Verify.<br/><em>Protect with confidence.</em></h2><p>Customer-side installation is not certification. AccessProof requires real source and Guard evidence before activation.</p></div>
    <div className="onboard-progress"><div><span>Onboarding progress</span><b>{loaded ? `${count} / 3` : "Checking…"}</b></div><meter min="0" max="3" value={count} aria-label="Completed onboarding steps"/><small>🔒 Unknown permission and Guard status remain fail-closed.</small></div></section>
    {data.errors.length > 0 && <p className="onboard-error" role="alert">{data.errors.join("; ")}. Try refreshing or signing in again.</p>}
    {error && <p className="onboard-error" role="alert">{error}</p>}
    <div className="onboard-grid">
      <section className="onboard-card"><header><span>01</span><Pill ok={fresh} caution={!!source && !fresh} label={fresh ? "Connected & fresh" : source ? "Needs attention" : "Not connected"}/></header>
        <h3>Connect SharePoint</h3><p>Authorize a Microsoft source and synchronize directory identities and document permissions.</p>
        <div className="onboard-fact"><b>{source?.name ?? "No SharePoint connection"}</b><small>{fresh ? "Directory and ACL sync current" : "Check the approved source scope and synchronization."}</small></div>
        <Link href="/sources">Manage SharePoint connection →</Link>
      </section>
      <section className="onboard-card"><header><span>02</span><Pill ok={reported} caution={!bound} label={reported ? "Installation reported" : bound ? "Not paired" : "Binding incomplete"}/></header>
        <h3>Connect your RAG</h3><p>Pair your customer-side Gateway without automatically changing employee traffic.</p>
        <label className="onboard-select">Your AI application<select value={app?.application_id ?? ""} onChange={e => setSelectedId(e.target.value)}>
          {!app && <option value="">Select application</option>}{data.apps.map(a => <option key={a.id} value={a.application_id}>{a.name}</option>)}
        </select></label>
        {app && <div className="onboard-fact"><b>{app.name}</b><small>{guard ? `Guard connected · policy ${guard.active_policy_version ?? "none"} · verify readiness` : "Enroll and bind a Guard first"}</small></div>}
        {!app && <Link href="/applications">Register an application →</Link>}
        {app && bound && !reported && <div className="onboard-actions">
          <a className="button secondary" href="/downloads/accessproof-gateway-connector.zip?v=20261101-source" download="accessproof-gateway-connector.zip">Download Gateway installer</a>
          <button className="button" disabled={busy} onClick={() => void issuePairing()}>{busy ? "Preparing…" : "Download pairing key"}</button>
          <div className="onboard-command"><b>Run from your Docker RAG project directory</b><code>{installCommand}</code><small>Existing Gateways are detected. Refresh expired keys only when new pairing is actually needed.</small></div>
        </div>}
        {reported && <div className="onboard-success">✓ Gateway installation reported. The security route is not certified yet.</div>}
        <Link href="/integrations">Technical compatibility & installation details →</Link>
      </section>
      <section className="onboard-card"><header><span>03</span><Pill ok={protectedVerified} caution={checks.length > 0} label={protectedVerified ? "Protected verified" : "Checks pending"}/></header>
        <h3>Verify & protect</h3><p>Verify source permissions, provenance, real Gateway decisions, and customer-approved cutover.</p>
        <div className="onboard-fact"><b>{protectedVerified ? "Protected verified" : "Not protected yet"}</b><small>{readiness?.state_message ?? "Security evidence has not been certified."}</small></div>
        {checks.length > 0 && <details open className="onboard-checks"><summary>{checks.length} security prerequisites need attention</summary><ul>{checks.slice(0, 16).map((c, i) => <li key={c.code + i}><b>{c.code.replaceAll("_", " ")}</b> — {c.reason ?? "Verification required"}</li>)}</ul></details>}
        {reported && !protectedVerified && <div className="onboard-actions">
          <div className="onboard-command"><b>Check locally before requesting a challenge</b><p>No pairing key needed. This read-only diagnostic does not activate Protect.</p><code>{installCommand} --doctor</code></div>
          <button className="button" disabled={busy || !pairing?.deployment_sha256 || !pairing?.route_sha256 || blockedChallenge} onClick={() => void issueChallenge()}>Download security challenge</button>
          {blockedChallenge && <small>First resolve SharePoint certificate, OIDC and permission-sync prerequisites; never bypass them.</small>}
          {challenge && <div className="onboard-command"><b>Expires {new Date(challenge.expires_at).toLocaleString()}</b><code>{installCommand} --challenge-file ~/Downloads/accessproof-security-challenge.json</code><small>A preflight only; customer cutover remains separately approved.</small></div>}
          <button className="button secondary" disabled={busy} onClick={() => void checkChallenge()}>Refresh security results</button>
        </div>}
        {challengeStatus && <small>Challenge: {challengeStatus.state.replaceAll("_", " ")}</small>}
        {activation && <p role="status">{activation.message}</p>}
        <button className="button secondary" disabled={busy || !app} onClick={() => void checkReadiness()}>{busy ? "Checking…" : "Run protection readiness checks"}</button>
        <Link href="/protection">View continuous monitoring →</Link>
      </section>
    </div><footer className="onboard-footer">🔒 Your data stays under your control. Microsoft consent, customer-side installation and traffic cutover require explicit approval. Unknown permissions fail closed. <span>Checked {checkedAt || "now"}</span></footer>
  </div></ProtectedPage>;
}
