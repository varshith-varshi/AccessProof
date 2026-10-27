"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import { EmptyState, ErrorState, PendingButton, ProtectionStateBadge, Skeleton, StatusBadge } from "../../components/ui";
import { AIApplication, CurrentDashboard, Guard, ProtectionOverview, ProtectionStatus, Source, api } from "../../lib/api";
import { PageHeader } from "../app-shell";
import { ProtectedPage } from "../protected-page";

type GatewayIssuedChallenge = {
  challenge_id: string; nonce: string; application_id: string;
  guard_id: string; expires_at: string; request_ids: Record<string, string>;
  state: string; production_certification: false;
};
type GatewayChallengeState = {
  application_id: string; state: string; challenge_id: string | null;
  verified_at: string | null; certified_for_reference_route: boolean;
  production_certification: false;
};

export default function Applications() {
  const [applications, setApplications] = useState<AIApplication[]>([]);
  const [guards, setGuards] = useState<Guard[]>([]), [sources, setSources] = useState<Source[]>([]);
  const [protectionStates, setProtectionStates] = useState<Record<string, string>>({});
  const [observed, setObserved] = useState<Array<{ id: string; blocked: number; latest: string | null }>>([]);
  const [loading, setLoading] = useState(true), [error, setError] = useState(""), [creating, setCreating] = useState(false), [pending, setPending] = useState(false), [formError, setFormError] = useState("");
  const [applicationId, setApplicationId] = useState(""), [name, setName] = useState(""), [guardId, setGuardId] = useState(""), [sourceIds, setSourceIds] = useState<string[]>([]);
  const [activationStatus, setActivationStatus] = useState<ProtectionStatus | null>(null);
  const [checkingApplication, setCheckingApplication] = useState<string | null>(null);
  const [activationError, setActivationError] = useState("");
  const [gatewayApplication, setGatewayApplication] = useState<AIApplication | null>(null);
  const [deploymentDigest, setDeploymentDigest] = useState("");
  const [routeDigest, setRouteDigest] = useState("");
  const [gatewayChallenge, setGatewayChallenge] = useState<GatewayIssuedChallenge | null>(null);
  const [gatewayChallengeState, setGatewayChallengeState] = useState<GatewayChallengeState | null>(null);
  const [gatewayStatusError, setGatewayStatusError] = useState("");
  const [gatewayBusy, setGatewayBusy] = useState(false);
  const load = useCallback(async () => {
    setLoading(true); setError("");
    try {
      const [registered, dashboard, availableGuards, availableSources, protection] = await Promise.all([
        api<AIApplication[]>("/api/v1/current/ai-applications"), api<CurrentDashboard>("/api/v1/current/dashboard"),
        api<Guard[]>("/api/v1/guards"), api<Source[]>("/api/v1/current/sources"),
        api<ProtectionOverview>("/api/v1/current/protection/overview"),
      ]);
      setGuards(availableGuards); setSources(availableSources);
      setProtectionStates(Object.fromEntries(
        protection.applications.map(item => [item.application_id, item.effective_state]),
      ));
      const observedMap = new Map<string, { id: string; blocked: number; latest: string | null }>();
      for (const item of dashboard.recent_activity) {
        if (!item.application_id || registered.some(row => row.application_id === item.application_id)) continue;
        const row = observedMap.get(item.application_id) ?? { id: item.application_id, blocked: 0, latest: item.timestamp };
        row.blocked += item.type.includes("BLOCK") ? 1 : 0;
        if (!row.latest || item.timestamp > row.latest) row.latest = item.timestamp;
        observedMap.set(item.application_id, row);
      }
      setApplications(registered); setObserved([...observedMap.values()].sort((a, b) => (b.latest ?? "").localeCompare(a.latest ?? "")));
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Unable to load AI applications."); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { queueMicrotask(() => void load()); }, [load]);
  async function create(event: FormEvent) {
    event.preventDefault(); setPending(true); setFormError("");
    try {
      await api("/api/v1/current/ai-applications", { method: "POST", body: JSON.stringify({ application_id: applicationId.trim(), name: name.trim(), guard_id: guardId.trim() || undefined, source_id: sourceIds[0] || undefined, source_ids: sourceIds, adapter_type: "accessproof-gateway", adapter_contract_version: "accessproof.rag/v1" }) });
      setApplicationId(""); setName(""); setGuardId(""); setSourceIds([]); setCreating(false); await load();
    } catch (cause) { setFormError(cause instanceof Error ? cause.message : "Unable to register the application."); }
    finally { setPending(false); }
  }
  function beginGatewaySetup(row: AIApplication) {
    setGatewayApplication(row);
    setDeploymentDigest("");
    setRouteDigest("");
    setGatewayChallenge(null);
    setGatewayChallengeState(null);
    setGatewayStatusError("");
  }
  async function loadGatewayManifest(file: File | null) {
    if (!file) return;
    setGatewayStatusError("");
    if (file.size > 50_000) { setGatewayStatusError("Installation manifest is too large."); return; }
    try {
      const result = JSON.parse(await file.text()) as Record<string, unknown>;
      if (result.reference_contract !== "accessproof.gateway/v1" ||
          result.application_id !== gatewayApplication?.application_id ||
          typeof result.deployment_sha256 !== "string" ||
          typeof result.route_sha256 !== "string" ||
          !/^[0-9a-f]{64}$/.test(result.deployment_sha256) ||
          !/^[0-9a-f]{64}$/.test(result.route_sha256)) {
        throw new Error("Select the generated installation.json for this registered Gateway application.");
      }
      setDeploymentDigest(result.deployment_sha256);
      setRouteDigest(result.route_sha256);
    } catch (error) {
      setGatewayStatusError(error instanceof Error ? error.message : "Invalid Gateway installation manifest.");
    }
  }
  async function issueGatewayChallenge() {
    if (!gatewayApplication) return;
    setGatewayBusy(true); setGatewayStatusError(""); setGatewayChallenge(null);
    try {
      const challenge = await api<GatewayIssuedChallenge>(
        `/api/v1/current/ai-applications/${encodeURIComponent(gatewayApplication.application_id)}/protection/challenge`,
        { method: "POST", body: JSON.stringify({
          deployment_sha256: deploymentDigest,
          route_sha256: routeDigest,
        }) },
      );
      setGatewayChallenge(challenge);
      setGatewayChallengeState(null);
      await load();
    } catch (error) {
      setGatewayStatusError(error instanceof Error ? error.message : "Unable to issue a route challenge.");
    } finally { setGatewayBusy(false); }
  }
  async function refreshGatewayChallenge() {
    if (!gatewayApplication) return;
    setGatewayBusy(true); setGatewayStatusError("");
    try {
      const status = await api<GatewayChallengeState>(
        `/api/v1/current/ai-applications/${encodeURIComponent(gatewayApplication.application_id)}/protection/challenge`,
      );
      setGatewayChallengeState(status);
      await load();
    } catch (error) {
      setGatewayStatusError(error instanceof Error ? error.message : "Unable to read challenge status.");
    } finally { setGatewayBusy(false); }
  }
  async function setMode(row: AIApplication, mode: "protect" | "shadow") {
    try { await api(`/api/v1/current/ai-applications/${encodeURIComponent(row.application_id)}/mode`, { method: "PATCH", body: JSON.stringify({ mode }) }); await load(); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Unable to update protection mode."); }
  }
  async function enableProtection(row: AIApplication) {
    setCheckingApplication(row.application_id);
    setActivationStatus(null);
    setActivationError("");
    try {
      const status = await api<ProtectionStatus>(`/api/v1/current/ai-applications/${encodeURIComponent(row.application_id)}/protection/enable`, { method: "POST" });
      // The server always gives the truthful security status. A requested
      // preflight is NOT equivalent to an active Guard Protect acknowledgement.
      setActivationStatus(status);
      await load();
    } catch (cause) {
      setActivationError(cause instanceof Error ? cause.message : "The automatic security check could not start.");
    } finally { setCheckingApplication(null); }
  }
  async function retryProtection() {
    if (!activationStatus) return;
    const row = applications.find(item => item.application_id === activationStatus.application_id);
    if (row) await enableProtection(row);
  }
  return <ProtectedPage>
    <PageHeader eyebrow="AI SURFACES" title="AI applications" description="Register an AI application, connect its Guard and source, then run automatic protection checks. Protection is not claimed active until verified." action={<button className="button compact" onClick={() => setCreating(value => !value)}>{creating ? "Close" : "Register application"}</button>} />
    {creating && <section className="card create-panel"><div className="panel-head"><div><p className="label">PROTECTION REGISTRATION</p><h2>Register an AI application</h2></div></div><p className="muted">Bind an application to one Guard and one or more explicitly approved permission sources. AccessProof checks this binding before Protect can be enabled.</p><form className="form" onSubmit={create}><label>Application ID<input value={applicationId} onChange={e => setApplicationId(e.target.value)} placeholder="finance-rag-prod" required/><small>A stable identifier sent by your customer-side Gateway with every protected request.</small></label><label>Display name<input value={name} onChange={e => setName(e.target.value)} placeholder="Finance knowledge assistant" required/></label><label>Integration method<input aria-label="Integration method" value="AccessProof Gateway" readOnly/><small>Only the verified Gateway route is supported. No framework selection or application library changes.</small></label><label>Guard<select aria-label="Guard selector" value={guardId} onChange={e => setGuardId(e.target.value)} required><option value="">Select an enrolled Guard</option>{guards.map(guard => <option key={guard.id} value={guard.id}>{guard.name} · {guard.health}</option>)}</select><small>{guards.length ? "The Guard must be online before verification can pass." : "Create and enroll a Guard first."}</small></label><fieldset style={{ border: "1px solid var(--border, #445)", padding: 12, borderRadius: 8 }}>
        <legend>Authorized enterprise data sources</legend>
        <p className="muted small">Select one or more connected sources. Each needs independent employee mapping, fresh ACLs, signed provenance and a passing V2 Guard test before production activation.</p>
        {sources.filter(source => ["google-drive", "sharepoint", "onedrive", "microsoft365"].includes(source.provider) && source.status !== "disconnected").map(source =>
          <label key={source.id} style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <input type="checkbox" aria-label={"Source " + source.name} checked={sourceIds.includes(source.id)}
              onChange={event => setSourceIds(current => event.target.checked ? [...current, source.id] : current.filter(id => id !== source.id))}/>
            <span>{source.name} · {source.provider} {source.provider !== "google-drive" ? "· requires live validation" : ""}</span>
          </label>
        )}
        {!sources.length && <p>Connect and validate a permission source first.</p>}
        <small>Mixed-source Protect remains blocked until route-specific security certification is completed.</small>
      </fieldset>{formError && <p className="form-error" role="alert">{formError}</p>}<PendingButton className="button compact" pending={pending || sourceIds.length === 0}>{pending ? "Registering…" : "Register application"}</PendingButton></form></section>}
    {gatewayApplication && <section className="card create-panel" aria-label="Gateway automated integration">
      <div className="panel-head"><div><p className="label">SUPPORTED RAG GATEWAY</p><h2>Verify {gatewayApplication.name}</h2></div>
        <button type="button" className="text-button" onClick={() => setGatewayApplication(null)}>Close</button>
      </div>
      <p className="muted">This workflow is available for the explicitly supported attested-manifest Docker Gateway route. It does not protect arbitrary RAGs or bypass required verification.</p>
      <p><b>1. Install the Gateway locally.</b> Run the customer-side Docker installer from the private installation guide. It starts the Gateway without changing the RAG service, then saves an <code>installation.json</code> manifest.</p>
      <label>Choose your generated installation.json
        <input aria-label="Gateway installation manifest" type="file" accept=".json,application/json" onChange={event => void loadGatewayManifest(event.target.files?.[0] ?? null)} />
      </label>
      {deploymentDigest && <p className="muted small">Deployment digest verified for this application: {deploymentDigest.slice(0, 16)}…</p>}
      <p><b>2. Run reference security challenges.</b> AccessProof issues a single-use challenge bound to this deployment, source and enrolled Guard. Use the customer-side challenge agent to run synthetic allow, deny, content-forgery and in-flight revocation tests and upload Guard audit evidence.</p>
      <button className="button compact" type="button" disabled={gatewayBusy || !deploymentDigest || !routeDigest} onClick={() => void issueGatewayChallenge()}>
        {gatewayBusy ? "Checking…" : "Issue security challenge"}
      </button>
      {gatewayChallenge && <div role="status" className="card section">
        <p><b>Challenge issued</b> — expires {new Date(gatewayChallenge.expires_at).toLocaleString()}</p>
        <p className="muted small">Copy the one-time challenge nonce into the customer-side private agent configuration; do not put synthetic identity tokens or ingestion keys in this website.</p>
        <code style={{ overflowWrap: "anywhere" }}>{gatewayChallenge.nonce}</code>
        <p className="muted small">Reference challenge ID: {gatewayChallenge.challenge_id}</p>
      </div>}
      <p><b>3. Verify the actual RAG cutover.</b> Once all four Guard-audited challenges pass, an explicitly approved customer-side deployment change and a separate employee-facing request must also pass. Only then can the enrolled Guard acknowledge Protect.</p>
      <button className="button compact" type="button" disabled={gatewayBusy} onClick={() => void refreshGatewayChallenge()}>Refresh challenge status</button>
      {gatewayChallengeState && <p role="status">Latest challenge: <b>{gatewayChallengeState.state.replaceAll("_", " ")}</b>. Complete customer route certified: {gatewayChallengeState.certified_for_reference_route ? "Yes — subject to remaining Guard/source checks" : "Not yet"}.</p>}
      {gatewayStatusError && <p role="alert" className="form-error">{gatewayStatusError}</p>}
    </section>}
    {(checkingApplication || activationStatus || activationError) && <section className="card create-panel" aria-live="polite" aria-label="Protection security checks">
      <div className="panel-head"><div><p className="label">PROTECTION SECURITY CHECKS</p><h2>{checkingApplication ? "Checking integration…" : activationStatus?.state === "protected" ? "Guard protection active" : activationStatus?.state === "validating" ? "Waiting for Guard acknowledgment" : activationStatus?.state === "protection_needs_attention" ? "Protection needs attention — unsafe requests blocked" : "Action required"}</h2></div><button className="text-button" type="button" onClick={() => { setActivationStatus(null); setActivationError(""); }}>Close</button></div>
      {checkingApplication && <p role="status">Checking the Guard, source permissions, employee identities, and RAG integration…</p>}
      {activationError && <p className="form-error" role="alert">{activationError}</p>}
      {activationStatus && <>
        <p className="muted">{activationStatus.state === "protected" ? "All current checks passed and the enrolled Guard acknowledged Protect mode. This status is specific to the bound application and expires if source or policy checks become stale." : "AccessProof cannot mark protection active until all checks succeed and the customer-side Guard confirms activation. No unsafe bypass has been enabled."}</p>
        <p role="status"><b>{activationStatus.message}</b></p>
        <ul>{activationStatus.checks.filter(check => !check.ok).slice(0, 6).map(check => <li key={check.code}><b>{check.code.replaceAll("_", " ").toLowerCase()}</b>: {check.reason ?? "Additional validation required."}</li>)}</ul>
        <details><summary>View all security check results</summary><ul>{activationStatus.checks.map(check => <li key={check.code}>{check.ok ? "✓" : "—"} {check.code.replaceAll("_", " ").toLowerCase()} {check.reason ? `— ${check.reason}` : ""}</li>)}</ul></details>
        {activationStatus.last_checked_at && <small>Last checked: {new Date(activationStatus.last_checked_at).toLocaleString()}</small>}
        <button className="button compact" type="button" onClick={() => void retryProtection()} disabled={checkingApplication !== null}>Retry checks</button>
      </>}
    </section>}
    <section className="card table-card">{loading ? <Skeleton rows={5}/> : error ? <ErrorState message={error} retry={load}/> : !applications.length && !observed.length ? <EmptyState title="No AI applications yet" description="Register an AI surface to track its Guard binding and protection readiness. Observed applications will also appear after their first authorization decision." action={<button className="button compact" onClick={() => setCreating(true)}>Register application</button>}/> : <><table><thead><tr><th>Application</th><th>Integration</th><th>Protection</th><th>Readiness</th><th>Guard / source</th><th>Action</th></tr></thead><tbody>{applications.map(row => { const failed = row.readiness.filter(check => !check.ok); return <tr key={row.id}><td><b>{row.name}</b><small>{row.application_id}</small></td><td><b>{row.adapter_type === "accessproof-gateway" ? "Gateway" : "Legacy integration · unsupported"}</b><small>{row.adapter_type === "accessproof-gateway" ? row.adapter_contract_version : "Read-only historical record; cannot be certified"}</small></td><td><ProtectionStateBadge value={protectionStates[row.application_id] ?? "UNKNOWN"}/><small>Mode: {row.mode}</small></td><td><StatusBadge value={failed.length ? `${failed.length} checks pending` : "Ready for protection review"}/>{failed.length > 0 && <small>{failed[0].reason}</small>}</td><td className="table-muted"><small>Guard: {row.guard_id || "Not bound"}</small><small>Sources: {(row.source_ids?.length ? row.source_ids : row.source_id ? [row.source_id] : []).join(", ") || "Not bound"}</small></td><td>{row.adapter_type === "accessproof-gateway" ? <><button className="button compact" type="button" onClick={() => beginGatewaySetup(row)}>Set up Gateway</button> <button className="button compact" disabled={checkingApplication !== null} onClick={() => void enableProtection(row)}>{checkingApplication === row.application_id ? "Checking integration…" : "Enable Protection"}</button></> : <small className="muted">Historical record only · new Gateway required</small>}</td></tr>; })}</tbody></table>{observed.length > 0 && <div className="card-head"><div><p className="label">OBSERVED SURFACES</p><h2>Unregistered authorization traffic</h2></div></div>}{observed.length > 0 && <table><thead><tr><th>Application ID</th><th>Activity</th><th>Latest decision</th></tr></thead><tbody>{observed.map(row => <tr key={row.id}><td><b>{row.id}</b><small>Observed by Guard</small></td><td><StatusBadge value={row.blocked ? `${row.blocked} blocked` : "Observed"}/></td><td className="table-muted">{row.latest ? new Date(row.latest).toLocaleString() : "Not available"}</td></tr>)}</tbody></table>}</>}</section>
  </ProtectedPage>;
}
