"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import { EmptyState, ErrorState, PendingButton, Skeleton, StatusBadge } from "../../components/ui";
import { AIApplication, CurrentDashboard, api } from "../../lib/api";
import { PageHeader } from "../app-shell";
import { ProtectedPage } from "../protected-page";

export default function Applications() {
  const [applications, setApplications] = useState<AIApplication[]>([]);
  const [observed, setObserved] = useState<Array<{ id: string; blocked: number; latest: string | null }>>([]);
  const [loading, setLoading] = useState(true), [error, setError] = useState(""), [creating, setCreating] = useState(false), [pending, setPending] = useState(false), [formError, setFormError] = useState("");
  const [applicationId, setApplicationId] = useState(""), [name, setName] = useState(""), [guardId, setGuardId] = useState(""), [sourceId, setSourceId] = useState("");
  const load = useCallback(async () => {
    setLoading(true); setError("");
    try {
      const [registered, dashboard] = await Promise.all([api<AIApplication[]>("/api/v1/current/ai-applications"), api<CurrentDashboard>("/api/v1/current/dashboard")]);
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
      await api("/api/v1/current/ai-applications", { method: "POST", body: JSON.stringify({ application_id: applicationId.trim(), name: name.trim(), guard_id: guardId.trim() || undefined, source_id: sourceId.trim() || undefined }) });
      setApplicationId(""); setName(""); setGuardId(""); setSourceId(""); setCreating(false); await load();
    } catch (cause) { setFormError(cause instanceof Error ? cause.message : "Unable to register the application."); }
    finally { setPending(false); }
  }
  async function setMode(row: AIApplication, mode: "protect" | "shadow") {
    try { await api(`/api/v1/current/ai-applications/${encodeURIComponent(row.application_id)}/mode`, { method: "PATCH", body: JSON.stringify({ mode }) }); await load(); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Unable to update protection mode."); }
  }
  return <ProtectedPage>
    <PageHeader eyebrow="AI SURFACES" title="AI applications" description="Register each AI surface, verify its enforcement path, and enable Protect only when every readiness check passes." action={<button className="button compact" onClick={() => setCreating(value => !value)}>{creating ? "Close" : "Register application"}</button>} />
    {creating && <section className="card create-panel"><div className="panel-head"><div><p className="label">PROTECTION REGISTRATION</p><h2>Register an AI application</h2></div></div><p className="muted">Use the stable application identifier that Guard sends with authorization decisions. IDs are tenant-scoped.</p><form className="form" onSubmit={create}><label>Application ID<input value={applicationId} onChange={e => setApplicationId(e.target.value)} placeholder="finance-rag-prod" required/></label><label>Display name<input value={name} onChange={e => setName(e.target.value)} placeholder="Finance knowledge assistant" required/></label><label>Guard ID <small>Optional until the Guard is enrolled.</small><input value={guardId} onChange={e => setGuardId(e.target.value)} placeholder="Guard registration ID"/></label><label>Permission source ID <small>Optional until the source is connected.</small><input value={sourceId} onChange={e => setSourceId(e.target.value)} placeholder="Source connection ID"/></label>{formError && <p className="form-error" role="alert">{formError}</p>}<PendingButton className="button compact" pending={pending}>{pending ? "Registering…" : "Register application"}</PendingButton></form></section>}
    <section className="card table-card">{loading ? <Skeleton rows={5}/> : error ? <ErrorState message={error} retry={load}/> : !applications.length && !observed.length ? <EmptyState title="No AI applications yet" description="Register an AI surface to track its Guard binding and Protect readiness. Observed applications will also appear after their first authorization decision." action={<button className="button compact" onClick={() => setCreating(true)}>Register application</button>}/> : <><table><thead><tr><th>Application</th><th>Mode</th><th>Readiness</th><th>Guard / source</th><th>Action</th></tr></thead><tbody>{applications.map(row => { const failed = row.readiness.filter(check => !check.ok); return <tr key={row.id}><td><b>{row.name}</b><small>{row.application_id}</small></td><td><StatusBadge value={row.mode}/></td><td><StatusBadge value={failed.length ? `${failed.length} checks pending` : "Ready for Protect"}/>{failed.length > 0 && <small>{failed[0].reason}</small>}</td><td className="table-muted"><small>Guard: {row.guard_id || "Not bound"}</small><small>Source: {row.source_id || "Not bound"}</small></td><td>{row.mode === "protect" ? <button className="text-button" onClick={() => void setMode(row, "shadow")}>Return to Shadow</button> : <button className="button compact" disabled={failed.length > 0} title={failed.length ? "Complete readiness checks first" : "Enable Protect"} onClick={() => void setMode(row, "protect")}>Enable Protect</button>}</td></tr>; })}</tbody></table>{observed.length > 0 && <div className="card-head"><div><p className="label">OBSERVED SURFACES</p><h2>Unregistered authorization traffic</h2></div></div>}{observed.length > 0 && <table><thead><tr><th>Application ID</th><th>Activity</th><th>Latest decision</th></tr></thead><tbody>{observed.map(row => <tr key={row.id}><td><b>{row.id}</b><small>Observed by Guard</small></td><td><StatusBadge value={row.blocked ? `${row.blocked} blocked` : "Observed"}/></td><td className="table-muted">{row.latest ? new Date(row.latest).toLocaleString() : "Not available"}</td></tr>)}</tbody></table>}</>}</section>
  </ProtectedPage>;
}
