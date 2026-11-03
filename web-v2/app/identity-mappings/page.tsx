"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import { EmptyState, ErrorState, Skeleton, StatusBadge } from "../../components/ui";
import { api, Source } from "../../lib/api";
import { PageHeader } from "../app-shell";
import { ProtectedPage } from "../protected-page";

type SourceIdentity = { id: string; name: string; stable_id: string; status: string };
type Mapping = { id: string; source_id: string; oidc_issuer: string; oidc_subject: string; oidc_tenant_id: string | null; source_subject: SourceIdentity; status: string; method: string };
type SourceResolution = { source_id: string; name: string; state: string; automatic_verified: number; directory_last_success_at: string | null; directory_age_seconds: number | null };
type Resolution = { sources: SourceResolution[]; automatic: { verified: number; suspended: number; conflict: number }; conflicts: number; guests_not_bound: number; notes: string[] };

const STATE_TEXT: Record<string, string> = {
  ACTIVE: "Employees are resolved automatically from the directory.",
  DIRECTORY_NOT_SYNCHRONIZED: "The employee directory has not been synchronized yet. No employee can be resolved.",
  DIRECTORY_STALE: "The employee directory is out of date. New or changed employees are not resolved until it synchronizes.",
  NO_RESOLVED_IDENTITIES: "The directory synchronized but no eligible member accounts were found for this source's tenant.",
};

export default function IdentityResolutionPage() {
  const [resolution, setResolution] = useState<Resolution | null>(null);
  const [exceptions, setExceptions] = useState<Mapping[]>([]);
  const [sources, setSources] = useState<Source[]>([]);
  const [employees, setEmployees] = useState<SourceIdentity[] | null>(null);
  const [loading, setLoading] = useState(true); const [error, setError] = useState(""); const [saving, setSaving] = useState(false);
  const [form, setForm] = useState({ source_id: "", oidc_issuer: "", oidc_subject: "", oidc_tenant_id: "", source_subject_id: "" });
  const load = useCallback(async () => {
    setLoading(true); setError("");
    try {
      const [res, conflicts, manual, ss] = await Promise.all([
        api<Resolution>("/api/v1/current/identity-resolution"),
        api<Mapping[]>("/api/v1/current/identity-mappings?status=CONFLICT&limit=200"),
        api<Mapping[]>("/api/v1/current/identity-mappings?method=admin_verified&limit=200"),
        api<Source[]>("/api/v1/current/sources"),
      ]);
      const seen = new Set<string>();
      setResolution(res);
      setExceptions([...conflicts, ...manual].filter(m => (seen.has(m.id) ? false : (seen.add(m.id), true))));
      setSources(ss);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Unable to load identity resolution."); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { queueMicrotask(() => void load()); }, [load]);
  async function loadEmployees() { if (employees === null) { try { setEmployees(await api<SourceIdentity[]>("/api/v1/current/employees")); } catch { setEmployees([]); } } }
  async function submit(event: FormEvent) { event.preventDefault(); setSaving(true); setError(""); try { await api<Mapping>("/api/v1/current/identity-mappings", { method: "POST", body: JSON.stringify({ ...form, oidc_tenant_id: form.oidc_tenant_id || null }) }); setForm({ source_id: "", oidc_issuer: "", oidc_subject: "", oidc_tenant_id: "", source_subject_id: "" }); await load(); } catch (cause) { setError(cause instanceof Error ? cause.message : "Unable to save mapping."); } finally { setSaving(false); } }
  async function changeStatus(id: string, status: "SUSPENDED" | "REVOKED") { try { await api(`/api/v1/current/identity-mappings/${id}`, { method: "PATCH", body: JSON.stringify({ status }) }); await load(); } catch (cause) { setError(cause instanceof Error ? cause.message : "Unable to update mapping."); } }
  const update = (name: keyof typeof form, value: string) => setForm(current => ({ ...current, [name]: value }));
  return <ProtectedPage><PageHeader eyebrow="ADVANCED" title="Identity resolution" description="Microsoft 365 employees are matched to their SharePoint permissions automatically, using the immutable Entra object ID from your synchronized directory. No per-employee setup is needed."/>
    {loading ? <Skeleton rows={4}/> : error ? <ErrorState message={error} retry={load}/> : <>
      <section className="card section"><h2>Automatic resolution</h2>
        {!resolution?.sources.length ? <EmptyState title="No Microsoft 365 source connected" description="Connect SharePoint to resolve employees automatically."/> :
          <table><thead><tr><th>Source</th><th>Status</th><th>Resolved employees</th><th>Last directory sync</th></tr></thead><tbody>{resolution.sources.map(s => <tr key={s.source_id}>
            <td><b>{s.name}</b></td>
            <td><StatusBadge value={s.state.startsWith("DIRECTORY_UNAVAILABLE") ? "DIRECTORY_UNAVAILABLE" : s.state}/><small>{STATE_TEXT[s.state] ?? "The Microsoft directory reported an error. Resolution is paused and unresolved employees are denied."}</small></td>
            <td>{s.automatic_verified.toLocaleString()}</td>
            <td>{s.directory_last_success_at ? new Date(s.directory_last_success_at).toLocaleString() : "Never"}</td></tr>)}</tbody></table>}
        {resolution && <p className="muted">{resolution.automatic.suspended.toLocaleString()} suspended (disabled, removed or changed to guest) · {resolution.guests_not_bound.toLocaleString()} guest accounts not resolved automatically · {resolution.conflicts.toLocaleString()} conflicts need review.</p>}
        {resolution?.notes.map(n => <p className="muted" key={n}>{n}</p>)}
      </section>
      <section className="card table-card"><h2>Exceptions</h2>{!exceptions.length ? <EmptyState title="No exceptions" description="Conflicts and manually managed identities appear here."/> : <table><thead><tr><th>Principal</th><th>Source identity</th><th>Method</th><th>Status</th><th>Action</th></tr></thead><tbody>{exceptions.map(m => <tr key={m.id}><td><b>{m.oidc_subject}</b><small>{m.oidc_issuer}</small></td><td><b>{m.source_subject.name}</b><small>{m.source_subject.stable_id}</small></td><td>{m.method === "directory_verified" ? "Automatic" : "Manual"}</td><td><StatusBadge value={m.status}/></td><td>{(m.status === "VERIFIED" || m.status === "CONFLICT") && <span className="row wrap"><button className="button compact secondary" onClick={()=>void changeStatus(m.id,"SUSPENDED")}>Suspend</button><button className="button compact danger" onClick={()=>void changeStatus(m.id,"REVOKED")}>Revoke</button></span>}</td></tr>)}</tbody></table>}</section>
      <details className="card section" onToggle={e => { if ((e.target as HTMLDetailsElement).open) void loadEmployees(); }}><summary><b>Advanced: manual exception</b> — only for identities that cannot be resolved automatically (for example an approved guest).</summary>
        <form onSubmit={submit} className="form-grid"><label>Permission source<select required value={form.source_id} onChange={e=>update("source_id", e.target.value)}><option value="">Select source</option>{sources.map(source=><option value={source.id} key={source.id}>{source.name}</option>)}</select></label><label>Source identity<select required value={form.source_subject_id} onChange={e=>update("source_subject_id", e.target.value)}><option value="">{employees === null ? "Loading…" : "Select synchronized employee"}</option>{(employees ?? []).filter(employee=>employee.status === "active").map(employee=><option value={employee.id} key={employee.id}>{employee.name} · {employee.stable_id}</option>)}</select></label><label>OIDC issuer<input required placeholder="https://issuer.example/" value={form.oidc_issuer} onChange={e=>update("oidc_issuer", e.target.value)}/></label><label>OIDC subject<input required value={form.oidc_subject} onChange={e=>update("oidc_subject", e.target.value)}/></label><label>Tenant ID (if used)<input value={form.oidc_tenant_id} onChange={e=>update("oidc_tenant_id", e.target.value)}/></label><div className="form-action"><button className="button" disabled={saving}>{saving ? "Saving…" : "Add exception"}</button></div></form>
      </details>
    </>}
  </ProtectedPage>;
}
