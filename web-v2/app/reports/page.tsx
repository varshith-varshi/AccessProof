"use client";

import { useCallback, useEffect, useState } from "react";
import { Download, FileCheck2, RefreshCw, ShieldAlert } from "lucide-react";
import { EmptyState, ErrorState, PendingButton, Skeleton } from "../../components/ui";
import { api, ReportEnvelope, ReportEvidenceLevels, ReportSummary, ReportType, apiErrorMessage } from "../../lib/api";
import { formatTimestamp, shortId, titleCase } from "../../lib/format";
import { PageHeader } from "../app-shell";
import { ProtectedPage } from "../protected-page";

const REPORT_TYPES: Array<{ value: ReportType; label: string; description: string }> = [
  { value: "APPLICATION_COVERAGE", label: "Application coverage", description: "Per-application protection state, failed checks, Guard and source evidence." },
  { value: "GUARD_HEALTH", label: "Guard health", description: "Enrolled Guard health, heartbeat age, policy version, and source freshness." },
  { value: "AUTHORIZATION_ACTIVITY", label: "Authorization activity", description: "24-hour decision aggregates plus recent metadata-only Guard decisions." },
];

const EVIDENCE_LABELS: Array<{ key: keyof ReportEvidenceLevels; label: string }> = [
  { key: "control_plane_state", label: "Control-plane state" },
  { key: "guard_decisions", label: "Guard decisions" },
  { key: "provider_effective_permissions", label: "Provider effective permissions" },
  { key: "revocation_to_first_denial_timing", label: "Revocation-to-first-denial timing" },
];

function evidenceTone(level: string) {
  if (level === "NOT_OBSERVED") return "neutral";
  if (level === "ASSERTED_BY_CUSTOMER_MACHINE") return "warning";
  return "success";
}

function evidenceLabel(level: string) {
  if (level === "DIRECTLY_OBSERVED_BY_ACCESSPROOF") return "Observed by AccessProof";
  if (level === "ASSERTED_BY_CUSTOMER_MACHINE") return "Asserted by customer Guard";
  if (level === "CONFIRMED_INDEPENDENTLY_AGAINST_PROVIDER") return "Confirmed against provider";
  if (level === "NOT_OBSERVED") return "Not observed";
  return titleCase(level);
}

function numberValue(value: unknown) {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function reportTypeLabel(value: string) {
  return REPORT_TYPES.find(item => item.value === value)?.label ?? titleCase(value);
}

function VerificationBadge({ ok, label }: { ok: boolean; label: string }) {
  return <span className={`status-badge ${ok ? "success" : "danger"}`}>{ok ? <FileCheck2 size={12}/> : <ShieldAlert size={12}/>}{label}</span>;
}

export default function Reports() {
  const [reports, setReports] = useState<ReportSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [creating, setCreating] = useState(false);
  const [reportType, setReportType] = useState<ReportType>("APPLICATION_COVERAGE");
  const [generating, setGenerating] = useState(false);
  const [actionError, setActionError] = useState("");
  const [selected, setSelected] = useState<ReportEnvelope | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [opening, setOpening] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true); setError("");
    try { setReports(await api<ReportSummary[]>("/api/v1/current/reports")); }
    catch (cause) { setError(apiErrorMessage(cause, "Unable to load reports.")); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { queueMicrotask(() => void load()); }, [load]);

  async function openReport(reportId: string) {
    setOpening(reportId); setActionError("");
    try {
      setSelected(await api<ReportEnvelope>(`/api/v1/current/reports/${encodeURIComponent(reportId)}`));
      setSelectedId(reportId);
    } catch (cause) {
      setActionError(apiErrorMessage(cause, "Unable to read the report."));
    } finally { setOpening(null); }
  }

  async function generate() {
    setGenerating(true); setActionError("");
    try {
      const created = await api<ReportEnvelope>("/api/v1/current/reports", {
        method: "POST", body: JSON.stringify({ report_type: reportType }),
      });
      setSelected(created);
      setSelectedId(created.report.report_id);
      setCreating(false);
      await load();
    } catch (cause) {
      setActionError(apiErrorMessage(cause, "Unable to generate a report."));
    } finally { setGenerating(false); }
  }

  async function reverify(reportId: string) {
    setOpening(reportId); setActionError("");
    try {
      const verification = await api<ReportEnvelope["verification"]>(`/api/v1/current/reports/${encodeURIComponent(reportId)}/verify`);
      setSelected(current => current && current.report.report_id === reportId
        ? { ...current, verification }
        : current);
    } catch (cause) {
      setActionError(apiErrorMessage(cause, "Unable to verify the report."));
    } finally { setOpening(null); }
  }

  const summary = selected?.report.summary ?? {};
  const evidence = selected?.report.evidence_levels;
  const decisions = summary.decisions_24h as Record<string, unknown> | undefined;

  return <ProtectedPage>
    <PageHeader
      eyebrow="SECURITY REVIEW"
      title="Reports"
      description="Tenant-scoped, signed evidence exports. Verification is explicit; missing evidence is reported as not observed."
      action={<button className="button compact" type="button" onClick={() => setCreating(value => !value)}>{creating ? "Close" : "Generate report"}</button>}
    />
    {creating && <section className="card create-panel" aria-label="Generate a report">
      <div className="panel-head"><div><p className="label">SIGNED EVIDENCE EXPORT</p><h2>Generate a control-plane report</h2></div></div>
      <p className="muted">
        Reports contain metadata-only control-plane observations. Guard decisions are customer-machine assertions unless
        separately confirmed against the provider. Revocation timing is not observed, subject identifiers are hashed, and
        prompts, answers, tokens, document contents, and source boundaries are never included.
      </p>
      <form className="form" onSubmit={event => { event.preventDefault(); void generate(); }}>
        <label>Report type
          <select value={reportType} onChange={event => setReportType(event.target.value as ReportType)}>
            {REPORT_TYPES.map(item => <option key={item.value} value={item.value}>{item.label}</option>)}
          </select>
          <small>{REPORT_TYPES.find(item => item.value === reportType)?.description}</small>
        </label>
        <p className="muted small">Reports are signed by the control plane, expire after 30 days, and remain readable only within this organization. Download the signed JSON for offline verification.</p>
        {actionError && <p className="form-error" role="alert">{actionError}</p>}
        <PendingButton className="button compact" pending={generating}>{generating ? "Generating…" : "Generate and sign report"}</PendingButton>
      </form>
    </section>}
    {selected && <section className="card create-panel" aria-label="Report detail" aria-live="polite">
      <div className="panel-head">
        <div>
          <p className="label">SIGNED REPORT</p>
          <h2>{reportTypeLabel(selected.report.report_type)} · {shortId(selected.report.report_id)}</h2>
        </div>
        <button className="text-button" type="button" onClick={() => { setSelected(null); setSelectedId(null); }}>Close</button>
      </div>
      <p className="muted small">Generated {formatTimestamp(selected.report.generated_at)} · Expires {formatTimestamp(selected.report.expires_at)} · Schema {selected.report.schema}</p>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 8, margin: "12px 0" }}>
        <VerificationBadge ok={selected.verification.verified} label={selected.verification.verified ? "Signature and scope verified" : "Not verified"}/>
        <VerificationBadge ok={selected.verification.signature_valid} label="Signature"/>
        <VerificationBadge ok={selected.verification.scope_valid} label="Tenant scope"/>
        <VerificationBadge ok={!selected.verification.expired} label={selected.verification.expired ? "Expired" : "Not expired"}/>
      </div>
      <div className="definition-list">
        {EVIDENCE_LABELS.map(item => <div key={item.key}>
          <span>{item.label}</span>
          <span className={`status-badge ${evidenceTone(evidence?.[item.key] ?? "NOT_OBSERVED")}`}>{evidenceLabel(evidence?.[item.key] ?? "NOT_OBSERVED")}</span>
        </div>)}
      </div>
      <div className="definition-list">
        <div><span>Applications registered</span><b>{numberValue(summary.applications_registered) ?? "NO DATA"}</b></div>
        <div><span>Applications verified protected</span><b>{numberValue(summary.applications_protected_verified) ?? "NO DATA"}</b></div>
        <div><span>Applications not verified</span><b>{numberValue(summary.applications_not_verified) ?? "NO DATA"}</b></div>
        <div><span>Guards online / total</span><b>{numberValue(summary.guards_online) ?? "NO DATA"} / {numberValue(summary.guards_total) ?? "NO DATA"}</b></div>
        <div><span>Sources fresh / total</span><b>{numberValue(summary.sources_fresh) ?? "NO DATA"} / {numberValue(summary.sources_total) ?? "NO DATA"}</b></div>
        <div><span>Decision telemetry · 24h</span><b>{decisions?.telemetry === "OBSERVED" ? `${numberValue(decisions.total) ?? 0} observed decisions` : "NO DATA"}</b></div>
      </div>
      {Array.isArray(selected.report.limitations) && selected.report.limitations.length > 0 && <details style={{ marginTop: 14 }}>
        <summary>Report limitations ({selected.report.limitations.length})</summary>
        <ul>{selected.report.limitations.map(limitation => <li key={limitation}>{limitation}</li>)}</ul>
      </details>}
      <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginTop: 18 }}>
        <a className="button compact secondary" href={`/api/v1/current/reports/${encodeURIComponent(selected.report.report_id)}/download`}><Download size={14}/>Download signed JSON</a>
        <button className="button compact secondary" type="button" disabled={opening !== null} onClick={() => void reverify(selected.report.report_id)}><RefreshCw className={opening === selected.report.report_id ? "spin" : undefined} size={14}/>Re-verify</button>
      </div>
      {actionError && <p className="form-error" role="alert">{actionError}</p>}
    </section>}
    {error ? <ErrorState message={error} retry={load}/> : loading ? <Skeleton rows={5}/> : <section className="card table-card">
      {!reports.length
        ? <EmptyState
            title="No signed reports yet"
            description="Generate a report to export the current control-plane evidence. The report records which facts were observed, which were asserted by a customer Guard, and which were never observed."
            action={<button className="button compact" onClick={() => setCreating(true)}>Generate report</button>}
          />
        : <table>
            <thead><tr><th>Report</th><th>Type</th><th>Generated</th><th>Expires</th><th>Guard decisions</th><th>Integrity</th><th>Action</th></tr></thead>
            <tbody>{reports.map(report => <tr key={report.id}>
              <td><b>{shortId(report.id)}</b><small>{report.key_id ? `Key ${shortId(report.key_id)}` : "Signing key not recorded"}</small></td>
              <td>{reportTypeLabel(report.report_type)}</td>
              <td className="table-muted">{formatTimestamp(report.generated_at)}</td>
              <td className="table-muted">{formatTimestamp(report.expires_at)}</td>
              <td className="table-muted">
                <span className={`status-badge ${report.evidence_levels.guard_decisions === "NOT_OBSERVED" ? "warning" : "success"}`}>{evidenceLabel(report.evidence_levels.guard_decisions)}</span>
              </td>
              <td className="table-muted">{selectedId === report.id && selected
                ? <VerificationBadge ok={selected.verification.verified} label={selected.verification.verified ? "Verified now" : "Not verified"}/>
                : <span className="muted small">Verify to confirm</span>}</td>
              <td><button className="button compact" type="button" disabled={opening !== null} onClick={() => void openReport(report.id)}>{opening === report.id ? "Verifying…" : "Open & verify"}</button></td>
            </tr>)}</tbody>
          </table>}
    </section>}
  </ProtectedPage>;
}
