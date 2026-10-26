"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { RefreshCw } from "lucide-react";
import { EmptyState, ErrorState, ProtectionStateBadge, Skeleton } from "../../components/ui";
import { api, ProtectionOverview, ProtectionOverviewApplication } from "../../lib/api";
import { formatTimestamp, titleCase } from "../../lib/format";
import { PageHeader } from "../app-shell";
import { ProtectedPage } from "../protected-page";

const VERIFIED = "PROTECTED_VERIFIED";

function formatAge(seconds: number | null) {
  if (seconds === null) return "No data";
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function Telemetry({ application }: { application: ProtectionOverviewApplication }) {
  const telemetry = application.decision_telemetry;
  if (telemetry.telemetry !== "OBSERVED" || !telemetry.layer1 || !telemetry.layer2) {
    return <><span className="status-badge warning">NO DATA</span><small>No Guard decisions recorded in 24h</small></>;
  }
  const layer1 = telemetry.layer1;
  const layer2 = telemetry.layer2;
  return <>
    <span className="status-badge success">OBSERVED</span>
    <small>L1: {layer1.allow} allow / {layer1.block} block</small>
    <small>L2: {layer2.allow} allow / {layer2.block} block</small>
  </>;
}

export default function Protection() {
  const [overview, setOverview] = useState<ProtectionOverview | null>(null);
  const [error, setError] = useState("");
  const [refreshing, setRefreshing] = useState(false);
  const load = useCallback(async () => {
    setRefreshing(true); setError("");
    try { setOverview(await api<ProtectionOverview>("/api/v1/current/protection/overview")); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Unable to load protection status."); }
    finally { setRefreshing(false); }
  }, []);
  useEffect(() => { queueMicrotask(() => void load()); }, [load]);

  const totals = overview?.totals;
  const metrics = totals ? [
    ["Verified protected", `${totals.applications_protected_verified}/${totals.applications_registered}`, "Applications whose current backend checks pass. This status is per application and expires."],
    ["Not verified", totals.applications_not_verified, "Registered applications without current verification. Treat their routes as unprotected."],
    ["Guards online", `${totals.guards_online}/${totals.guards_total}`, "Enrolled Guards with a recent authenticated heartbeat."],
    ["Sources fresh", `${totals.sources_fresh}/${totals.sources_total}`, "Sources with current permission and directory synchronization."],
    ["Unsupported adapters", totals.applications_unsupported, "Applications whose adapter cannot provide a verified Layer 1 and Layer 2 boundary."],
  ] : [];
  const verified = totals?.applications_protected_verified ?? 0;
  const registered = totals?.applications_registered ?? 0;

  return <ProtectedPage>
    <PageHeader
      eyebrow="ENFORCEMENT"
      title="Protection"
      description="Per-application protection truth derived from backend checks, Guard heartbeats, source freshness, and recorded decisions."
      action={<button className="button compact" type="button" disabled={refreshing} onClick={() => void load()}><RefreshCw className={refreshing ? "spin" : undefined} size={14}/>{refreshing ? "Refreshing…" : "Refresh status"}</button>}
    />
    {error ? <ErrorState message={error} retry={load}/> : !overview ? <Skeleton rows={5}/> : <>
      <section className="grid current-metrics">
        {metrics.map(([label, value, description]) => <article className="card" key={String(label)}><span className="label">{label}</span><strong>{value}</strong><p className="muted">{description}</p></article>)}
      </section>
      <section className="card section" aria-live="polite">
        <div className="panel-head">
          <div>
            <p className="label">VERIFICATION SCOPE</p>
            <h2>{registered === 0 ? "No applications are registered" : verified === 0 ? "No application is currently verified as protected" : `${verified} of ${registered} applications verified`}</h2>
          </div>
          <small>Checked {formatTimestamp(overview.generated_at)}</small>
        </div>
        <p className="muted">
          A Guard heartbeat, an application mode value, or the absence of failed checks alone does not prove protection.
          Only <b>Protected verified</b> means every current backend check passed for that application. Unknown, stale, or
          missing evidence is reported as unverified, never as a pass.
        </p>
        <p className="muted small">
          Missing decision telemetry is shown as <b>NO DATA</b>; it is not counted as zero blocked requests or as a healthy state.
        </p>
      </section>
      <section className="card table-card section">
        {!overview.applications.length
          ? <EmptyState
              title="No AI applications to evaluate"
              description="Register an AI application, bind a Guard and an authoritative permission source, then complete verification. Nothing on this page can be marked protected without those steps."
              action={<Link className="button compact" href="/applications">Register an application</Link>}
            />
          : <table>
              <thead><tr><th>Application</th><th>Protection state</th><th>Why</th><th>Guard</th><th>Source freshness</th><th>Decisions · 24h</th><th>Latest decision</th></tr></thead>
              <tbody>{overview.applications.map(application => <tr key={application.application_id}>
                <td>
                  <b>{application.name}</b>
                  <small>{application.application_id}</small>
                  <small>{application.adapter.type} · {application.adapter.contract_version}</small>
                  {!application.adapter.protect_capable && <small>Adapter cannot verify Protect</small>}
                </td>
                <td>
                  <ProtectionStateBadge value={application.effective_state}/>
                  <small>Mode: {titleCase(application.mode)}</small>
                  {application.route_certification.required && <small>Route certificate: {application.route_certification.certified ? `Certified · verified ${formatAge(application.route_certification.age_seconds)}` : titleCase(application.route_certification.status)}</small>}
                </td>
                <td className="table-muted">
                  <span>{application.state_message}</span>
                  <small>Reason: {titleCase(application.reason_code)}</small>
                  {application.failed_checks.length > 0 && <details>
                    <summary>{application.failed_checks.length} failing check{application.failed_checks.length === 1 ? "" : "s"}</summary>
                    <ul>{application.failed_checks.map(check => <li key={check.code}><b>{titleCase(check.code)}</b>{check.reason ? ` — ${check.reason}` : ""}</li>)}</ul>
                  </details>}
                </td>
                <td className="table-muted">
                  {application.guard.id
                    ? <><span className="status-badge">{titleCase(application.guard.health)}</span><small>{application.guard.name ?? "Bound Guard"}</small><small>Heartbeat: {formatAge(application.guard.heartbeat_age_seconds)}</small></>
                    : <><span className="status-badge warning">Not bound</span><small>No Guard is bound to this application.</small></>}
                </td>
                <td className="table-muted">
                  {application.source.id
                    ? <><span className="status-badge">{titleCase(application.source.status ?? "unknown")}</span><small>ACL sync: {formatAge(application.source.acl_sync_age_seconds)}{application.source.acl_fresh ? "" : " · stale"}</small><small>Directory: {formatAge(application.source.directory_sync_age_seconds)}{application.source.directory_fresh ? "" : " · stale"}</small></>
                    : <><span className="status-badge warning">Not bound</span><small>No permission source is bound.</small></>}
                </td>
                <td><Telemetry application={application}/></td>
                <td className="table-muted">{application.latest_decision_at ? formatTimestamp(application.latest_decision_at) : "NO DATA"}</td>
              </tr>)}</tbody>
            </table>}
      </section>
    </>}
  </ProtectedPage>;
}
