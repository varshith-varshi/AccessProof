"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { EmptyState, ErrorState, Skeleton, StatusBadge } from "../../components/ui";
import { api, CurrentDashboard, ProtectionDecisionBucket } from "../../lib/api";
import { formatTimestamp } from "../../lib/format";
import { AppShell, PageHeader } from "../app-shell";

function decisionSummary(bucket: ProtectionDecisionBucket | null | undefined) {
  if (!bucket) return "NO DATA";
  return `${bucket.allow} allow · ${bucket.block} block · ${bucket.would_allow} would allow · ${bucket.would_block} would block`;
}

export default function Dashboard() {
  const [data, setData] = useState<CurrentDashboard | null>(null);
  const [error, setError] = useState("");
  async function load() { setError(""); try { setData(await api<CurrentDashboard>("/api/v1/current/dashboard")); } catch (cause) { setError(cause instanceof Error ? cause.message : "Unable to load the authorization overview."); } }
  useEffect(() => { queueMicrotask(() => void load()); }, []);
  const health = !data ? "Loading status" : data.guards_total === 0 ? "Setup incomplete" : data.guards_online < data.guards_total ? "Attention required" : "Operational";
  const protection = data?.protection;
  const decisions = protection?.decisions_24h;
  const metrics = data && protection ? [
    ["Verified protection", `${protection.applications_protected_verified}/${protection.applications_registered}`, "Registered applications whose current backend checks pass. This status expires and is never inferred from a mode flag."],
    ["Not verified", protection.applications_not_verified, "Registered applications without current verification. Treat their routes as unprotected."],
    ["Guards online", `${data.guards_online}/${data.guards_total}`, "Enrolled Guards with a recent authenticated heartbeat."],
    ["Sources fresh", `${protection.sources_fresh}/${protection.sources_total}`, "Sources with current permission and directory synchronization."],
    ["Decisions · 24h", decisions?.telemetry === "OBSERVED" ? decisions.total : "NO DATA", decisions?.telemetry === "OBSERVED" ? "Guard-audited Layer 1 and Layer 2 decisions." : "No Guard decisions were recorded. This is not zero risk and not a pass."],
  ] : [];
  return <AppShell><PageHeader eyebrow="OVERVIEW" title="Authorization control plane" description="Monitor how permission changes become safe AI responses." action={<span className="status"><b/>{health}</span>}/>
    {error ? <ErrorState message={error} retry={load}/> : !data ? <Skeleton rows={5}/> : <><section className="grid current-metrics">{metrics.map(([label, value, description]) => <article className="card" key={String(label)}><span className="label">{label}</span><strong>{value}</strong><p className="muted">{description}</p></article>)}</section>
      <section className="card section">
        <div className="panel-head"><div><p className="label">GUARD EVIDENCE</p><h2>Observed decisions and coverage gaps</h2></div><Link className="text-button" href="/protection">View per-application state</Link></div>
        <div className="definition-list">
          <div><span>Layer 1 decisions · 24h</span><b>{decisions?.telemetry === "OBSERVED" ? decisionSummary(decisions.layer1) : "NO DATA"}</b></div>
          <div><span>Layer 2 decisions · 24h</span><b>{decisions?.telemetry === "OBSERVED" ? decisionSummary(decisions.layer2) : "NO DATA"}</b></div>
          <div><span>Latest Guard decision</span><b>{protection?.latest_decision_at ? formatTimestamp(protection.latest_decision_at) : "NO DATA"}</b></div>
          <div><span>Guard health</span><b>{protection ? `${protection.guards.online ?? 0} online · ${protection.guards.offline ?? 0} offline · ${protection.guards.not_enrolled ?? 0} not enrolled · ${protection.guards.revoked ?? 0} revoked` : "NO DATA"}</b></div>
          <div><span>Unsupported adapters</span><b>{protection?.applications_unsupported ?? "NO DATA"}</b></div>
          <div><span>Revocation-to-first-denial timing</span><b>NO DATA</b><small>No measured revocation experiment is attached. Timing is not inferred from configuration or heartbeat data.</small></div>
        </div>
      </section>
      <section className="card section"><span className="label">Protection lifecycle</span><h2>SYNC → RESOLVE → ENFORCE → VERIFY → AUDIT</h2><div className="steps">{[["01", "Permission sources", "Connect authoritative access state"], ["02", "Effective access", "Resolve every direct and group path"], ["03", "AccessProof Guard", "Enforce at the customer boundary"], ["04", "Trusted provenance", "Verify what the model actually used"]].map(([number, title, description]) => <div className="step" key={number}><span>{number}</span><div><b>{title}</b><p className="muted">{description}</p></div></div>)}</div></section><section className="card section"><span className="label">Recent activity</span>{data.recent_activity.length ? <div className="activity-list">{data.recent_activity.map(event => <div className="activity-row" key={event.id}><StatusBadge value={event.type}/><span>{event.summary}</span><small>{formatTimestamp(event.timestamp)}</small></div>)}</div> : <EmptyState title="Your authorization control plane is ready to configure" description="Connect a permission source, synchronize identities and resources, create a Guard, then run the protection integration checks."/>}</section></>}</AppShell>;
}
