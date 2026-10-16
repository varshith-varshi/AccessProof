"use client";

import { useEffect, useState } from "react";
import { EmptyState, ErrorState, Skeleton, StatusBadge } from "../../components/ui";
import { api, CurrentDashboard } from "../../lib/api";
import { formatTimestamp } from "../../lib/format";
import { AppShell, PageHeader } from "../app-shell";

export default function Dashboard() {
  const [data, setData] = useState<CurrentDashboard | null>(null);
  const [error, setError] = useState("");
  async function load() { setError(""); try { setData(await api<CurrentDashboard>("/api/v1/current/dashboard")); } catch (cause) { setError(cause instanceof Error ? cause.message : "Unable to load the authorization overview."); } }
  useEffect(() => { queueMicrotask(() => void load()); }, []);
  const health = !data ? "Loading status" : data.guards_total === 0 ? "Setup incomplete" : data.guards_online < data.guards_total ? "Attention required" : "Operational";
  const metrics = data ? [["AI applications", data.ai_applications, "Applications with recorded Guard decisions."], ["Guards online", `${data.guards_online}/${data.guards_total}`, "Based on recent Guard heartbeats."], ["Permission sources", data.permission_sources, "Authoritative sources connected to this organization."], ["Blocked requests", data.blocked_requests, "Layer 1 or Layer 2 blocks recorded by Guards."]] : [];
  return <AppShell><PageHeader eyebrow="OVERVIEW" title="Authorization control plane" description="Monitor how permission changes become safe AI responses." action={<span className="status"><b/>{health}</span>}/>
    {error ? <ErrorState message={error} retry={load}/> : !data ? <Skeleton rows={5}/> : <><section className="grid current-metrics">{metrics.map(([label, value, description]) => <article className="card" key={String(label)}><span className="label">{label}</span><strong>{value}</strong><p className="muted">{description}</p></article>)}</section><section className="card section"><span className="label">Protection lifecycle</span><h2>SYNC → RESOLVE → ENFORCE → VERIFY → AUDIT</h2><div className="steps">{[["01", "Permission sources", "Connect authoritative access state"], ["02", "Effective access", "Resolve every direct and group path"], ["03", "AccessProof Guard", "Enforce at the customer boundary"], ["04", "Trusted provenance", "Verify what the model actually used"]].map(([number, title, description]) => <div className="step" key={number}><span>{number}</span><div><b>{title}</b><p className="muted">{description}</p></div></div>)}</div></section><section className="card section"><span className="label">Recent activity</span>{data.recent_activity.length ? <div className="activity-list">{data.recent_activity.map(event => <div className="activity-row" key={event.id}><StatusBadge value={event.type}/><span>{event.summary}</span><small>{formatTimestamp(event.timestamp)}</small></div>)}</div> : <EmptyState title="Your authorization control plane is ready to configure" description="Connect a permission source, synchronize identities and resources, create a Guard, then begin in Shadow mode."/>}</section></>}</AppShell>;
}
