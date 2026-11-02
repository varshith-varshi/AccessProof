"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { ArrowRight, CheckCircle2, Circle } from "lucide-react";
import { EmptyState, ErrorState, Skeleton, StatusBadge } from "../../components/ui";
import { api, CurrentDashboard, ProtectionDecisionBucket } from "../../lib/api";
import { formatTimestamp } from "../../lib/format";
import { AppShell, PageHeader } from "../app-shell";

function decisionSummary(bucket: ProtectionDecisionBucket | null | undefined) {
  if (!bucket) return "NO DATA";
  return `${bucket.allow} allow · ${bucket.block} block · ${bucket.would_allow} would allow · ${bucket.would_block} would block`;
}

type SetupStep = { title: string; detail: string; done: boolean; href: string; cta: string };

function setupSteps(data: CurrentDashboard): SetupStep[] {
  const p = data.protection;
  return [
    { title: "Connect a permission source", detail: "Link SharePoint or Google Drive so AccessProof knows who can read what.",
      done: data.permission_sources > 0, href: "/sources", cta: "Connect source" },
    { title: "Install a Guard", detail: "The Guard runs next to your AI app and makes every allow/deny decision locally.",
      done: data.guards_total > 0 && data.guards_online > 0, href: "/guards", cta: data.guards_total > 0 ? "Check Guard" : "Install Guard" },
    { title: "Register your AI application", detail: "Tell AccessProof which chatbot to protect and which source it answers from.",
      done: data.ai_applications > 0, href: "/applications", cta: "Add application" },
    { title: "Connect the Gateway and verify", detail: "Route your chatbot through the Gateway, then let AccessProof verify protection end to end.",
      done: p.applications_protected_verified > 0, href: "/onboarding", cta: "Open guided setup" },
  ];
}

function SetupChecklist({ data }: { data: CurrentDashboard }) {
  const steps = setupSteps(data);
  const complete = steps.filter(step => step.done).length;
  const next = steps.find(step => !step.done);
  if (!next) return null;
  return <section className="card setup-checklist" aria-labelledby="setup-heading">
    <div className="setup-head">
      <div><p className="label">GET PROTECTED</p><h2 id="setup-heading">Finish setting up protection</h2>
        <p className="muted">{complete} of {steps.length} steps complete. Until the last step passes, treat your AI application as unprotected.</p></div>
      <Link className="button compact" href={next.href}>Continue setup<ArrowRight size={15}/></Link>
    </div>
    <div className="progress" role="progressbar" aria-valuemin={0} aria-valuemax={steps.length} aria-valuenow={complete} aria-label="Setup progress">
      <span style={{ width: `${(complete / steps.length) * 100}%` }}/>
    </div>
    <ol className="checklist-steps">{steps.map(step => <li key={step.title} className={step.done ? "done" : step === next ? "current" : ""}>
      {step.done ? <CheckCircle2 size={18} aria-label="Done"/> : <Circle size={18} aria-label="Not done"/>}
      <div><b>{step.title}</b><p className="muted">{step.detail}</p></div>
      {!step.done && <Link className="text-button" href={step.href}>{step.cta}<ArrowRight size={13}/></Link>}
    </li>)}</ol>
  </section>;
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
  return <AppShell><PageHeader eyebrow="OVERVIEW" title="Authorization control plane" description="See whether your AI applications are protected, and what AccessProof has allowed or blocked." action={<span className="status"><b/>{health}</span>}/>
    {error ? <ErrorState message={error} retry={load}/> : !data ? <Skeleton rows={5}/> : <><SetupChecklist data={data}/><section className="grid current-metrics">{metrics.map(([label, value, description]) => <article className="card" key={String(label)}><span className="label">{label}</span><strong>{value}</strong><p className="muted">{description}</p></article>)}</section>
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
      <section className="card section"><span className="label">Recent activity</span>{data.recent_activity.length ? <div className="activity-list">{data.recent_activity.map(event => <div className="activity-row" key={event.id}><StatusBadge value={event.type}/><span>{event.summary}</span><small>{formatTimestamp(event.timestamp)}</small></div>)}</div> : <EmptyState title="No activity yet" description="Permission changes, Guard decisions and blocked requests will appear here as soon as your first source and Guard are connected."/>}</section></>}</AppShell>;
}
