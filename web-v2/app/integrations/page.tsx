"use client";

import Link from "next/link";
import { ShieldCheck, ArrowRight, Server, Files, LockKeyhole, ClipboardCheck } from "lucide-react";
import { PageHeader } from "../app-shell";
import { ProtectedPage } from "../protected-page";

const steps = [
  { number: "01", title: "Connect Google Workspace", description: "Authorize an approved Google Drive root. Employee identities, groups and file permissions synchronize server-side.", href: "/sources", link: "Connect source", icon: Files },
  { number: "02", title: "Enroll your Guard", description: "Deploy the customer-hosted enforcement engine and verify machine enrollment, heartbeat and policy synchronization.", href: "/guards", link: "Manage Guards", icon: LockKeyhole },
  { number: "03", title: "Deploy AccessProof Gateway", description: "Install the reviewed Docker Gateway beside your RAG service. Supply independently attested retrieval resources and route model traffic through Gateway.", href: "/integrations/setup", link: "Open Gateway setup", icon: Server },
  { number: "04", title: "Verify the real RAG route", description: "Register the application, perform allow/deny/provenance/revocation challenges, approve the customer-side cutover and enable Protect only after all gates pass.", href: "/applications", link: "Register application", icon: ClipboardCheck },
] as const;

export default function GatewayIntegrations() {
  return <ProtectedPage>
    <PageHeader
      eyebrow="CUSTOMER INTEGRATION"
      title="AccessProof Gateway"
      description="A single, security-verified integration path for supported Google Workspace and Google Drive RAG deployments."
      action={<Link className="button compact" href="/integrations/setup">Configure Gateway <ArrowRight size={16} /></Link>}
    />
    <section className="card section" aria-labelledby="gateway-protection-heading">
      <div className="section-head">
        <div><p className="label">PRODUCTION V1</p><h2 id="gateway-protection-heading">One Gateway. Two enforcement layers.</h2></div>
      </div>
      <p className="muted">
        AccessProof Gateway receives a verified employee identity and signed retrieval manifest,
        checks Google Drive authorization with the local Guard before the LLM sees a document,
        and verifies the complete buffered response before releasing it.
        The supported HTTP contract requires no customer-side library installation.
      </p>
      <div className="row wrap">
        <Link className="button compact" href="/integrations/setup">Start Gateway installation</Link>
        <Link className="button compact secondary" href="/protection">View protection status</Link>
      </div>
    </section>
    <section className="card section" aria-labelledby="gateway-steps-heading">
      <div className="section-head">
        <div><p className="label">DEPLOYMENT WORKFLOW</p><h2 id="gateway-steps-heading">Go from permissions to verified protection</h2></div>
      </div>
      <div className="row wrap" style={{ alignItems: "stretch" }}>
        {steps.map(({ number, title, description, href, link, icon: Icon }) =>
          <div className="card" key={number} style={{ flex: "1 1 230px", padding: 20, minWidth: 220 }}>
            <p className="label">{number} · <Icon size={15} aria-hidden="true" /></p>
            <h3>{title}</h3>
            <p className="muted">{description}</p>
            <Link href={href} className="button compact secondary">{link} <ArrowRight size={14} /></Link>
          </div>
        )}
      </div>
    </section>
    <section className="card section" aria-labelledby="gateway-boundary-heading">
      <div className="section-head">
        <div><p className="label">SECURITY BOUNDARY</p><h2 id="gateway-boundary-heading"><ShieldCheck size={18} aria-hidden="true" /> Protection is verified per route</h2></div>
      </div>
      <p className="muted">
        A transparent model proxy cannot independently discover hidden vector-store results,
        caches, tools, or other return paths. Gateway requires signed source provenance and a
        supported, reviewed deployment contract. Native token streaming, WebSocket routes,
        autonomous agent actions and arbitrary unobserved RAG paths are not certified.
      </p>
      <p className="muted small">
        Only an enrolled, challenged customer route can become verified. Unknown permission
        state, stale Guard policy, incomplete route checks and missing provenance must block Protect.
      </p>
    </section>
  </ProtectedPage>;
}
