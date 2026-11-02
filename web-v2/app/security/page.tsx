import type { Metadata } from "next";
import Link from "next/link";
import { ArrowRight } from "lucide-react";
import { MarketingFooter, MarketingNav } from "../marketing-chrome";

export const metadata: Metadata = {
  title: "Security · AccessProof",
  description: "How AccessProof enforces enterprise permissions on AI answers, where your data lives, and what we can and cannot guarantee.",
};

const sections: Array<{ id: string; title: string; body: React.ReactNode }> = [
  { id: "model", title: "Two independent enforcement layers", body: <>
    <p><b>Layer 1, before the model.</b> Every retrieved document and chunk is checked against the employee&rsquo;s current permissions. Unauthorized content is removed before the model receives any context. A chunk-level grant is never widened to a whole document.</p>
    <p><b>Layer 2, before release.</b> The model&rsquo;s answer is buffered, never streamed early. Every source it used must carry a valid cryptographic attestation from your ingestion pipeline and match what Layer 1 authorized, under the same authorization revision. If permissions change mid-request, the answer is not released.</p>
    <p><b>Shared conversations.</b> When an answer is shown to several people, a document is used only if every participant may read it.</p>
    <p><b>Output safety.</b> Links and images to hosts you haven&rsquo;t approved are removed from answers, so injected instructions can&rsquo;t exfiltrate data through auto-loaded content.</p>
  </> },
  { id: "fail-closed", title: "Fail closed, always", body: <>
    <p>Unknown is treated as deny. If identity can&rsquo;t be verified, a permission source goes stale, the Guard is unreachable, or a check can&rsquo;t run, the request is blocked rather than answered. The Guard keeps enforcing the last verified policy only for a short, bounded window during a control-plane outage, then denies.</p>
  </> },
  { id: "identity", title: "Verified identity", body: <>
    <p>Employees are identified by signed tokens from your identity provider (OIDC, such as Microsoft Entra ID), validated for issuer, audience, signature, expiry and tenant. An email address or user ID supplied in a request is never trusted. Production Guards refuse shared-secret identity.</p>
  </> },
  { id: "data", title: "Where your data lives", body: <>
    <ul>
      <li><b>In your environment:</b> the Guard, the Gateway, your RAG, your vector store, your model and your documents.</li>
      <li><b>In the AccessProof cloud:</b> permission metadata (which identities can access which resources), Guard and Gateway health, and decision audit records. Document content is not required by the control plane.</li>
      <li><b>Tenant isolation:</b> every record is scoped to your organization; cross-tenant access is covered by automated security tests.</li>
      <li><b>Secrets:</b> source credentials are encrypted at rest; machine credentials are stored only as hashes.</li>
    </ul>
  </> },
  { id: "evidence", title: "Evidence, not dashboards", body: <>
    <p>Protection status is derived from real evidence: authenticated heartbeats, authorization revisions and audited Guard decisions. It never comes from a configuration flag. Reports are signed and verifiable, and a Gateway that was installed once is never shown as online without a fresh authenticated heartbeat.</p>
  </> },
  { id: "status", title: "Current certification status", body: <>
    <p>We are transparent about what has been independently verified. Google Drive is generally available. Microsoft SharePoint is in early access: Protect mode is enabled for a SharePoint source only after live, source-specific permission certification for that tenant. AccessProof has not yet completed a third-party security audit such as SOC 2; contact us for our current security documentation.</p>
  </> },
];

export default function SecurityPage() {
  return <main className="marketing">
    <MarketingNav/>
    <section className="page-hero">
      <p className="eyebrow">SECURITY</p>
      <h1>How AccessProof protects your data</h1>
      <p className="lede">AccessProof exists to stop AI assistants from revealing documents people aren&rsquo;t allowed to see. Here is exactly how it works, and its limits.</p>
    </section>
    <div className="doc-layout">
      <nav className="doc-toc" aria-label="On this page">{sections.map(section => <a key={section.id} href={`#${section.id}`}>{section.title}</a>)}</nav>
      <article className="doc-body">{sections.map(section => <section key={section.id} id={section.id}><h2>{section.title}</h2>{section.body}</section>)}
        <p className="section-link"><a href="mailto:admin@accessproof.in?subject=Security%20review">Request our security review package <ArrowRight size={14}/></a></p>
        <p className="section-link"><Link href="/register">Create a workspace <ArrowRight size={14}/></Link></p>
      </article>
    </div>
    <MarketingFooter/>
  </main>;
}
