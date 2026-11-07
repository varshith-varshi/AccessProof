import Link from "next/link";
import {
  ArrowRight, BadgeCheck, Ban, CheckCircle2, Database, FileLock2, Fingerprint, History, Link2Off, Network,
  ScrollText, ShieldCheck, Users, XCircle,
} from "lucide-react";
import { MarketingFooter, MarketingNav } from "./marketing-chrome";

const features = [
  { icon: Ban, title: "Blocks restricted files before the AI sees them",
    copy: "Layer 1 checks retrieved resources against synchronized, source-bound authorization state before the model receives context." },
  { icon: BadgeCheck, title: "Verifies the answer before release",
    copy: "Layer 2 checks the cryptographic provenance of recorded source inputs before releasing a buffered answer through the protected route." },
  { icon: History, title: "Revocation follows your source of truth",
    copy: "Permission changes become enforceable after the authoritative source is synchronized. Stale or unknown authorization state cannot produce a verified allow." },
  { icon: Users, title: "Safe in shared chats",
    copy: "When an assistant answers a group chat or channel, it only uses documents every participant is allowed to read." },
  { icon: Link2Off, title: "Reduces link-based exfiltration risk",
    copy: "The configured output policy filters unsafe link and image destinations from protected answers; this does not replace broader prompt-injection defenses." },
  { icon: ScrollText, title: "Evidence your auditors can verify",
    copy: "Guard decisions carry the policy and authorization revision that produced them. Signed evidence reports are available for recorded, supported flows." },
];

const setup = [
  { n: "1", title: "Connect Microsoft SharePoint", copy: "Grant the approved Microsoft Graph permissions and select the pilot site. AccessProof synchronizes supported permission grants and directory identities, then validates effective access during the pilot." },
  { n: "2", title: "Install Guard and Gateway", copy: "Use the reviewed customer-hosted installer, keeping the RAG private and verifying Guard and Gateway connectivity." },
  { n: "3", title: "Integrate the supported Gateway contract", copy: "Connect a reviewed RAG route that supplies verified identity and complete, signed retrieval provenance." },
  { n: "4", title: "Verify, approve, then protect", copy: "Run source, identity, allow/deny, provenance and route challenges. Protect remains unavailable until current checks and customer approval pass." },
];

const faqs = [
  { q: "What problem does AccessProof solve?", a: "It adds an authorization boundary around supported enterprise RAG routes so broad indexing access does not automatically become an employee's answer access." },
  { q: "Do our documents leave our network?", a: "In the supported customer-hosted deployment, the Guard, Gateway, RAG and document content remain in the customer environment. The control plane receives permission metadata, health state and decision evidence. Pilot architecture and data flows are reviewed before installation." },
  { q: "Do we need to rebuild our RAG application?", a: "Your RAG must implement the supported Gateway contract and provide complete retrieval provenance. Whether that is a configuration change or an adapter change depends on the existing application; AccessProof verifies the real route before Protect can activate." },
  { q: "What happens if AccessProof is unavailable?", a: "Protected routes fail closed when required identity, policy, source freshness, Guard or provenance checks are unavailable. A bounded last-known-good policy may be used only under the configured and verified offline policy." },
  { q: "Can't we just tell the model not to reveal restricted documents?", a: "Instructions to a model are probabilistic and can be bypassed with prompt injection. AccessProof removes unauthorized documents before the model ever sees them and verifies the answer before release." },
  { q: "Does SharePoint group and inherited access work?", a: "The Microsoft connector resolves supported direct, group-derived and inherited access paths. Each pilot validates the customer's selected site and permission patterns; AccessProof does not claim universal compatibility with every SharePoint configuration." },
  { q: "What happens when SharePoint synchronization fails?", a: "The source is reported stale or degraded. A protected route cannot use unknown or stale source state as a verified allow, and the product shows the administrator the failed synchronization prerequisite." },
  { q: "Does AccessProof store employee passwords?", a: "No. Employees authenticate through the configured identity provider. AccessProof validates signed identity tokens and does not ask administrators to enter employee Microsoft passwords." },
  { q: "Which deployment environments are supported?", a: "The current guided pilot uses the reviewed customer-hosted Docker deployment for Guard and Gateway. The exact RAG topology, networking and route contract are checked during pilot scoping and installation." },
  { q: "Which systems are included in the launch pilot?", a: "The initial guided pilot is Microsoft SharePoint with Microsoft Entra identity and a reviewed customer RAG route. Other connectors and model configurations are evaluated against their implemented adapter contract; listing an integration does not certify a customer route." },
  { q: "How do we prove it works?", a: "AccessProof runs source, identity, allow/deny, provenance and customer-route challenges. The product reports missing evidence as unverified, and The product distinguishes Protect active with validation pending from independently verified protection; customer-specific certification is required for a verified result." },
];

export default function Home() {
  return <main className="marketing">
    <MarketingNav/>
    <section className="hero">
      <div className="hero-copy">
        <p className="eyebrow">PERMISSION-SAFE ENTERPRISE AI</p>
        <h1>Make enterprise AI respect enterprise permissions.</h1>
        <p className="lede">AccessProof helps a SharePoint-backed enterprise AI use only resources the verified employee is authorized to read. It checks retrieved context before the model and verifies complete provenance before a protected answer is released.</p>
        <div className="hero-actions">
          <a className="button" href="mailto:admin@accessproof.in?subject=AccessProof%20guided%20pilot">Request a pilot <ArrowRight size={16}/></a>
          <Link className="button secondary" href="/register">Create workspace</Link>
        </div>
        <div className="trust-row">
          <span><CheckCircle2 size={15}/>Runs in your environment</span>
          <span><CheckCircle2 size={15}/>Reviewed RAG integration contract</span>
          <span><CheckCircle2 size={15}/>Protected routes fail closed</span>
        </div>
      </div>
      <div className="example-card" role="img" aria-label="Example: Bob asks about a finance plan he cannot open; AccessProof removes it before the model and answers only from documents Bob can read">
        <div className="example-head"><ShieldCheck size={18}/><b>What happens when Bob asks</b><span>Protect</span></div>
        <div className="example-question">&ldquo;Summarize the Q3 plans for me.&rdquo; <small>Bob · Engineering</small></div>
        <ul className="example-docs">
          <li className="denied"><XCircle size={16}/><span><b>Q3 finance plan.docx</b><small>Bob can&rsquo;t open this in SharePoint</small></span><em>Removed before the AI</em></li>
          <li className="allowed"><CheckCircle2 size={16}/><span><b>Q3 engineering roadmap.docx</b><small>Bob has access</small></span><em>Used</em></li>
          <li className="allowed"><CheckCircle2 size={16}/><span><b>Company all-hands notes</b><small>Shared with everyone</small></span><em>Used</em></li>
        </ul>
        <div className="example-foot"><FileLock2 size={15}/>Answer verified against its sources, then released to Bob.</div>
      </div>
    </section>

    <section className="problem-section">
      <p className="eyebrow">THE SECURITY GAP</p>
      <h2>A broad indexing identity can outlive an employee&rsquo;s permission.</h2>
      <p>Many RAG systems index content with a service identity and do not independently enforce the requesting employee&rsquo;s effective permission at retrieval and release time. AccessProof adds a verifiable authorization boundary for supported routes.</p>
    </section>

    <section id="product" className="marketing-section">
      <div className="section-intro"><p className="eyebrow">WHAT YOU GET</p><h2>Authorization enforced on every answer.</h2></div>
      <div className="feature-grid">{features.map(({ icon: Icon, title, copy }) => <article key={title}><Icon size={20}/><h3>{title}</h3><p>{copy}</p></article>)}</div>
    </section>

    <section id="how" className="marketing-section alt">
      <div className="section-intro"><p className="eyebrow">HOW IT WORKS</p><h2>A guided path from source permissions to a verified route.</h2></div>
      <div className="process-grid">{setup.map(step => <article key={step.n}><span>{step.n.padStart(2, "0")}</span><h3>{step.title}</h3><p>{step.copy}</p></article>)}</div>
      <div id="integrations" className="integrations">
        <div><b>Launch pilot</b><span className="chip">Microsoft SharePoint</span><span className="chip">Microsoft Entra ID</span></div>
        <div><b>RAG boundary</b><span className="chip">AccessProof Gateway HTTP contract</span><span className="chip">Signed retrieval provenance</span></div>
        <div><b>Deployment</b><span className="chip">Customer-hosted Guard and Gateway</span><span className="chip">Guided verification</span></div>
      </div>
    </section>

    <section className="marketing-section architecture-section">
      <div className="section-intro"><p className="eyebrow">ARCHITECTURE</p><h2>Control-plane evidence. Customer-side enforcement.</h2></div>
      <div className="architecture-flow" aria-label="AccessProof architecture flow">
        <article><span>1</span><h3>Employee + Entra</h3><p>The RAG receives a cryptographically verified employee identity.</p></article>
        <ArrowRight aria-hidden="true"/>
        <article><span>2</span><h3>Gateway + Guard</h3><p>Layer 1 authorizes retrieved resources using synchronized SharePoint state.</p></article>
        <ArrowRight aria-hidden="true"/>
        <article><span>3</span><h3>Customer RAG + model</h3><p>The model receives authorized context and returns a buffered response with provenance.</p></article>
        <ArrowRight aria-hidden="true"/>
        <article><span>4</span><h3>Release verification</h3><p>Layer 2 verifies the complete source set and authorization revision before release.</p></article>
      </div>
      <p className="architecture-note">The AccessProof control plane synchronizes permission metadata, distributes signed policy, monitors authenticated health and records decision evidence. It does not infer protection from installation status.</p>
    </section>

    <section id="guard" className="split-section">
      <div><p className="eyebrow">ACCESSPROOF GUARD</p><h2>Prove it on real traffic before you enforce.</h2>
        <p>The Guard receives signed, versioned policy and evaluates every request beside your AI application. Start in Shadow to see what would be blocked, with no change to your users, then switch to Protect when you&rsquo;re ready.</p></div>
      <div className="mode-panel">
        <article><span>SHADOW</span><h3>Measure safely</h3><p>See every would-be block on live traffic without changing a single answer.</p></article>
        <article className="protect"><span>PROTECT</span><h3>Enforce authorization</h3><p>Withhold unauthorized documents and unsafe output, with evidence for every decision.</p></article>
      </div>
    </section>

    <section id="security" className="security-section">
      <div className="section-intro"><p className="eyebrow">SECURITY BY DESIGN</p><h2>Built for the enterprise boundary.</h2></div>
      <div className="security-grid">
        <article><Fingerprint/><h3>Verified identity</h3><p>Decisions use signed employee identity from your identity provider, never an email typed into a request.</p></article>
        <article><Database/><h3>Synchronized permissions</h3><p>Access comes from your source of truth, including groups and inherited permissions, and expires when sync goes stale.</p></article>
        <article><Network/><h3>Customer-side enforcement</h3><p>Guard and Gateway run in your network. Your model and documents stay where they are.</p></article>
      </div>
      <p className="section-link"><Link href="/security">Read how AccessProof protects your data <ArrowRight size={14}/></Link></p>
    </section>

    <section id="pilot" className="marketing-section pilot-section">
      <div><p className="eyebrow">GUIDED PILOT</p><h2>Prove one real SharePoint authorization boundary.</h2><p>We scope one SharePoint source, one Entra tenant and one customer RAG route. The pilot includes architecture review, Guard and Gateway installation, employee allow/deny permission challenges, provenance verification and a written readiness result. Commercial terms are confirmed after technical scoping.</p></div>
      <ul><li><CheckCircle2 size={16}/>Customer-approved site scope and identities</li><li><CheckCircle2 size={16}/>Shadow evidence before any Protect cutover</li><li><CheckCircle2 size={16}/>Explicit limitations and administrator actions</li></ul>
      <a className="button" href="mailto:admin@accessproof.in?subject=AccessProof%20guided%20pilot">Request a pilot <ArrowRight size={16}/></a>
    </section>

    <section id="faq" className="marketing-section alt">
      <div className="section-intro"><p className="eyebrow">FAQ</p><h2>Questions security teams ask us.</h2></div>
      <div className="faq-list">{faqs.map(item => <details key={item.q}><summary>{item.q}</summary><p>{item.a}</p></details>)}</div>
    </section>

    <section className="cta">
      <p className="eyebrow light">GET STARTED</p>
      <h2>Validate the authorization boundary before Protect.</h2>
      <p>Start with a scoped SharePoint pilot and a reviewed RAG route. AccessProof keeps incomplete evidence visibly unverified.</p>
      <div className="hero-actions center"><a className="button light-button" href="mailto:admin@accessproof.in?subject=AccessProof%20guided%20pilot">Request a pilot <ArrowRight size={16}/></a>
        <Link className="button ghost-light" href="/register">Create workspace</Link></div>
    </section>
    <MarketingFooter/>
  </main>;
}
