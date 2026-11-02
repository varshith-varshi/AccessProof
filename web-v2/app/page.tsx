import Link from "next/link";
import {
  ArrowRight, BadgeCheck, Ban, CheckCircle2, Database, FileLock2, Fingerprint, History, Link2Off, Network,
  ScrollText, ShieldCheck, Users, XCircle,
} from "lucide-react";
import { MarketingFooter, MarketingNav } from "./marketing-chrome";

const features = [
  { icon: Ban, title: "Blocks restricted files before the AI sees them",
    copy: "Layer 1 removes every document the employee cannot open in SharePoint or Google Drive before the model receives any context." },
  { icon: BadgeCheck, title: "Verifies the answer before release",
    copy: "Layer 2 checks the cryptographic provenance of every source the model used, then releases a buffered answer. No early tokens leak." },
  { icon: History, title: "Revocation follows your source of truth",
    copy: "Remove access in SharePoint or Drive and AccessProof picks it up automatically. Cached answers are re-checked, and an answer whose permissions change mid-request is never released." },
  { icon: Users, title: "Safe in shared chats",
    copy: "When an assistant answers a group chat or channel, it only uses documents every participant is allowed to read." },
  { icon: Link2Off, title: "Stops zero-click data exfiltration",
    copy: "Hidden instructions in a document can't smuggle data out through auto-loading images or link previews." },
  { icon: ScrollText, title: "Evidence your auditors can verify",
    copy: "Every allow and deny is recorded with the policy and authorization revision that produced it, exportable as signed reports." },
];

const setup = [
  { n: "1", title: "Connect your permission source", copy: "Approve read-only access to SharePoint or Google Drive. AccessProof syncs who can open what." },
  { n: "2", title: "Install the Guard", copy: "One container in your environment makes every allow/deny decision locally, even if our cloud is unreachable." },
  { n: "3", title: "Route your chatbot through the Gateway", copy: "Keep your existing RAG and model. The installer finds your chatbot and adds the Gateway without exposing it." },
  { n: "4", title: "Verify, then protect", copy: "Start in Shadow mode to see what would be blocked, then switch to Protect once checks pass." },
];

const plans = [
  { name: "Design partner", price: "Pilot", copy: "For teams validating permission-safe AI on one chatbot.",
    items: ["1 AI application", "1 permission source", "Shadow and Protect modes", "Guided onboarding with our engineers"], cta: "Apply for a pilot", href: "mailto:admin@accessproof.in?subject=AccessProof%20pilot" },
  { name: "Team", price: "Contact us", featured: true, copy: "For production assistants serving a department.",
    items: ["Up to 5 AI applications", "SharePoint and Google Drive", "Shared-chat protection", "Signed audit reports", "Email support"], cta: "Start free", href: "/register" },
  { name: "Enterprise", price: "Custom", copy: "For organization-wide AI with strict compliance needs.",
    items: ["Unlimited applications", "SSO, SCIM and role-based access", "Dedicated support and security review", "Custom data retention"], cta: "Talk to sales", href: "mailto:admin@accessproof.in?subject=AccessProof%20Enterprise" },
];

const faqs = [
  { q: "Do our documents leave our network?", a: "No document content needs to leave your environment. The Guard and Gateway run in your infrastructure and enforce decisions locally. The AccessProof cloud stores permission metadata (who can access which resource) and decision audit records." },
  { q: "Do we need to rebuild our RAG application?", a: "No. AccessProof sits in front of the chatbot you already have. You keep your retriever, vector store and model; the Gateway enforces authorization around them." },
  { q: "What happens if AccessProof is unavailable?", a: "Enforcement fails closed. The Guard keeps enforcing the last verified policy for a short, bounded window, then denies rather than guessing. Restricted content is never released because a check could not run." },
  { q: "Can't we just tell the model not to reveal restricted documents?", a: "Instructions to a model are probabilistic and can be bypassed with prompt injection. AccessProof removes unauthorized documents before the model ever sees them and verifies the answer before release." },
  { q: "Which systems do you support?", a: "Google Drive is generally available. Microsoft SharePoint is in early access with live permission certification. Models: any OpenAI-compatible API, Anthropic and Google Gemini, deployed with Docker Compose." },
  { q: "How do we prove it works?", a: "Shadow mode shows exactly what would be blocked on real traffic before you enforce anything, and every decision is exportable as signed evidence for your security team." },
];

export default function Home() {
  return <main className="marketing">
    <MarketingNav/>
    <section className="hero">
      <div className="hero-copy">
        <p className="eyebrow">PERMISSION-SAFE ENTERPRISE AI</p>
        <h1>Make enterprise AI respect enterprise permissions.</h1>
        <p className="lede">Your AI assistant can read everything in SharePoint and Google Drive. Your employees can&rsquo;t. AccessProof makes sure every answer only uses documents the person asking is allowed to open: before the model sees them, and again before the answer is released.</p>
        <div className="hero-actions">
          <Link className="button" href="/register">Start free <ArrowRight size={16}/></Link>
          <a className="button secondary" href="mailto:admin@accessproof.in?subject=AccessProof%20demo">Book a demo</a>
        </div>
        <div className="trust-row">
          <span><CheckCircle2 size={15}/>Runs in your environment</span>
          <span><CheckCircle2 size={15}/>Works with your existing RAG</span>
          <span><CheckCircle2 size={15}/>Fails closed</span>
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
      <h2>Your AI assistant is the most over-privileged employee you have.</h2>
      <p>RAG chatbots index documents with a service account that can read everything. Without enforcement, anyone who asks the right question can get answers from files they were never allowed to open, and keep getting them after their access is revoked.</p>
    </section>

    <section id="product" className="marketing-section">
      <div className="section-intro"><p className="eyebrow">WHAT YOU GET</p><h2>Authorization enforced on every answer.</h2></div>
      <div className="feature-grid">{features.map(({ icon: Icon, title, copy }) => <article key={title}><Icon size={20}/><h3>{title}</h3><p>{copy}</p></article>)}</div>
    </section>

    <section id="how" className="marketing-section alt">
      <div className="section-intro"><p className="eyebrow">HOW IT WORKS</p><h2>Protected in four steps, without rebuilding your RAG.</h2></div>
      <div className="process-grid">{setup.map(step => <article key={step.n}><span>{step.n.padStart(2, "0")}</span><h3>{step.title}</h3><p>{step.copy}</p></article>)}</div>
      <div className="integrations">
        <div><b>Permission sources</b><span className="chip">Google Drive</span><span className="chip">SharePoint <em>early access</em></span></div>
        <div><b>Models</b><span className="chip">OpenAI-compatible</span><span className="chip">Anthropic</span><span className="chip">Google Gemini</span></div>
        <div><b>Deployment</b><span className="chip">Docker Compose</span><span className="chip">Your VPC or data center</span></div>
      </div>
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
        <article><Database/><h3>Live permissions</h3><p>Access comes from your source of truth, including groups and inherited permissions, and expires when sync goes stale.</p></article>
        <article><Network/><h3>Customer-side enforcement</h3><p>Guard and Gateway run in your network. Your model and documents stay where they are.</p></article>
      </div>
      <p className="section-link"><Link href="/security">Read how AccessProof protects your data <ArrowRight size={14}/></Link></p>
    </section>

    <section id="pricing" className="marketing-section">
      <div className="section-intro"><p className="eyebrow">PRICING</p><h2>Start with one chatbot. Scale to the whole company.</h2></div>
      <div className="pricing-grid">{plans.map(plan => <article key={plan.name} className={plan.featured ? "featured" : ""}>
        {plan.featured && <span className="badge">Most popular</span>}
        <h3>{plan.name}</h3><p className="price">{plan.price}</p><p className="muted">{plan.copy}</p>
        <ul>{plan.items.map(item => <li key={item}><CheckCircle2 size={14}/>{item}</li>)}</ul>
        {plan.href.startsWith("/") ? <Link className={`button ${plan.featured ? "" : "secondary"}`} href={plan.href}>{plan.cta}</Link>
          : <a className={`button ${plan.featured ? "" : "secondary"}`} href={plan.href}>{plan.cta}</a>}
      </article>)}</div>
    </section>

    <section id="faq" className="marketing-section alt">
      <div className="section-intro"><p className="eyebrow">FAQ</p><h2>Questions security teams ask us.</h2></div>
      <div className="faq-list">{faqs.map(item => <details key={item.q}><summary>{item.q}</summary><p>{item.a}</p></details>)}</div>
    </section>

    <section className="cta">
      <p className="eyebrow light">GET STARTED</p>
      <h2>Ship enterprise AI your security team will approve.</h2>
      <p>Create a workspace, connect a source and see what your assistant would block, in Shadow mode on your own traffic.</p>
      <div className="hero-actions center"><Link className="button light-button" href="/register">Start free <ArrowRight size={16}/></Link>
        <a className="button ghost-light" href="mailto:admin@accessproof.in?subject=AccessProof%20pilot">Request a pilot</a></div>
    </section>
    <MarketingFooter/>
  </main>;
}
