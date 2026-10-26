"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { PageHeader } from "../../app-shell";
import { ProtectedPage } from "../../protected-page";

type Cache = "redis" | "memcached" | "postgresql" | "none";
type ModelProvider = "openai-compatible" | "anthropic" | "gemini";
type Step = "prepare" | "inspect" | "stage" | "install" | "verify" | "cutover";

const steps: Array<{ id: Step; title: string; description: string }> = [
  { id: "prepare", title: "Connect", description: "Register one source, an enrolled Guard, and your application." },
  { id: "inspect", title: "Inspect", description: "Detect compatible Docker RAG routing and cache configuration." },
  { id: "stage", title: "Stage", description: "Generate private installation files. No customer traffic changes." },
  { id: "install", title: "Install", description: "Start Gateway only after approval; RAG traffic stays unchanged." },
  { id: "verify", title: "Verify", description: "Run enrolled-machine positive, negative, forgery, and revocation checks." },
  { id: "cutover", title: "Protect", description: "Approve route cutover and re-test employee-facing traffic." },
];

const fixedSpec = "--spec ./accessproof-install-spec.json --compose ./compose.yml --output ./.accessproof-gateway";
const tool = "python -m apps.gateway.accessproof_gateway.integration_wizard";

export default function IntegrationSetup() {
  const [cache, setCache] = useState<Cache>("redis");
  const [modelProvider, setModelProvider] = useState<ModelProvider>("openai-compatible");
  const [step, setStep] = useState<Step>("prepare");
  const [copied, setCopied] = useState("");
  const [approved, setApproved] = useState(false);
  const [approveCutover, setApproveCutover] = useState(false);
  const chosen = steps.find((item) => item.id === step) ?? steps[0];
  const commands = useMemo(() => ({
    inspect: `${tool} plan ${fixedSpec}`,
    stage: `${tool} stage ${fixedSpec}`,
    install: `${tool} install ${fixedSpec} --approve-gateway-install`,
    verify: `${tool} verify ${fixedSpec} --challenge ./challenge.json --guard-credentials ./enrolled-guard.json --receipt ./verify-result.json`,
    cutover: `${tool} cutover ${fixedSpec} --challenge ./challenge.json --guard-credentials ./enrolled-guard.json --employee-route-probe ./employee-probe.json --approve-route-cutover --receipt ./cutover-result.json`,
  }), []);
  const modelDetails: Record<ModelProvider, { endpoint: string; name: string; credential: string; description: string }> = {
    "openai-compatible": {
      endpoint: "http://model:8000/v1/chat/completions",
      name: "local-model", credential: "",
      description: "An OpenAI-compatible HTTP model API, including many self-hosted Llama, Mistral or DeepSeek servers.",
    },
    anthropic: {
      endpoint: "https://api.anthropic.com/v1/messages",
      name: "REPLACE_WITH_CLAUDE_MODEL_ID", credential: "ANTHROPIC_CUSTOMER_KEY",
      description: "The official Anthropic Messages API. The model and the API key are selected by the customer.",
    },
    gemini: {
      endpoint: "https://generativelanguage.googleapis.com/v1beta/models/REPLACE_WITH_GEMINI_MODEL_ID:generateContent",
      name: "REPLACE_WITH_GEMINI_MODEL_ID", credential: "GEMINI_CUSTOMER_KEY",
      description: "The official Gemini GenerateContent API. Keep the model ID in the URL and model_name identical.",
    },
  };
  const cacheDetails: Record<Cache, string> = {
    redis: "Redis: configure ACCESSPROOF_DEMO_CACHE_BACKEND=redis and ACCESSPROOF_DEMO_CACHE_URL on the customer RAG. Signed cache hits must be reauthorized.",
    memcached: "Memcached: configure ACCESSPROOF_DEMO_CACHE_BACKEND=memcached and ACCESSPROOF_DEMO_CACHE_MEMCACHED_HOST on the customer RAG.",
    postgresql: "PostgreSQL: configure ACCESSPROOF_DEMO_CACHE_BACKEND=postgresql and a dedicated SQLAlchemy URL. The approved cache table must be provisioned separately.",
    none: "No answer cache: the RAG must still route retrieved source context and every generated answer through both Guard layers.",
  };
  const cacheSupport: Record<Cache, { label: string; tone: string; evidence: string; production: string }> = {
    redis: {
      label: "Reference adapter",
      tone: "warning",
      evidence: "Exercised by the opt-in signed Docker reference smoke against a real Redis service. That smoke is not part of CI.",
      production: "Not certified by this selection. The customer deployment must prove every cache return path is intercepted and reauthorized.",
    },
    memcached: {
      label: "Reference adapter",
      tone: "warning",
      evidence: "A real-service smoke path exists in scripts/signed_reference_docker_smoke.py but is opt-in and not run in CI.",
      production: "Not certified by this selection. Customer return-path interception, pooling behavior, and revocation must be proven in the target deployment.",
    },
    postgresql: {
      label: "Reference adapter",
      tone: "warning",
      evidence: "A real-service smoke path exists in scripts/signed_reference_docker_smoke.py but is opt-in and not run in CI. The customer must provision the signed cache table explicitly.",
      production: "Not certified by this selection. Customer schema provisioning, return-path interception, and revocation must be proven in the target deployment.",
    },
    none: {
      label: "No cache reuse",
      tone: "neutral",
      evidence: "No answer-cache return path exists to reauthorize, but retrieval and generated answers still require Guard Layer 1 and Layer 2.",
      production: "Choosing no cache does not certify the RAG route or its model integration.",
    },
  };
  const command = step === "prepare" ? null : commands[step];

  async function copy(value: string) {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(step);
    } catch {
      setCopied("blocked");
    }
  }
  return <ProtectedPage>
    <PageHeader eyebrow="CUSTOMER INTEGRATION" title="Deploy AccessProof Gateway" description="For reviewed Docker Compose RAG deployments with signed retrieval provenance. The customer-side installer prepares a Gateway, while a separate enrolled-machine test must approve actual protection." action={<Link href="/integrations" className="button compact secondary">Back to integrations</Link>}/>
    <section className="card section">
      <div className="panel-head">
        <div><p className="label">SUPPORTED DEPLOYMENT</p><h2>Choose your cache backend</h2></div>
        <span className="status-badge warning">Reference Docker RAG only</span>
      </div>
      <p className="muted small">Cache selection changes how signed answers are stored, not their authorization rules. Existing arbitrary RAG routes cannot be certified by cache selection alone.</p>
      <label style={{ maxWidth: 360 }}>Answer cache
        <select aria-label="Answer cache backend" value={cache} onChange={(event) => setCache(event.target.value as Cache)}>
          <option value="redis">Redis — reference adapter</option><option value="memcached">Memcached — reference adapter</option><option value="postgresql">PostgreSQL — reference adapter</option><option value="none">No answer cache</option>
        </select>
      </label>
      <p className="muted small">{cacheDetails[cache]}</p>
      <div className="definition-list" aria-label="Cache backend support status">
        <div><span>Backend support</span><span className={`status-badge ${cacheSupport[cache].tone}`}>{cacheSupport[cache].label}</span></div>
        <div><span>Reference evidence</span><span className="table-muted small">{cacheSupport[cache].evidence}</span></div>
        <div><span>Production status</span><span className="table-muted small">{cacheSupport[cache].production}</span></div>
      </div>
      <p className="alert warning-alert small">Selecting a backend is a configuration choice, not evidence of coverage. No cache option grants Protect or certifies an arbitrary RAG route.</p>
      {cache !== "none" && <p className="alert warning-alert small">Before Protect, the customer RAG must declare the <code>com.accessproof.cache.return_path=signed-manifest-guard-reauthorization/v1</code> contract and prove that every supported answer-cache return path is intercepted.</p>}
    </section>

    <section className="card section" aria-labelledby="model-setup-heading">
      <div className="panel-head"><div><p className="label">MODEL INTEGRATION</p><h2 id="model-setup-heading">Choose the customer&apos;s LLM API</h2></div></div>
      <label style={{ maxWidth: 400 }}>LLM API protocol
        <select aria-label="LLM API provider" value={modelProvider}
          onChange={(event) => setModelProvider(event.target.value as ModelProvider)}>
          <option value="openai-compatible">OpenAI-compatible (including local/custom models)</option>
          <option value="anthropic">Anthropic Claude — native Messages API</option>
          <option value="gemini">Google Gemini — native GenerateContent API</option>
        </select>
      </label>
      <p className="muted small">{modelDetails[modelProvider].description}</p>
      <p className="muted small">Include these keys in the customer&apos;s private installation spec; store API credentials only in the named customer-host environment variable, not in the browser.</p>
      <pre style={{ background: "#102630", borderRadius: 6, padding: 16, color: "#fff", overflowX: "auto" }}><code>{JSON.stringify({
        model_provider: modelProvider,
        model_url: modelDetails[modelProvider].endpoint,
        model_name: modelDetails[modelProvider].name,
        ...(modelDetails[modelProvider].credential ? { model_token_env: modelDetails[modelProvider].credential } : {}),
      }, null, 2)}</code></pre>
      <p className="muted small">For a proprietary non-compatible protocol, AccessProof supports a locally installed reviewed Python model adapter; arbitrary custom model APIs cannot be used by simply selecting a dropdown option.</p>
      {modelProvider !== "openai-compatible" && <p className="alert warning-alert small">Live cloud APIs require customer-approved outbound access, provider credentials and security/retention review. Reference network checks ensure only Gateway has public egress; external provider operation is not yet customer-production-certified.</p>}
    </section>
    <section className="card section" aria-label="Guided integration stages">
      <p className="label">DEPLOYMENT WORKFLOW</p>
      <div className="row wrap" style={{ marginTop: 12 }}>
        {steps.map((item, index) =>
          <button key={item.id} className={`button compact ${step === item.id ? "" : "secondary"}`}
            aria-current={step === item.id ? "step" : undefined} onClick={() => { setStep(item.id); setCopied(""); }}>
            {index + 1}. {item.title}
          </button>,
        )}
      </div>
      <h2 style={{ marginTop: 24 }}>{chosen.title}</h2><p className="muted">{chosen.description}</p>

      {step === "prepare" ? <div>
        <p>First complete the product controls, then create the customer-owned <code>accessproof-install-spec.json</code> with tenant ID, application ID, RAG service, Guard URL, model URL, and your public ingestion-verification keys. Keep the file private (mode 0600). Use the reviewed Gateway Docker contract and approved application routing variable.</p>
        <div className="row wrap">
          <Link href="/sources" className="button compact secondary">1. Connect Google Drive</Link>
          <Link href="/guards" className="button compact secondary">2. Enroll Guard</Link>
          <Link href="/applications" className="button compact secondary">3. Register RAG</Link>
        </div>
        <p className="muted small">This setup does not grant AccessProof remote host access. Run the following phases on the customer-controlled Docker host.</p>
      </div> : <div>
        <p className="muted small">Run from the AccessProof repository on the approved customer Docker host. Replace example file paths with actual reviewed private files. Commands do not contain credentials.</p>
        {step === "cutover" && <div className="card section">
          <label className="checkbox"><input type="checkbox" checked={approved} onChange={event => setApproved(event.target.checked)}/> I approve installing the customer-side Gateway.</label>
          <label className="checkbox" style={{ marginTop: 12 }}><input type="checkbox" checked={approveCutover} onChange={event => setApproveCutover(event.target.checked)}/> I approve restarting only the reviewed customer RAG service for verified cutover.</label>
        </div>}
        {command && <div style={{ background: "#102630", borderRadius: 6, marginTop: 12, padding: 16, color: "#fff", overflowX: "auto" }}>
          <code style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{command}</code>
        </div>}
        <button type="button" className="button compact secondary" style={{ marginTop: 12 }}
          disabled={step === "cutover" && !(approved && approveCutover)} onClick={() => command && void copy(command)}>
          {copied === step ? "Command copied" : copied === "blocked" ? "Clipboard unavailable" : "Copy customer-side command"}
        </button>
        {step === "inspect" && <p className="muted">The inspection returns a compatibility report without writing files or starting services. Unsupported routes and unreviewed cache paths are blocked.</p>}
        {step === "stage" && <p className="muted">Stage creates mode-0600 Gateway environment, override, and installation hash files. The customer&apos;s existing Compose source is never modified.</p>}
        {step === "install" && <p className="muted">The installer verifies the staged files and starts only the Gateway. It must report <b>INSTALLED_UNVERIFIED</b>; customer RAG traffic remains unchanged.</p>}
        {step === "verify" && <p className="muted">Upload the generated installation manifest in the AI application screen, issue a server challenge, then provide the resulting private challenge and enrolled Guard credentials to the local command. This test does not activate Protect by itself.</p>}
        {step === "cutover" && <div>
          <p className="alert warning-alert small">The cutover command requires an already installed, reviewed Gateway and a server-issued machine challenge. For a single approved install → verify → cutover transaction after staging, use the separate complete command documented in the customer runbook. It will refuse to proceed if a security check fails. A successful customer-route challenge is not a blanket production certificate.</p>
          <p className="muted small">After the route is verified, an authorized administrator can request the separate control-plane Protect preflight. The server must independently validate source permissions, identity, routes and Guard acknowledgment before it reports protection active.</p>
          <Link className="button compact secondary" href="/applications">Check Protect readiness for registered application</Link>
        </div>}
      </div>}
      <p className="muted small">Protect mode remains fail-closed until independently verified effective permissions, source freshness, enrolled Guard identity, route cutover, and response/cache-path checks succeed.</p>
      <div className="row wrap" style={{ marginTop: 12 }}>
        <button className="button compact secondary" disabled={step === "prepare"} onClick={() => setStep(steps[Math.max(0, steps.findIndex(item => item.id === step) - 1)].id)}>Previous</button>
        <button className="button compact" disabled={step === "cutover"} onClick={() => setStep(steps[Math.min(steps.length - 1, steps.findIndex(item => item.id === step) + 1)].id)}>Next step</button>
      </div>
    </section>
  </ProtectedPage>;
}
