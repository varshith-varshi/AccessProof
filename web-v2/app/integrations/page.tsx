"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { EmptyState, ErrorState, Skeleton, StatusBadge } from "../../components/ui";
import { AdapterRegistration, api } from "../../lib/api";
import { PageHeader } from "../app-shell";
import { ProtectedPage } from "../protected-page";

export default function Integrations() {
  const [items, setItems] = useState<AdapterRegistration[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const load = useCallback(async () => {
    setLoading(true); setError("");
    try { setItems(await api<AdapterRegistration[]>("/api/v1/current/adapters")); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Unable to load integrations."); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { queueMicrotask(() => void load()); }, [load]);
  return <ProtectedPage>
    <PageHeader eyebrow="INTEGRATION CATALOG" title="Adapters" description="Choose a reviewed enforcement boundary for your AI application. Availability reflects code and test coverage in this release." />
    <section className="card section" aria-labelledby="connect-rag-heading">
      <div className="section-head"><div><p className="label">RAG CONNECTION</p><h2 id="connect-rag-heading">Connect your RAG in three steps</h2></div></div>
      <p className="muted">An adapter is installed in your RAG service. It sends the authenticated employee and trusted retrieved-resource metadata to the customer-side Guard before generation, then verifies provenance before releasing the response.</p>
      <div className="row wrap" style={{ marginBottom: 14 }}>
        <Link className="button compact" href="/integrations/setup">Open guided integration</Link>
      </div>
      <div className="row wrap">
        <Link className="button compact" href="/sources">1. Connect permission source</Link>
        <Link className="button compact" href="/guards">2. Create a Guard</Link>
        <Link className="button compact" href="/applications">3. Register AI application</Link>
      </div>
      <p className="muted small">Connect your Guard and source before enabling protection. Automatic verification must test the real protected RAG route and report every unmet requirement. Generic HTTP connectivity is useful for testing but does not enforce retrieval authorization inside a RAG.</p>
    </section>
    <section className="card section" aria-labelledby="gateway-heading">
      <div className="section-head"><div><p className="label">REFERENCE GATEWAY</p><h2 id="gateway-heading">Protect a configurable retrieval route</h2></div></div>
      <p className="muted">The AccessProof RAG Security Gateway is a customer-side OpenAI-compatible boundary with buffered SSE after Layer 2 approval. It validates a signed retrieval manifest, calls Guard Layer 1 before the model, buffers the model response, then calls Layer 2 before release.</p>
      <p className="muted small">A plain model proxy cannot discover hidden vector, cache, or tool inputs. Installations remain unverified until an allow, denial, and provenance challenge pass on the real route.</p>
      <a className="button compact" href="/applications">Register the Gateway application</a>
    </section>
    <section className="card table-card">
      {loading ? <Skeleton rows={5}/> : error ? <ErrorState message={error} retry={load}/> : !items.length ? <EmptyState title="No adapters published" description="The control plane has no reviewed adapter metadata."/> : <table><thead><tr><th>Adapter</th><th>Status</th><th>Security layers</th><th>Install and compatibility</th><th>Boundary</th></tr></thead><tbody>{items.map(item => <tr key={item.id}><td><b>{item.name}</b><small>{item.category} · {item.language} · {item.contract_version}</small><small>Adapter {item.adapter_version ?? "version not published"} · Guard {item.required_guard_version ?? "compatibility not published"}</small></td><td><StatusBadge value={item.status}/><small>{item.certification?.replaceAll("_", " ") ?? "Validation pending"}</small></td><td className="table-muted"><small>Layer 1: {item.pre_generation_filtering ? "Supported" : "Not provided"}</small><small>Layer 2: {item.output_verification ? "Supported" : "Not provided"}</small><small>Shadow: {item.shadow_mode ? "Supported" : "Not provided"} · Protect: {item.protect_mode ? "Supported" : "Not provided"}</small></td><td className="table-muted">{item.installation}<small>{item.framework_versions?.join(", ")}</small><small>{item.deployment_models?.join(" · ")}</small></td><td className="table-muted">{item.limitation}{item.validation_requirements?.length ? <small>Validate: {item.validation_requirements.join(" · ")}</small> : null}</td></tr>)}</tbody></table>}
    </section>
  </ProtectedPage>;
}
