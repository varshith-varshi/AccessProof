"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import { Plus, X } from "lucide-react";
import { EmptyState, ErrorState, PendingButton, Skeleton, StatusBadge } from "../../components/ui";
import { api, Source } from "../../lib/api";
import { formatTimestamp } from "../../lib/format";
import { PageHeader } from "../app-shell";
import { ProtectedPage } from "../protected-page";

const providerDetails: Record<string, { boundaryLabel: string; boundaryPlaceholder: string; tokenLabel: string }> = {
  "google-drive": { boundaryLabel: "Approved Google Drive root folder ID", boundaryPlaceholder: "Folder ID containing the protected RAG documents", tokenLabel: "Google access token" },
};

export default function Sources() {
  const [rows, setRows] = useState<Source[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [creating, setCreating] = useState(false);
  const [pending, setPending] = useState(false);
  const provider = "google-drive";
  const [name, setName] = useState("");
  const [boundary, setBoundary] = useState("");
  const [googleNotice, setGoogleNotice] = useState("");
  const [googleOAuthReady, setGoogleOAuthReady] = useState<boolean | null>(null);
  const [syncNotice, setSyncNotice] = useState("");
  const detail = providerDetails[provider];

  const load = useCallback(async () => {
    setLoading(true); setError("");
    try { setRows(await api<Source[]>("/api/v1/current/sources")); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Unable to load permission sources."); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => {
    queueMicrotask(() => {
      void load();
      void api<{ configured: boolean }>("/api/v1/current/sources/google-oauth/status")
        .then(result => setGoogleOAuthReady(result.configured))
        .catch(() => setGoogleOAuthReady(null));
    });
  }, [load]);
  useEffect(() => {
    const google = new URLSearchParams(window.location.search).get("google");
    queueMicrotask(() => {
      if (google === "consent-complete") {
        setGoogleNotice("Google Drive authorization completed. AccessProof is checking Workspace employees; source ACLs and RAG enforcement still require validation.");
      } else if (google === "consent-failed") {
        setGoogleNotice("Google consent or approved root validation failed. Verify admin scope permissions and retry.");
      }
    });
  }, []);
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const sourceId = params.get("source_id");
    if (params.get("google") !== "consent-complete" || !sourceId || !/^[0-9a-f-]{36}$/i.test(sourceId)) return;
    // The server committed durable ACL + directory jobs before redirecting.
    // Browser closure/reload cannot drop those jobs, and duplicate frontend
    // submissions cannot trigger competing full inventories.
    params.delete("google");
    params.delete("source_id");
    const suffix = params.toString();
    window.history.replaceState(window.history.state, "", window.location.pathname + (suffix ? `?${suffix}` : ""));
    queueMicrotask(() => {
      setSyncNotice("Google Workspace connected. Employee and Drive permission synchronization are queued securely on the server. Access remains unverified until both sync indicators are fresh.");
      void load();
    });
  }, [load]);

  function closePanel() {
    if (pending) return;
    setCreating(false); setName(""); setBoundary("");
  }
  async function connect(event: FormEvent) {
    event.preventDefault(); setPending(true); setError("");
    try {
      // Preflight before creating a source. A customer must not be left with
      // another unusable OAuth draft when the operator hasn't configured OAuth.
      const readiness = await api<{ configured: boolean }>("/api/v1/current/sources/google-oauth/status");
      setGoogleOAuthReady(readiness.configured);
      if (!readiness.configured) throw new Error("Google Workspace connection is not enabled by the AccessProof operator. No source was created. Contact support.");
      const credentials = {};
      const created = await api<Source>("/api/v1/current/sources", { method: "POST", body: JSON.stringify({ provider, name, boundary, credentials }) });
      setCreating(false);
      await load();
      await authorizeGoogle(created.id);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Unable to connect the permission source."); }
    finally { setPending(false); }
  }
  async function authorizeGoogle(sourceId: string) {
    setPending(true); setError("");
    try {
      const result = await api<{ authorization_url: string }>(
        `/api/v1/current/sources/${encodeURIComponent(sourceId)}/google-oauth/begin`,
        { method: "POST" },
      );
      const url = new URL(result.authorization_url);
      if (url.protocol !== "https:" || url.hostname !== "accounts.google.com") {
        throw new Error("Unexpected Google consent destination");
      }
      window.location.assign(url.toString());
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Google OAuth authorization unavailable.");
      setPending(false);
    }
  }
  async function validate(sourceId: string) {
    setPending(true); setError("");
    try { await api(`/api/v1/sources/${sourceId}/validate`, { method: "POST" }); await load(); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Unable to validate the permission source."); }
    finally { setPending(false); }
  }
  async function syncDirectory(sourceId: string) {
    setPending(true); setError("");
    try { await api(`/api/v1/current/sources/${sourceId}/sync-directory`, { method: "POST" }); await load(); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Unable to synchronize the directory."); }
    finally { setPending(false); }
  }

  const connectButton = <button className="button compact" onClick={() => setCreating(true)}><Plus size={15}/>Connect source</button>;
  return <ProtectedPage><PageHeader eyebrow="AUTHORITATIVE ACCESS" title="Permission sources" description="Connections that supply the authorization state AccessProof turns into enforceable policy." action={connectButton}/>
    {creating && <section className="card create-panel" aria-labelledby="connect-source-title"><div className="panel-head"><div><p className="label">CONNECT PERMISSION SOURCE</p><h2 id="connect-source-title">Connect Google Workspace + Drive</h2></div><button className="icon-button" aria-label="Close" onClick={closePanel}><X size={18}/></button></div><p className="muted">Google Workspace + Drive V1. Enter an administrator-approved root folder ID. AccessProof redirects you to Google consent and automatically starts employee/group synchronization on return. No customer OAuth secret, refresh token, or access token is entered here. Document ACL reconciliation and Guard/AI-route validation remain separate security requirements.</p>{googleOAuthReady === false && <div className="alert warning-alert" role="status">Google connection is not yet configured on the AccessProof server. Ask the service operator to enable Google OAuth. No source was created.</div>}<form className="inline-form source-form" onSubmit={connect}><label>Connection name<input value={name} onChange={event => setName(event.target.value)} placeholder="Finance knowledge base" required/></label><label>{detail.boundaryLabel}<input value={boundary} onChange={event => setBoundary(event.target.value)} placeholder={detail.boundaryPlaceholder} required/></label><div className="form-actions"><PendingButton className="button compact" pending={pending}>{pending ? "Connecting…" : "Connect Google Workspace"}</PendingButton><button type="button" className="text-button" onClick={closePanel}>Cancel</button></div></form></section>}
    {googleNotice && <div className="alert warning-alert">{googleNotice}</div>}{syncNotice && <div className="alert warning-alert" role="status">{syncNotice}</div>}
    {error && <ErrorState message={error} retry={load}/>}<section className="card table-card">{loading ? <Skeleton rows={5}/> : rows.length === 0 ? <EmptyState title="Connect your Google Workspace source" description="Add an approved Google Drive root before creating enforceable policy." action={connectButton}/> : <table><thead><tr><th>Source</th><th>Provider</th><th>Status</th><th>Last validation</th><th>Health detail</th><th></th></tr></thead><tbody>{rows.map(row => <tr key={row.id}><td><b>{row.name}</b><small>{row.boundary}</small></td><td>{row.provider}</td><td><StatusBadge value={row.status}/>{row.provider === "google-drive" && <small>Workspace directory: {row.directory_sync?.fresh ? "Fresh" : row.directory_sync?.status === "connected" ? "Stale" : row.directory_sync?.status === "degraded" ? "Sync failed" : row.directory_sync?.status === "queued" ? "Queued" : row.directory_sync?.status === "syncing" ? "Syncing" : "Not synced"}{row.directory_sync?.last_error_code ? ` (${row.directory_sync.last_error_code})` : ""}</small>}{row.provider === "google-drive" && <small>Drive ACLs: {row.acl_sync?.fresh ? "Fresh" : row.acl_sync?.status === "connected" ? "Stale" : row.acl_sync?.status === "degraded" ? "Sync failed" : row.acl_sync?.status === "queued" ? "Queued" : row.acl_sync?.status === "syncing" ? "Syncing" : "Not synced"}{row.acl_sync?.last_error_code ? ` (${row.acl_sync.last_error_code})` : ""}</small>}</td><td>{formatTimestamp(row.last_validated_at)}</td><td className="table-muted">{row.last_error ?? "No connection error"}{row.provider === "google-drive" && <small>{row.directory_sync?.last_success_at ? `Directory last synced: ${formatTimestamp(row.directory_sync.last_success_at)}` : "Directory not yet verified"}</small>}</td><td className="row-actions"><button className="text-button" disabled={pending} onClick={() => void validate(row.id)}>Validate</button>{row.provider === "google-drive" && <button className="text-button" disabled={pending || googleOAuthReady === false} onClick={() => void authorizeGoogle(row.id)}>Authorize Google</button>}{row.provider === "google-drive" && <button className="text-button" disabled={pending} onClick={() => void syncDirectory(row.id)}>Sync directory</button>}</td></tr>)}</tbody></table>}</section></ProtectedPage>;
}
