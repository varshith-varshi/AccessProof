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
  microsoft365: { boundaryLabel: "SharePoint site or drive ID", boundaryPlaceholder: "The approved SharePoint site or drive", tokenLabel: "Microsoft Graph access token" },
  confluence: { boundaryLabel: "Confluence space", boundaryPlaceholder: "The approved space key", tokenLabel: "Confluence access token" },
  slack: { boundaryLabel: "Slack workspace boundary", boundaryPlaceholder: "The approved workspace or channel boundary", tokenLabel: "Slack access token" },
};

export default function Sources() {
  const [rows, setRows] = useState<Source[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [creating, setCreating] = useState(false);
  const [pending, setPending] = useState(false);
  const [provider, setProvider] = useState("google-drive");
  const [name, setName] = useState("");
  const [boundary, setBoundary] = useState("");
  const [accessToken, setAccessToken] = useState("");
  const [refreshToken, setRefreshToken] = useState("");
  const [oauthClientId, setOauthClientId] = useState("");
  const [oauthClientSecret, setOauthClientSecret] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [driveId, setDriveId] = useState("");
  const detail = providerDetails[provider];

  const load = useCallback(async () => {
    setLoading(true); setError("");
    try { setRows(await api<Source[]>("/api/v1/current/sources")); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Unable to load permission sources."); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { queueMicrotask(() => void load()); }, [load]);

  function closePanel() {
    if (pending) return;
    setCreating(false); setName(""); setBoundary(""); setAccessToken(""); setDriveId("");
    setRefreshToken(""); setOauthClientId(""); setOauthClientSecret(""); setExpiresAt("");
  }
  async function connect(event: FormEvent) {
    event.preventDefault(); setPending(true); setError("");
    try {
      const hasRenewal = Boolean(refreshToken || oauthClientId || oauthClientSecret || expiresAt);
      if (hasRenewal && !(refreshToken && oauthClientId && oauthClientSecret && expiresAt)) {
        throw new Error("Fill in all OAuth renewal fields or leave them all blank.");
      }
      const expiry = hasRenewal ? new Date(expiresAt) : null;
      if (expiry && Number.isNaN(expiry.getTime())) throw new Error("Enter a valid OAuth access-token expiry.");
      const credentials = provider === "microsoft365"
        ? { access_token: accessToken, drive_id: driveId, test_root_item_id: boundary }
        : {
            access_token: accessToken,
            ...(hasRenewal ? {
              refresh_token: refreshToken,
              client_id: oauthClientId,
              client_secret: oauthClientSecret,
              expires_at: expiry!.toISOString(),
              token_endpoint: "https://oauth2.googleapis.com/token",
            } : {}),
          };
      await api<Source>("/api/v1/current/sources", { method: "POST", body: JSON.stringify({ provider, name, boundary, credentials }) });
      setCreating(false); setName(""); setBoundary(""); setAccessToken(""); setDriveId("");
      setRefreshToken(""); setOauthClientId(""); setOauthClientSecret(""); setExpiresAt("");
      await load();
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Unable to connect the permission source."); }
    finally { setPending(false); }
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
    {creating && <section className="card create-panel" aria-labelledby="connect-source-title"><div className="panel-head"><div><p className="label">CONNECT PERMISSION SOURCE</p><h2 id="connect-source-title">Connect a source</h2></div><button className="icon-button" aria-label="Close" onClick={closePanel}><X size={18}/></button></div><p className="muted">Google Drive is the only supported permission source in V1. Use a dedicated, administrator-approved credential and a root folder ID; sharing a personal access token is only suitable for controlled pilot setup. The secret is encrypted at rest, but automatic Google consent is not yet enabled.</p><form className="inline-form source-form" onSubmit={connect}><label>Provider<select value={provider} onChange={event => { setProvider(event.target.value); setBoundary(""); setDriveId(""); }}><option value="google-drive">Google Drive (V1)</option></select></label><label>Connection name<input value={name} onChange={event => setName(event.target.value)} placeholder="Finance knowledge base" required/></label>{provider === "microsoft365" && <label>Microsoft drive ID<input value={driveId} onChange={event => setDriveId(event.target.value)} placeholder="The drive that contains the test root" required/></label>}<label>{detail.boundaryLabel}<input value={boundary} onChange={event => setBoundary(event.target.value)} placeholder={detail.boundaryPlaceholder} required/></label><label>{detail.tokenLabel}<input type="password" autoComplete="new-password" value={accessToken} onChange={event => setAccessToken(event.target.value)} placeholder="Stored encrypted; never shown again" required/></label><details><summary>Optional OAuth token renewal (guided pilot)</summary><p className="muted small">Use an administrator-approved Google OAuth client. AccessProof encrypts these credentials at rest. This is not a Google sign-in or consent flow.</p><label>Google OAuth client ID<input value={oauthClientId} onChange={event => setOauthClientId(event.target.value)} autoComplete="off" placeholder="OAuth client ID"/></label><label>Google OAuth client secret<input type="password" value={oauthClientSecret} onChange={event => setOauthClientSecret(event.target.value)} autoComplete="new-password"/></label><label>Google refresh token<input type="password" value={refreshToken} onChange={event => setRefreshToken(event.target.value)} autoComplete="new-password"/></label><label>Access-token expiry<input type="datetime-local" value={expiresAt} onChange={event => setExpiresAt(event.target.value)}/><small>Enter expiry in your local time.</small></label></details><div className="form-actions"><PendingButton className="button compact" pending={pending}>{pending ? "Connecting…" : "Connect source"}</PendingButton><button type="button" className="text-button" onClick={closePanel}>Cancel</button></div></form></section>}
    {error && <ErrorState message={error} retry={load}/>}<section className="card table-card">{loading ? <Skeleton rows={5}/> : rows.length === 0 ? <EmptyState title="Connect your first permission source" description="Add an enterprise source of truth before creating enforceable policy." action={connectButton}/> : <table><thead><tr><th>Source</th><th>Provider</th><th>Status</th><th>Last validation</th><th>Health detail</th><th></th></tr></thead><tbody>{rows.map(row => <tr key={row.id}><td><b>{row.name}</b><small>{row.boundary}</small></td><td>{row.provider}</td><td><StatusBadge value={row.status}/></td><td>{formatTimestamp(row.last_validated_at)}</td><td className="table-muted">{row.last_error ?? "No active error"}</td><td className="row-actions"><button className="text-button" disabled={pending} onClick={() => void validate(row.id)}>Validate</button>{["google-drive", "microsoft365"].includes(row.provider) && <button className="text-button" disabled={pending} onClick={() => void syncDirectory(row.id)}>Sync directory</button>}</td></tr>)}</tbody></table>}</section></ProtectedPage>;
}
