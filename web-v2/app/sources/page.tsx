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
  microsoft365: { boundaryLabel: "Approved folder item ID", boundaryPlaceholder: "Root folder item ID in the selected SharePoint/OneDrive drive", tokenLabel: "Microsoft Graph access token" },
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
  const [microsoftTenantId, setMicrosoftTenantId] = useState("");
  const [microsoftNotice, setMicrosoftNotice] = useState("");
  const [googleNotice, setGoogleNotice] = useState("");
  const detail = providerDetails[provider];

  const load = useCallback(async () => {
    setLoading(true); setError("");
    try { setRows(await api<Source[]>("/api/v1/current/sources")); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Unable to load permission sources."); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { queueMicrotask(() => void load()); }, [load]);
  useEffect(() => {
    const microsoft = new URLSearchParams(window.location.search).get("microsoft");
    const google = new URLSearchParams(window.location.search).get("google");
    queueMicrotask(() => {
      if (google === "consent-complete") {
        setGoogleNotice("Google Drive connected. Allow directory/ACL synchronization and test actual employee access before Protect mode.");
      } else if (google === "consent-failed") {
        setGoogleNotice("Google consent or approved root validation failed. Verify admin scope permissions and retry.");
      }
      if (microsoft === "consent-complete") {
        setMicrosoftNotice("Microsoft admin consent completed and the approved drive was validated. Synchronize employees and permissions before considering enforcement; SharePoint Protect is still unavailable.");
      } else if (microsoft === "consent-failed") {
        setMicrosoftNotice("Microsoft consent or drive validation failed. Verify the Entra tenant, application permissions and approved drive before retrying.");
      }
    });
  }, []);

  function closePanel() {
    if (pending) return;
    setCreating(false); setName(""); setBoundary(""); setAccessToken(""); setDriveId(""); setMicrosoftTenantId("");
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
      if (provider === "microsoft365" && !/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(microsoftTenantId)) {
        throw new Error("Enter the customer's Microsoft Entra tenant UUID to configure token renewal.");
      }
      const credentials = provider === "microsoft365"
        ? {
            access_token: accessToken, drive_id: driveId, test_root_item_id: boundary,
            ...(microsoftTenantId ? { tenant_id: microsoftTenantId, tenant_hint: microsoftTenantId } : {}),
            ...(hasRenewal ? {
              refresh_token: refreshToken,
              client_id: oauthClientId,
              client_secret: oauthClientSecret,
              expires_at: expiry!.toISOString(),
              token_endpoint: `https://login.microsoftonline.com/${microsoftTenantId}/oauth2/v2.0/token`,
            } : {}),
          }
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
      const created = await api<Source>("/api/v1/current/sources", { method: "POST", body: JSON.stringify({ provider, name, boundary, credentials }) });
      if (provider === "google-drive" && !accessToken) {
        setCreating(false);
        await load();
        await authorizeGoogle(created.id);
        return;
      }
      setCreating(false); setName(""); setBoundary(""); setAccessToken(""); setDriveId(""); setMicrosoftTenantId("");
      setRefreshToken(""); setOauthClientId(""); setOauthClientSecret(""); setExpiresAt("");
      await load();
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
  async function authorizeMicrosoft(sourceId: string) {
    setPending(true); setError("");
    try {
      const result = await api<{ authorization_url: string }>(
        `/api/v1/current/sources/${encodeURIComponent(sourceId)}/microsoft-admin-consent/begin`,
        { method: "POST" },
      );
      const url = new URL(result.authorization_url);
      if (url.protocol !== "https:" || url.hostname !== "login.microsoftonline.com") {
        throw new Error("Unexpected Microsoft consent destination");
      }
      window.location.assign(url.toString());
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Microsoft admin consent unavailable.");
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
    {creating && <section className="card create-panel" aria-labelledby="connect-source-title"><div className="panel-head"><div><p className="label">CONNECT PERMISSION SOURCE</p><h2 id="connect-source-title">Connect a source</h2></div><button className="icon-button" aria-label="Close" onClick={closePanel}><X size={18}/></button></div><p className="muted">{provider === "microsoft365"
      ? "Microsoft 365 preview / Shadow testing only. Choose one administrator-approved SharePoint or OneDrive drive and folder. After creation, select Authorize Microsoft for administrator consent, or supply an existing token. Graph delegated/app access requires approved scopes, and directory synchronization needs separately approved user/group reading rights. Inherited SharePoint/site-level effective permissions are not yet certified, so Protect remains disabled. Credentials are encrypted; Microsoft administrator consent requires a configured server-side Entra application."
      : "Google Drive V1. Enter an administrator-approved root folder ID, then use Google OAuth to authorize read-only Drive and Workspace Directory access. Google OAuth requires a configured server-side client; tokens below remain an optional advanced pilot method. ACL and identity validation are required before Protect mode."}</p><form className="inline-form source-form" onSubmit={connect}><label>Provider<select value={provider} onChange={event => { setProvider(event.target.value); setBoundary(""); setDriveId(""); }}><option value="google-drive">Google Drive (V1)</option><option value="microsoft365">SharePoint / OneDrive (certification required)</option></select></label><label>Connection name<input value={name} onChange={event => setName(event.target.value)} placeholder="Finance knowledge base" required/></label>{provider === "microsoft365" && <label>Microsoft drive ID<input value={driveId} onChange={event => setDriveId(event.target.value)} placeholder="The drive that contains the test root" required/></label>}{provider === "microsoft365" && <label>Microsoft Entra tenant ID (required for source identity isolation)<input value={microsoftTenantId} onChange={event => setMicrosoftTenantId(event.target.value)} placeholder="Microsoft Entra tenant UUID"/></label>}<label>{detail.boundaryLabel}<input value={boundary} onChange={event => setBoundary(event.target.value)} placeholder={detail.boundaryPlaceholder} required/></label><label>{detail.tokenLabel}<input type="password" autoComplete="new-password" value={accessToken} onChange={event => setAccessToken(event.target.value)} placeholder={provider === "microsoft365" ? "Optional if using admin consent" : "Optional: leave blank to connect securely using Google OAuth"} required={false}/></label><details><summary>Optional OAuth token renewal (guided pilot)</summary><p className="muted small">Provide administrator-approved {provider === "microsoft365" ? "Microsoft Entra" : "Google"} OAuth credentials and an existing refresh token. AccessProof encrypts them at rest. This is not an automated sign-in or consent flow.</p><label>{provider === "microsoft365" ? "Microsoft OAuth client ID" : "Google OAuth client ID"}<input value={oauthClientId} onChange={event => setOauthClientId(event.target.value)} autoComplete="off" placeholder="OAuth client ID"/></label><label>{provider === "microsoft365" ? "Microsoft OAuth client secret" : "Google OAuth client secret"}<input type="password" value={oauthClientSecret} onChange={event => setOauthClientSecret(event.target.value)} autoComplete="new-password"/></label><label>{provider === "microsoft365" ? "Microsoft refresh token" : "Google refresh token"}<input type="password" value={refreshToken} onChange={event => setRefreshToken(event.target.value)} autoComplete="new-password"/></label><label>Access-token expiry<input type="datetime-local" value={expiresAt} onChange={event => setExpiresAt(event.target.value)}/><small>Enter expiry in your local time.</small></label></details><div className="form-actions"><PendingButton className="button compact" pending={pending}>{pending ? "Connecting…" : "Connect source"}</PendingButton><button type="button" className="text-button" onClick={closePanel}>Cancel</button></div></form></section>}
    {googleNotice && <div className="alert warning-alert">{googleNotice}</div>}{microsoftNotice && <section className="card" role="status"><p className="muted">{microsoftNotice}</p></section>}
    {error && <ErrorState message={error} retry={load}/>}<section className="card table-card">{loading ? <Skeleton rows={5}/> : rows.length === 0 ? <EmptyState title="Connect your first permission source" description="Add an enterprise source of truth before creating enforceable policy." action={connectButton}/> : <table><thead><tr><th>Source</th><th>Provider</th><th>Status</th><th>Last validation</th><th>Health detail</th><th></th></tr></thead><tbody>{rows.map(row => <tr key={row.id}><td><b>{row.name}</b><small>{row.boundary}</small></td><td>{row.provider}</td><td><StatusBadge value={row.status}/>{row.provider === "microsoft365" && <small>Effective permissions not yet certified for protection</small>}</td><td>{formatTimestamp(row.last_validated_at)}</td><td className="table-muted">{row.last_error ?? "No active error"}</td><td className="row-actions"><button className="text-button" disabled={pending} onClick={() => void validate(row.id)}>Validate</button>{row.provider === "microsoft365" && <button className="text-button" disabled={pending} onClick={() => void authorizeMicrosoft(row.id)}>Authorize Microsoft</button>}{row.provider === "google-drive" && <button className="text-button" disabled={pending} onClick={() => void authorizeGoogle(row.id)}>Authorize Google</button>}{["google-drive", "microsoft365"].includes(row.provider) && <button className="text-button" disabled={pending} onClick={() => void syncDirectory(row.id)}>Sync directory</button>}</td></tr>)}</tbody></table>}</section></ProtectedPage>;
}
