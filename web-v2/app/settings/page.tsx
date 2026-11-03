"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import { Copy, KeyRound, ShieldCheck, Trash2, UserPlus } from "lucide-react";
import { PageHeader, useAccount } from "../app-shell";
import { ProtectedPage } from "../protected-page";
import { ApiError, api } from "../../lib/api";
import { PendingButton } from "../../components/ui";

type Tab = "workspace" | "security" | "team" | "api";
type Member = { membership_id: string; user_id: string; email: string; role: string };
type SessionRow = { id: string; created_at: string; expires_at: string; revoked: boolean };
type ApiKeyRow = { id: string; label: string; scopes: string[]; expires_at: string | null; last_used_at: string | null; revoked: boolean };
const ROLES = ["OWNER", "ADMIN", "ENGINEER", "VIEWER", "AUDITOR"] as const;
const ROLE_HELP: Record<string, string> = {
  OWNER: "Full control, including deleting the workspace.",
  ADMIN: "Manage members, sources, Guards and protection.",
  ENGINEER: "Connect sources and applications; run checks.",
  VIEWER: "Read-only access to status and results.",
  AUDITOR: "Read-only access to audit evidence and reports.",
};
const message = (cause: unknown, fallback: string) => cause instanceof Error ? cause.message : fallback;
const when = (iso: string | null) => iso ? new Date(iso).toLocaleString() : "—";

function Notice({ tone, children }: { tone: "ok" | "error"; children: React.ReactNode }) {
  return <p className={tone === "ok" ? "notice-ok" : "form-error"} role={tone === "ok" ? "status" : "alert"}>{children}</p>;
}

function WorkspaceSection() {
  const { account, refreshAccount } = useAccount();
  const active = account?.organizations.find(org => org.id === account.active_organization_id);
  const canEdit = account?.role === "OWNER" || account?.role === "ADMIN";
  // Edited value; null means "show the current saved name".
  const [draft, setDraft] = useState<string | null>(null);
  const name = draft ?? active?.name ?? "";
  const setName = (value: string) => setDraft(value);
  const [pending, setPending] = useState(false);
  const [note, setNote] = useState<{ tone: "ok" | "error"; text: string } | null>(null);
  async function save(event: FormEvent) {
    event.preventDefault(); setPending(true); setNote(null);
    try {
      await api("/api/v1/organization", { method: "PATCH", body: JSON.stringify({ name }) });
      await refreshAccount();
      setDraft(null);
      setNote({ tone: "ok", text: "Workspace name saved." });
    } catch (cause) { setNote({ tone: "error", text: message(cause, "Could not rename the workspace.") }); }
    finally { setPending(false); }
  }
  return <section className="card settings-card" aria-labelledby="workspace-heading">
    <h2 id="workspace-heading">Workspace</h2>
    <p className="muted">Your workspace holds your permission sources, Guards, AI applications and audit history.</p>
    <form className="form inline-form" onSubmit={save}>
      <label>Workspace name
        <input value={name} onChange={event => setName(event.target.value)} minLength={2} maxLength={200} required disabled={!canEdit}/>
      </label>
      <PendingButton className="button compact" pending={pending} disabled={!canEdit || !name.trim() || name.trim() === active?.name}>Save</PendingButton>
    </form>
    {!canEdit && account && <p className="muted small">Only owners and admins can rename the workspace.</p>}
    {note && <Notice tone={note.tone}>{note.text}</Notice>}
    <dl className="facts">
      <div><dt>Your role</dt><dd>{account?.role ?? "—"}</dd></div>
      <div><dt>Workspace ID</dt><dd><code>{account?.active_organization_id ?? "—"}</code></dd></div>
    </dl>
    <ResetOnboarding/>
  </section>;
}

type ResetPreview = {
  organization_name: string; will_archive_ai_applications: string[]; will_revoke_guards: number;
  will_revoke_pending_guard_enrollments: number; will_disconnect_sources: number; kept: string[];
  scope_digest: string; confirm_text: string;
};

function ResetOnboarding() {
  const { account } = useAccount();
  const [preview, setPreview] = useState<ResetPreview | null>(null);
  const [typed, setTyped] = useState(""), [code, setCode] = useState("");
  const [pending, setPending] = useState(false);
  const [note, setNote] = useState<{ tone: "ok" | "error"; text: string } | null>(null);
  if (account?.role !== "OWNER") return null;
  async function review() {
    setPending(true); setNote(null);
    try { setPreview(await api<ResetPreview>("/api/v1/organization/onboarding-reset/preview")); setTyped(""); }
    catch (cause) { setNote({ tone: "error", text: message(cause, "Could not load what would be reset.") }); }
    finally { setPending(false); }
  }
  async function reset(event: FormEvent) {
    event.preventDefault(); if (!preview) return; setPending(true); setNote(null);
    try {
      await api("/api/v1/organization/onboarding-reset", { method: "POST", body: JSON.stringify({
        scope_digest: preview.scope_digest, confirm_text: typed, ...(account?.user.mfa_enabled ? { totp_code: code } : {}),
      }) });
      setPreview(null);
      setNote({ tone: "ok", text: "Onboarding was reset. Open Get Started to connect a source again." });
    } catch (cause) {
      setNote({ tone: "error", text: cause instanceof ApiError && cause.status === 409
        ? "Something changed since you reviewed this. Review the reset again." : message(cause, "Reset failed; nothing was changed.") });
    } finally { setPending(false); }
  }
  return <div className="settings-block danger-zone" aria-labelledby="reset-heading">
    <h3 id="reset-heading">Start onboarding again</h3>
    <p className="muted">Revoke every Guard and Gateway, disconnect permission sources and remove AI applications from protection so you can set up from scratch. Your account, team and all history are kept.</p>
    {!preview && <PendingButton className="button compact secondary" type="button" pending={pending} onClick={review}>Review what will be reset</PendingButton>}
    {preview && <form className="form" onSubmit={reset}>
      <ul className="reset-scope">
        <li><b>{preview.will_archive_ai_applications.length}</b> AI application(s) removed from protection{preview.will_archive_ai_applications.length ? `: ${preview.will_archive_ai_applications.join(", ")}` : ""}</li>
        <li><b>{preview.will_revoke_guards}</b> Guard(s) revoked, <b>{preview.will_revoke_pending_guard_enrollments}</b> pending enrollment(s) cancelled</li>
        <li><b>{preview.will_disconnect_sources}</b> permission source(s) disconnected and their credentials deleted</li>
        <li>Kept: {preview.kept.join("; ")}</li>
      </ul>
      <label>Type <code>{preview.confirm_text}</code> to confirm<input value={typed} onChange={e => setTyped(e.target.value)} autoComplete="off" required/></label>
      {account?.user.mfa_enabled && <label>Two-factor code<input inputMode="numeric" autoComplete="one-time-code" value={code} onChange={e => setCode(e.target.value)} required/></label>}
      <div className="button-row">
        <PendingButton className="button compact danger" pending={pending} disabled={typed !== preview.confirm_text}>Reset onboarding</PendingButton>
        <button type="button" className="text-button" onClick={() => setPreview(null)}>Cancel</button>
      </div>
    </form>}
    {note && <Notice tone={note.tone}>{note.text}</Notice>}
  </div>;
}

function PasswordForm() {
  const [current, setCurrent] = useState(""), [next, setNext] = useState(""), [confirm, setConfirm] = useState("");
  const [pending, setPending] = useState(false);
  const [note, setNote] = useState<{ tone: "ok" | "error"; text: string } | null>(null);
  async function submit(event: FormEvent) {
    event.preventDefault(); setNote(null);
    if (next !== confirm) { setNote({ tone: "error", text: "The new passwords do not match." }); return; }
    setPending(true);
    try {
      await api("/api/v1/auth/change-password", { method: "POST", body: JSON.stringify({ current_password: current, new_password: next }) });
      setCurrent(""); setNext(""); setConfirm("");
      setNote({ tone: "ok", text: "Password changed." });
    } catch (cause) { setNote({ tone: "error", text: message(cause, "Could not change your password.") }); }
    finally { setPending(false); }
  }
  return <form className="form" onSubmit={submit} aria-labelledby="password-heading">
    <h3 id="password-heading">Password</h3>
    <label>Current password<input type="password" autoComplete="current-password" value={current} onChange={e => setCurrent(e.target.value)} required/></label>
    <div className="form-grid">
      <label>New password<input type="password" autoComplete="new-password" minLength={12} value={next} onChange={e => setNext(e.target.value)} required/><small>At least 12 characters.</small></label>
      <label>Confirm new password<input type="password" autoComplete="new-password" minLength={12} value={confirm} onChange={e => setConfirm(e.target.value)} required/></label>
    </div>
    {note && <Notice tone={note.tone}>{note.text}</Notice>}
    <PendingButton className="button compact" pending={pending}>Change password</PendingButton>
  </form>;
}

function TwoFactor() {
  const { account, refreshAccount } = useAccount();
  const enabled = account?.user.mfa_enabled ?? false;
  const [setup, setSetup] = useState<{ provisioning_uri: string; recovery_codes: string[] } | null>(null);
  const [code, setCode] = useState("");
  const [pending, setPending] = useState(false);
  const [note, setNote] = useState<{ tone: "ok" | "error"; text: string } | null>(null);
  const secret = setup ? new URL(setup.provisioning_uri).searchParams.get("secret") ?? "" : "";
  async function begin() {
    setPending(true); setNote(null);
    try { setSetup(await api("/api/v1/auth/mfa/setup", { method: "POST" })); }
    catch (cause) { setNote({ tone: "error", text: message(cause, "Could not start two-factor setup.") }); }
    finally { setPending(false); }
  }
  async function confirm(event: FormEvent) {
    event.preventDefault(); setPending(true); setNote(null);
    try {
      await api(enabled ? "/api/v1/auth/mfa/disable" : "/api/v1/auth/mfa/enable", { method: "POST", body: JSON.stringify({ code: code.trim() }) });
      setCode(""); setSetup(null); await refreshAccount();
      setNote({ tone: "ok", text: enabled ? "Two-factor authentication turned off." : "Two-factor authentication is on. Keep your recovery codes somewhere safe." });
    } catch (cause) { setNote({ tone: "error", text: cause instanceof ApiError && cause.status === 400 ? "That code didn’t work. Check your authenticator app's clock and try again." : message(cause, "Could not verify the code.") }); }
    finally { setPending(false); }
  }
  return <div className="settings-block" aria-labelledby="mfa-heading">
    <h3 id="mfa-heading"><ShieldCheck size={16}/>Two-factor authentication <span className={`pill ${enabled ? "pill-ok" : "pill-warn"}`}>{enabled ? "On" : "Off"}</span></h3>
    <p className="muted">Require a code from an authenticator app (Google Authenticator, 1Password, Authy) when you sign in.</p>
    {!enabled && !setup && <PendingButton className="button compact" type="button" pending={pending} onClick={begin}>Set up two-factor</PendingButton>}
    {setup && <div className="mfa-setup">
      <ol>
        <li>In your authenticator app, add an account using this key: <code className="secret">{secret.match(/.{1,4}/g)?.join(" ")}</code>
          {" "}<a href={setup.provisioning_uri}>or open it in your authenticator app</a>.</li>
        <li>Save these one-time recovery codes. Each can be used once if you lose your device:
          <div className="recovery-codes">{setup.recovery_codes.map(item => <code key={item}>{item}</code>)}</div>
          <button type="button" className="text-button" onClick={() => void navigator.clipboard?.writeText(setup.recovery_codes.join("\n"))}><Copy size={13}/>Copy codes</button>
        </li>
        <li>Enter the 6-digit code from the app to turn it on.</li>
      </ol>
    </div>}
    {(setup || enabled) && <form className="form inline-form" onSubmit={confirm}>
      <label>{enabled ? "Authenticator or recovery code to turn off" : "6-digit code"}
        <input inputMode="numeric" autoComplete="one-time-code" value={code} onChange={e => setCode(e.target.value)} minLength={6} maxLength={64} required/>
      </label>
      <PendingButton className={`button compact ${enabled ? "danger" : ""}`} pending={pending}>{enabled ? "Turn off" : "Turn on"}</PendingButton>
    </form>}
    {note && <Notice tone={note.tone}>{note.text}</Notice>}
  </div>;
}

function Sessions() {
  const [rows, setRows] = useState<SessionRow[] | null>(null);
  const [error, setError] = useState("");
  const load = useCallback(async () => {
    try { setRows(await api<SessionRow[]>("/api/v1/auth/sessions")); setError(""); }
    catch (cause) { setError(message(cause, "Could not load sessions.")); }
  }, []);
  useEffect(() => { queueMicrotask(() => void load()); }, [load]);
  async function revoke(id: string) {
    try { await api(`/api/v1/auth/sessions/${encodeURIComponent(id)}`, { method: "DELETE" }); await load(); }
    catch (cause) { setError(message(cause, "Could not sign out that session.")); }
  }
  const active = (rows ?? []).filter(row => !row.revoked);
  return <div className="settings-block" aria-labelledby="sessions-heading">
    <h3 id="sessions-heading">Signed-in sessions</h3>
    <p className="muted">Sign out sessions you don’t recognize. Signing out your current session will return you to the login page.</p>
    {error && <p className="form-error" role="alert">{error}</p>}
    {rows === null ? <p className="muted">Loading…</p> : <table className="table compact-table">
      <thead><tr><th>Started</th><th>Expires</th><th><span className="sr-only">Actions</span></th></tr></thead>
      <tbody>{active.map(row => <tr key={row.id}><td>{when(row.created_at)}</td><td>{when(row.expires_at)}</td>
        <td className="row-actions"><button className="text-button" onClick={() => void revoke(row.id)}>Sign out</button></td></tr>)}
        {active.length === 0 && <tr><td colSpan={3} className="muted">No active sessions.</td></tr>}</tbody>
    </table>}
  </div>;
}

function Team() {
  const { account } = useAccount();
  const canManage = account?.role === "OWNER" || account?.role === "ADMIN";
  const [members, setMembers] = useState<Member[] | null>(null);
  const [email, setEmail] = useState(""), [role, setRole] = useState("ENGINEER");
  const [pending, setPending] = useState(false);
  const [note, setNote] = useState<{ tone: "ok" | "error"; text: string } | null>(null);
  const load = useCallback(async () => {
    try { setMembers(await api<Member[]>("/api/v1/organization/members")); }
    catch (cause) { setNote({ tone: "error", text: message(cause, "Could not load members.") }); }
  }, []);
  useEffect(() => { queueMicrotask(() => void load()); }, [load]);
  async function invite(event: FormEvent) {
    event.preventDefault(); setPending(true); setNote(null);
    try {
      await api("/api/v1/organization/invitations", { method: "POST", body: JSON.stringify({ email, role }) });
      setNote({ tone: "ok", text: `Invitation sent to ${email}. It expires in 7 days.` }); setEmail("");
    } catch (cause) { setNote({ tone: "error", text: message(cause, "Could not send the invitation.") }); }
    finally { setPending(false); }
  }
  async function changeRole(member: Member, next: string) {
    setNote(null);
    try { await api(`/api/v1/organization/members/${encodeURIComponent(member.membership_id)}`, { method: "PATCH", body: JSON.stringify({ role: next }) }); await load(); setNote({ tone: "ok", text: `${member.email} is now ${next.toLowerCase()}.` }); }
    catch (cause) { setNote({ tone: "error", text: message(cause, "Could not change that role.") }); }
  }
  return <section className="card settings-card" aria-labelledby="team-heading">
    <h2 id="team-heading">Team</h2>
    <p className="muted">Invite colleagues who will connect sources, install Guards or review evidence.</p>
    {canManage && <form className="form invite-form" onSubmit={invite}>
      <label>Email<input type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="colleague@company.com" required/></label>
      <label>Role<select value={role} onChange={e => setRole(e.target.value)}>{ROLES.filter(r => r !== "OWNER").map(r => <option key={r} value={r}>{r.charAt(0) + r.slice(1).toLowerCase()}</option>)}</select></label>
      <PendingButton className="button compact" pending={pending}><UserPlus size={15}/>Send invite</PendingButton>
    </form>}
    {canManage && <p className="muted small">{ROLE_HELP[role]}</p>}
    {note && <Notice tone={note.tone}>{note.text}</Notice>}
    {members === null ? <p className="muted">Loading members…</p> : <table className="table">
      <thead><tr><th>Member</th><th>Role</th></tr></thead>
      <tbody>{members.map(member => <tr key={member.membership_id}>
        <td>{member.email}{member.user_id === account?.user.id && <span className="pill">You</span>}</td>
        <td>{canManage && member.user_id !== account?.user.id
          ? <select aria-label={`Role for ${member.email}`} value={member.role} onChange={e => void changeRole(member, e.target.value)}>{ROLES.map(r => <option key={r} value={r}>{r.charAt(0) + r.slice(1).toLowerCase()}</option>)}</select>
          : member.role.charAt(0) + member.role.slice(1).toLowerCase()}</td>
      </tr>)}</tbody>
    </table>}
  </section>;
}

function ApiKeys() {
  const { account } = useAccount();
  const allowed = account?.role === "OWNER" || account?.role === "ADMIN";
  const [rows, setRows] = useState<ApiKeyRow[] | null>(null);
  const [label, setLabel] = useState(""), [days, setDays] = useState(90);
  const [created, setCreated] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");
  const load = useCallback(async () => {
    try { setRows(await api<ApiKeyRow[]>("/api/v1/api-keys")); setError(""); }
    catch (cause) { setError(message(cause, "Could not load API keys.")); }
  }, []);
  useEffect(() => { if (allowed) queueMicrotask(() => void load()); }, [allowed, load]);
  async function create(event: FormEvent) {
    event.preventDefault(); setPending(true); setError(""); setCreated(null);
    try {
      const result = await api<{ api_key: string }>("/api/v1/api-keys", { method: "POST", body: JSON.stringify({ label, expires_in_days: days }) });
      setCreated(result.api_key); setLabel(""); await load();
    } catch (cause) { setError(message(cause, "Could not create the key.")); }
    finally { setPending(false); }
  }
  async function revoke(id: string) {
    if (!window.confirm("Revoke this API key? Anything using it will stop working immediately.")) return;
    try { await api(`/api/v1/api-keys/${encodeURIComponent(id)}`, { method: "DELETE" }); await load(); }
    catch (cause) { setError(message(cause, "Could not revoke the key.")); }
  }
  if (account && !allowed) return <section className="card settings-card"><h2>API keys</h2><p className="muted">Only owners and admins can manage API keys.</p></section>;
  return <section className="card settings-card" aria-labelledby="keys-heading">
    <h2 id="keys-heading"><KeyRound size={17}/>API keys</h2>
    <p className="muted">Use API keys for CI pipelines and automation. Keys are shown once — store them in your secret manager.</p>
    <form className="form invite-form" onSubmit={create}>
      <label>Name<input value={label} onChange={e => setLabel(e.target.value)} placeholder="e.g. GitHub Actions" maxLength={200} required/></label>
      <label>Expires<select value={days} onChange={e => setDays(Number(e.target.value))}><option value={30}>30 days</option><option value={90}>90 days</option><option value={365}>1 year</option></select></label>
      <PendingButton className="button compact" pending={pending}>Create key</PendingButton>
    </form>
    {created && <div className="key-once" role="status"><b>Copy this key now — it won’t be shown again.</b><code>{created}</code>
      <button type="button" className="text-button" onClick={() => void navigator.clipboard?.writeText(created)}><Copy size={13}/>Copy</button></div>}
    {error && <p className="form-error" role="alert">{error}</p>}
    {rows && <table className="table">
      <thead><tr><th>Name</th><th>Expires</th><th>Last used</th><th><span className="sr-only">Actions</span></th></tr></thead>
      <tbody>{rows.filter(row => !row.revoked).map(row => <tr key={row.id}><td>{row.label}</td><td>{when(row.expires_at)}</td><td>{row.last_used_at ? when(row.last_used_at) : "Never"}</td>
        <td className="row-actions"><button className="text-button danger-text" onClick={() => void revoke(row.id)}><Trash2 size={13}/>Revoke</button></td></tr>)}
        {rows.filter(row => !row.revoked).length === 0 && <tr><td colSpan={4} className="muted">No API keys yet.</td></tr>}</tbody>
    </table>}
  </section>;
}

export default function Settings() {
  const [tab, setTab] = useState<Tab>("workspace");
  const tabs: Array<[Tab, string]> = [["workspace", "Workspace"], ["security", "Account & security"], ["team", "Team"], ["api", "API keys"]];
  return <ProtectedPage>
    <PageHeader eyebrow="SETTINGS" title="Settings" description="Manage your workspace, your sign-in security, your team and automation keys."/>
    <div className="tabs" role="tablist" aria-label="Settings sections">
      {tabs.map(([id, label]) => <button key={id} role="tab" id={`tab-${id}`} aria-selected={tab === id} aria-controls={`panel-${id}`}
        className={tab === id ? "active" : ""} onClick={() => setTab(id)}>{label}</button>)}
    </div>
    <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`} className="settings-panel">
      {tab === "workspace" && <WorkspaceSection/>}
      {tab === "security" && <section className="card settings-card"><h2>Account & security</h2><PasswordForm/><TwoFactor/><Sessions/></section>}
      {tab === "team" && <Team/>}
      {tab === "api" && <ApiKeys/>}
    </div>
  </ProtectedPage>;
}
