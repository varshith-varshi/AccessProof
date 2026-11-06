"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { api, type AIApplication, type Guard, type ProtectionStatus } from "../../lib/api";
import { useAccount } from "../app-shell";

type GatewayConnectivity = {
  connection: "CONNECTED" | "DISCONNECTED" | "UNKNOWN";
  enforcement_ready_reported: boolean;
  heartbeat_age_seconds: number | null;
  reason: string | null;
};
type PairedInstallation = {
  state: string;
  received_at?: string | null;
  gateway_connectivity?: GatewayConnectivity;
};
type Verification = {
  run_id: string | null;
  state: string;
  guard?: { connectivity: string; security_readiness: string; heartbeat_age_seconds: number | null };
};
type Route = {
  route_certificate?: { certified: boolean; status: string };
  checks?: Array<{ code: string; ok: boolean; reason: string | null }>;
};
type Review = {
  guard: Guard | null;
  pairing: PairedInstallation;
  verification: Verification;
  route: Route;
};

export function ProtectionConnectionPanel({ application, onClose, onChange }: {
  application: AIApplication;
  onClose: () => void;
  onChange: () => Promise<void>;
}) {
  const { account } = useAccount();
  const [review, setReview] = useState<Review | null>(null);
  const [approvalText, setApprovalText] = useState("");
  const [approvalNotice, setApprovalNotice] = useState("");
  const [result, setResult] = useState<ProtectionStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const id = encodeURIComponent(application.application_id);
  const base = `/api/v1/current/ai-applications/${id}`;
  const check = useCallback(async () => {
    setBusy(true);
    setError("");
    try {
      const [guards, pairing, verification, protection] = await Promise.all([
        api<Guard[]>("/api/v1/guards"),
        api<PairedInstallation>(base + "/gateway-pairing"),
        api<Verification>(base + "/verification-run"),
        api<Route>(base + "/protection/status"),
      ]);
      setReview({
        guard: guards.find(value => value.id === application.guard_id) ?? null,
        pairing,
        verification,
        route: protection,
      });
    } catch (cause) {
      setReview(null);
      setError(cause instanceof Error ? cause.message : "Unable to check Guard and Gateway status.");
    } finally {
      setBusy(false);
    }
  }, [base, application.guard_id]);
  useEffect(() => {
    queueMicrotask(() => void check());
  }, [check]);

  const guardConnected = review?.verification.guard?.connectivity === "CONNECTED";
  const guardReady = guardConnected && review?.verification.guard?.security_readiness === "READY";
  const gatewayLive = review?.pairing.gateway_connectivity;
  const gatewayConnected = gatewayLive?.connection === "CONNECTED";
  const gatewayReady = gatewayConnected && gatewayLive?.enforcement_ready_reported === true;
  // A live authenticated heartbeat supersedes the one-time pairing receipt.
  const gatewayPaired = review?.pairing.state === "installation_reported_unverified" || gatewayReady;
  const routeCertified = review?.route.route_certificate?.certified === true;
  const installationState = review?.pairing.state;
  const installationLabel = installationState === "installation_reported_unverified"
    ? "Installation reported"
    : installationState === "installation_reported_historical" ? "Previously installed"
    : installationState === "awaiting_customer_install" ? "Awaiting installer"
    : installationState === "pairing_expired" ? "Pairing expired"
    : "No installation report";
  const missingEvidence = review?.route.checks?.filter(check => !check.ok) ?? [];
  const firstSourceIssue = missingEvidence.find(check => (
    check.code === "PERMISSION_SOURCE_USABLE"
    || check.code === "MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED"
    || check.code === "V1_PROVIDER_SCOPE"
  ));
  // A pairing report proves installer contact, not a live Gateway. Likewise a
  // heartbeat proves Guard connectivity, not security readiness.
  const activationCheckable = !!guardReady && !!gatewayPaired && !busy;
  const approvalPhrase = `APPROVE PROTECT ${application.application_id}`;
  const approvalGate = review?.route.checks?.find(item => item.code === "HUMAN_ACTIVATION_APPROVAL_REQUIRED");
  // The backend revalidates every gate and enforces interactive OWNER authorization.
  // UI eligibility is only guidance; an installer receipt or Guard heartbeat is not certification.
  const approvalEligible = account?.role === "OWNER" && guardReady && gatewayReady &&
    approvalGate?.ok === false && !!review?.route.checks?.length &&
    review.route.checks.every(item => item.ok || item.code === "HUMAN_ACTIVATION_APPROVAL_REQUIRED");

  const approve = async () => {
    if (!approvalEligible || approvalText !== approvalPhrase || busy) return;
    setBusy(true);
    setError("");
    setApprovalNotice("");
    try {
      const result = await api<{ state: string }>(base + "/protection/approve", {
        method: "POST",
        body: JSON.stringify({ confirm_text: approvalText, reviewer: account!.user.email }),
      });
      setApprovalText("");
      setApprovalNotice(result.state === "approved_awaiting_guard_ack"
        ? "Owner approval recorded. Enable Protection to request Guard acknowledgment; approval alone does not activate Protect."
        : "Owner approval recorded. Check the remaining activation gates.");
      await check();
      await onChange();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Owner approval was not accepted. Review the current readiness checks.");
    } finally { setBusy(false); }
  };

  const enable = async () => {
    if (!activationCheckable || busy) return;
    setBusy(true);
    setError("");
    setResult(null);
    try {
      const status = await api<ProtectionStatus>(base + "/protection/enable", { method: "POST" });
      setResult(status);
      await onChange();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Protection activation failed.");
    } finally {
      setBusy(false);
    }
  };

  return <section className="card create-panel" aria-label="Guard and Gateway connection check">
    <div className="panel-head">
      <div><p className="label">PROTECTION ACTIVATION</p><h2>{application.name}</h2></div>
      <button className="text-button" type="button" onClick={onClose}>Close</button>
    </div>
    <p>Check that your Guard, trusted SharePoint permissions, and Gateway are enforcing the current application. After Protect is active, your team can optionally test access, denial, tampering and revocation using its own approved identities. Those four scenarios are not activation requirements.</p>
    <div style={{ display: "grid", gap: 10, gridTemplateColumns: "repeat(auto-fit,minmax(195px,1fr))" }} role="status">
      <div className="onboard-fact">
        <b>Guard connection</b>
        <strong>{!review ? "Checking…" : guardConnected ? "Connected" : "Offline / unknown"}</strong>
        <small>{review?.guard ? `${review.guard.name} · policy ${review.guard.active_policy_version ?? "none"}` : "No enrolled Guard status received"}</small>
      </div>
      <div className="onboard-fact">
        <b>Guard enforcement readiness</b>
        <strong>{!review ? "Checking…" : guardReady ? "Ready" : review.verification.guard?.security_readiness?.toLowerCase() ?? "Not verified"}</strong>
        <small>Connected does not mean security-ready.</small>
      </div>
      <div className="onboard-fact">
        <b>Gateway installation record</b>
        <strong>{!review ? "Checking…" : installationLabel}</strong>
        <small>{gatewayPaired
          ? "Recent installer receipt recorded. Live Gateway connectivity still requires customer-host verification."
          : installationState === "installation_reported_historical"
            ? "Durable installation record found. Current Gateway liveness and route readiness are NOT verified."
            : "A missing or expired pairing receipt does not mean your Gateway stopped running."}</small>
      </div>
      <div className="onboard-fact">
        <b>Gateway live connection</b>
        <strong>{!review ? "Checking…" : gatewayReady ? "Connected · ready"
          : gatewayConnected ? "Connected · not ready"
          : gatewayLive?.connection === "DISCONNECTED" ? "Disconnected" : "Unknown"}</strong>
        <small>{gatewayLive?.heartbeat_age_seconds != null
          ? `Last authenticated heartbeat ${gatewayLive.heartbeat_age_seconds}s ago${gatewayLive.reason ? ` · ${gatewayLive.reason.replaceAll("_", " ").toLowerCase()}` : ""}.`
          : "No authenticated Gateway heartbeat received. Installers before this release report Unknown."}</small>
      </div>
      <div className="onboard-fact">
        <b>Optional route challenge certificate</b>
        <strong>{!review ? "Checking…" : routeCertified ? "Reference route certified" : "Not certified"}</strong>
        <small>{review?.route.route_certificate?.status
          ? `Certificate status: ${review.route.route_certificate.status}. This does not attest every customer route.`
          : "Current route certification has not been confirmed."}</small>
      </div>
    </div>
    <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
      <button className="button compact secondary" disabled={busy} type="button" onClick={() => void check()}>
        {busy ? "Checking…" : "Check Guard & Gateway"}
      </button>
      <button className="button compact" disabled={!activationCheckable} type="button" onClick={() => void enable()}>
        {busy ? "Checking…" : "Enable Protection"}
      </button>
    </div>
    {review && approvalGate?.ok === false && <section className="owner-approval-panel" aria-label="Owner Protect approval">
      <h3>Owner approval required</h3>
      {account?.role !== "OWNER" ? <p>Only a signed-in organization Owner can authorize production Protect after the verified route is certified. Ask your workspace Owner to sign in.</p> : <>
        <p>Approval is an explicit, audited human decision. Source authorization, Guard readiness and the installed Gateway must pass all operational checks first. The four optional manual scenarios are not required for approval. Approval alone does not activate Protect.</p>
        <p className="muted small">Current reviewer: {account.user.email}</p>
        <label>Type <code>{approvalPhrase}</code> to confirm
          <input aria-label="Owner approval confirmation" autoComplete="off" spellCheck={false}
            value={approvalText} onChange={event => setApprovalText(event.target.value)}
            disabled={!approvalEligible || busy} placeholder={approvalPhrase} />
        </label>
        <button className="button compact" type="button" disabled={!approvalEligible || approvalText !== approvalPhrase || busy}
          onClick={() => void approve()}>{busy ? "Reviewing…" : "Approve Protect as Owner"}</button>
        {!approvalEligible && <p className="muted small">Approval is unavailable until Guard and Gateway report ready and all required source and runtime checks pass.</p>}
      </>}
    </section>}
    {approvalNotice && <p className="notice-ok" role="status">{approvalNotice}</p>}
    {review && !activationCheckable && <div role="status" className="muted">
      <p>Protection is not active. The Guard must be connected and security-ready, and the installer must report a valid
        binding. We cannot confirm live Gateway availability from a one-time pairing receipt.</p>
      {!guardReady && <p><strong>Guard is not ready.</strong> Check the customer-host Guard health and source ACL synchronization.
        Source permission failures must be resolved rather than bypassed.</p>}
      {!gatewayPaired && <p><strong>{installationState === "installation_reported_historical"
        ? "Historical installation needs fresh verification." : "Installation receipt missing."}</strong>
        {installationState === "installation_reported_historical"
          ? " Your existing installer was recorded previously, but a historical report cannot prove it is connected now. "
          : " If you already installed the Gateway, "}
        Generate a fresh pairing file under <Link href={`/onboarding?application=${id}`}>Get Started</Link> and
        re-run the installer in the existing RAG Compose project to re-report that installation.
        Do not reinstall another Gateway just to refresh the dashboard.</p>}
      {firstSourceIssue && <p><strong>Source authorization blocker:</strong> {firstSourceIssue.reason
        ?? firstSourceIssue.code.replaceAll("_", " ").toLowerCase()}</p>}
    </div>}
    {review && activationCheckable && <p role="status" className="muted">
      You can request activation after the source authorization and live Gateway readiness checks pass. The four manual security scenarios can be run after Protect is active.
    </p>}
    {result && <div role="status" className="onboard-fact">
      <b>{result.state === "protected" && result.guard_acknowledged
        ? "Protection active — now test your RAG"
        : "Protection not active yet"}</b>
      <p>{result.state === "protected" && result.guard_acknowledged
        ? "Guard protection is acknowledged. Open your own RAG and test it outside AccessProof."
        : result.message || "Protection needs additional security readiness before it can be activated."}</p>
      {result.state !== "protected" && <small>Current blocker: {result.reason_code.replaceAll("_", " ").toLowerCase()}.
        Review the detailed security status for diagnosis; this is not a request to perform tests inside AccessProof.</small>}
    </div>}
    {result?.state === "protected" && result.guard_acknowledged &&
      <section className="card section" aria-label="Post-activation customer manual validation">
        <h3>Optional manual validation after Protect is active</h3>
        <p>Test with your own approved employee identities and test-only documents. No Alice/Bob accounts or four-probe checklist are required for your manual review. Report unexpected access or refusal to your AccessProof support contact.</p>
        <p className="muted small">Suggested scenarios: an authorized document, a denied document, tampered test content, and permission revocation during a response. Do not use confidential canaries or disable production enforcement to run these tests.</p>
      </section>}
    {error && <p role="alert" className="form-error">{error}</p>}
    <div style={{ display: "flex", gap: 15, flexWrap: "wrap" }}>
      <Link href="/guards">Check Guard →</Link>
      <Link href={`/onboarding?application=${id}`}>Gateway setup →</Link>
      <Link href="/protection">Production security status →</Link>
    </div>
  </section>;
}
