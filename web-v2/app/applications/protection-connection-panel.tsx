"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { api, type AIApplication, type Guard, type ProtectionStatus } from "../../lib/api";

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
type Route = Partial<ProtectionStatus> & {
  route_certificate?: { certified: boolean; status: string };
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
  const [review, setReview] = useState<Review | null>(null);
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
      // The initial GET may already say Protect is active; a previous Enable
      // click can have completed asynchronously before this panel opened.
      if (typeof protection.state === "string") {
        setResult(protection as ProtectionStatus);
      }
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
  useEffect(() => {
    // Machine-authenticated Guard acknowledgment follows the admin request.
    // Watch the backend's read-only status, never treat the stale POST response
    // as authoritative, and don't make a second Enable request.
    let active = true;
    const timer = window.setInterval(async () => {
      if (document.visibilityState !== "visible") return;
      try {
        const latest = await api<ProtectionStatus>(base + "/protection/status");
        if (active && typeof latest.state === "string") {
          setResult(latest);
        }
      } catch { /* transient failure: keep the last verified state */ }
    }, 4_000);
    return () => { active = false; window.clearInterval(timer); };
  }, [base]);

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
  const missingEvidence = review?.route.checks?.filter(check => !check.ok && check.required_for_activation !== false) ?? [];
  const sourceCertificatePending = review?.route.checks?.some(check =>
    check.code === "MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED" && !check.ok &&
    check.required_for_activation === false,
  ) ?? false;
  const protectActive = result?.state === "protected" && result.guard_acknowledged === true;
  const firstSourceIssue = missingEvidence.find(check => (
    check.code === "PERMISSION_SOURCE_USABLE"
    || check.code === "MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED"
    || check.code === "V1_PROVIDER_SCOPE"
  ));
  // A pairing report proves installer contact, not a live Gateway. Likewise a
  // heartbeat proves Guard connectivity, not security readiness.
  // All *required* backend prerequisites must pass. For a never-certified,
  // exact SharePoint profile, the signed source certificate can instead be
  // earned by human testing after validation-first Protect activation.
  // A newly paired Gateway cannot be enforcement-ready until the Guard
  // receives the explicit admin-requested protect_pending binding. Allow
  // staging with a connected Guard+Gateway, but the backend must keep Protect
  // pending until machine health and all mandatory checks are green.
  const readinessHandshake = ["PRODUCTION_OIDC_READY", "GATEWAY_LIVE_AND_ENFORCEMENT_READY"];
  const activationCheckable = !!guardConnected && !!gatewayConnected &&
    !!review?.route.checks?.length && review.route.checks.every(item =>
      item.ok || item.required_for_activation === false || readinessHandshake.includes(item.code)
    ) && !busy && !protectActive;

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
    <p>Check that your Guard, fresh SharePoint permissions, identity mappings, and Gateway are ready. For a first-time source, you can enable validation-first Protect before receiving the optional independent source certificate, then test using approved synthetic documents. Uncertified protection must never be described as production-certified.</p>
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
    {sourceCertificatePending && <p className="onboard-next-action" role="status">
      <strong>Source certification pending — manual validation comes after activation.</strong>
      <br />This is a validation-first activation with fail-closed authorization, not independent SharePoint certification.
      Use only approved test documents until Alice/Bob permission and revocation tests pass.
    </p>}
    <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
      <button className="button compact secondary" disabled={busy} type="button" onClick={() => void check()}>
        {busy ? "Checking…" : "Check Guard & Gateway"}
      </button>
      <button className="button compact" disabled={!activationCheckable} type="button" onClick={() => void enable()}>
        {busy ? "Checking…" : protectActive ? "Protect Active" : "Enable Protection"}
      </button>
    </div>
    {review && !activationCheckable && !protectActive && <div role="status" className="muted">
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
    {review && activationCheckable && !protectActive && <p role="status" className="muted">
      Required source, policy, and identity-mapping checks have passed. An Owner or Admin may
      request Protect; the Guard/Gateway must become enforcement-ready before protection is active.
      If independent source certification is pending, test with approved canary documents first.
    </p>}
    {result && <div role="status" className="onboard-fact">
      <b>{result.state === "protected" && result.guard_acknowledged
        ? "Protection active — now test your RAG"
        : "Protection not active yet"}</b>
      <p>{result.state === "protected" && result.guard_acknowledged
        ? "Guard protection is acknowledged. Open your own RAG and test it outside AccessProof."
        : result.message || "Waiting for the Guard to acknowledge Protect. This view updates automatically."}</p>
      {result.state !== "protected" && <small>Current status: {(result.reason_code ?? "AWAITING_GUARD_ACK").replaceAll("_", " ").toLowerCase()}.
        Review the detailed security status for diagnosis; this is not a request to perform tests inside AccessProof.</small>}
    </div>}
    {result?.state === "protected" && result.guard_acknowledged &&
      <section className="card section" aria-label="Post-activation customer manual validation">
        <h3>Manual validation after Protect activation</h3>
        <p>Use two distinct approved Entra employees and test-only documents. Verify allowed and forbidden content, then revoke test access and confirm denial. A source certificate is not a prerequisite to start these tests, but a successful chatbot response is not independent certification. Report unexpected access or refusal to AccessProof support.</p>
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
