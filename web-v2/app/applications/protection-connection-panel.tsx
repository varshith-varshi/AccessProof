"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { api, type AIApplication, type Guard, type ProtectionStatus } from "../../lib/api";

type PairedInstallation = { state: string; received_at?: string | null };
type Verification = {
  run_id: string | null;
  state: string;
  guard?: { connectivity: string; security_readiness: string; heartbeat_age_seconds: number | null };
};
type Route = { route_certification?: { certified: boolean; status: string } };
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
  const gatewayPaired = review?.pairing.state === "installation_reported_unverified";
  const routeCertified = review?.route.route_certification?.certified === true;
  // A pairing report proves installer contact, not a live Gateway. Likewise a
  // heartbeat proves Guard connectivity, not security readiness.
  const activationCheckable = !!guardReady && !!gatewayPaired && !busy;

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
    <p>First check your Guard and Gateway. Once the protection route is ready, enable protection here, then test your RAG separately. No test questions or worksheets are needed on this website.</p>
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
        <b>Gateway installation</b>
        <strong>{!review ? "Checking…" : gatewayPaired ? "Paired" : "Not paired"}</strong>
        <small>Pairing confirms installation, not current Gateway liveness.</small>
      </div>
      <div className="onboard-fact">
        <b>Gateway protected route</b>
        <strong>{!review ? "Checking…" : routeCertified ? "Verified" : "Not verified active"}</strong>
        <small>Independent customer-route certification is required for verified Protect.</small>
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
    {review && !activationCheckable && <p role="status" className="muted">
      Protection cannot be activated yet. The Guard must be connected and security-ready, and the Gateway must be paired.
      Fix the connection or policy issue and check again. Do not attempt to bypass a degraded Guard.
    </p>}
    {review && activationCheckable && !routeCertified && <p role="status" className="muted">
      Guard and Gateway pairing prerequisites are present. You may request activation, but it will remain pending until
      the actual Gateway route and source authorization are verified by the backend.
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
    {error && <p role="alert" className="form-error">{error}</p>}
    <div style={{ display: "flex", gap: 15, flexWrap: "wrap" }}>
      <Link href="/guards">Check Guard →</Link>
      <Link href={`/onboarding?application=${id}`}>Gateway setup →</Link>
      <Link href="/protection">Production security status →</Link>
    </div>
  </section>;
}
