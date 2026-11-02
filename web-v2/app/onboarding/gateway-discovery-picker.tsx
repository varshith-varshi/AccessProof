"use client";

import { useCallback, useEffect, useState } from "react";
import { api } from "../../lib/api";

type Candidate = {
  stable_id: string; display_name: string; compose_project: string;
  service: string; state: "SUPPORTED" | "REQUIRES_INTEGRATION" | "AMBIGUOUS" | "NON_AI_SERVICE";
};
type Discovery = {
  state: "not_ready" | "awaiting_selection" | "selected";
  applications: Candidate[]; selected_id: string | null; production_certification: false;
};

export function GatewayDiscoveryPicker({ applicationId, installed }: { applicationId: string; installed: boolean }) {
  const [discovery, setDiscovery] = useState<Discovery | null>(null);
  const [selected, setSelected] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const base = "/api/v1/current/ai-applications/" + encodeURIComponent(applicationId) + "/gateway-discovery";
  const refresh = useCallback(async () => {
    try {
      const state = await api<Discovery>(base);
      setDiscovery(state);
    } catch {
      setDiscovery(null);
    }
  }, [base]);
  useEffect(() => {
    queueMicrotask(() => void refresh());
    if (installed) return;
    const timer = setInterval(() => void refresh(), 4000);
    return () => clearInterval(timer);
  }, [installed, refresh]);
  const confirm = async () => {
    if (!selected || busy || installed || discovery?.state !== "awaiting_selection") return;
    setBusy(true);
    setError("");
    try {
      await api(base + "/select", { method: "POST", body: JSON.stringify({ stable_id: selected }) });
      await refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Selection failed. Check your pairing and try again.");
    } finally {
      setBusy(false);
    }
  };
  if (installed) return null;
  const choices = discovery?.applications.filter(row => row.state !== "NON_AI_SERVICE") ?? [];
  return <section className="onboard-discovery" aria-label="Choose your discovered chatbot">
    <b>Choose one chatbot to connect</b>
    {discovery?.state === "not_ready" || !discovery ? <>
      <p>Run the downloaded installer on the Docker host. Its discovered chatbots will appear here while your one-time pairing is valid.</p>
      <small>AccessProof does not remotely scan your host or request your private files.</small>
    </> : <>
      <p>Choose exactly one compatible chatbot. The installer rechecks its real Docker identity and integration before installing a Gateway.</p>
      <div className="onboard-choices" role="radiogroup" aria-label="Discovered chatbots">
        {choices.map(row => <label key={row.stable_id}
          className={"onboard-choice " + (row.state !== "SUPPORTED" ? "disabled" : "")}>
          <input type="radio" name={"chatbot-" + applicationId} value={row.stable_id}
            checked={(discovery.selected_id || selected) === row.stable_id}
            disabled={busy || discovery.state === "selected" || row.state !== "SUPPORTED"}
            onChange={() => setSelected(row.stable_id)}/>
          <span><strong>{row.display_name}</strong><small>{row.compose_project} / {row.service}</small></span>
          <em>{row.state === "SUPPORTED" ? "Compatible candidate" : "Adapter required"}</em>
        </label>)}
      </div>
      {discovery.state === "selected"
        ? <div className="onboard-success">✓ One chatbot selected. The local installer can continue its compatibility checks.</div>
        : <button type="button" className="button" disabled={!selected || busy} onClick={() => void confirm()}>
            Confirm this one chatbot
          </button>}
      <small>Other chatbots remain untouched. A confirmed choice cannot be changed without generating a fresh pairing file.</small>
    </>}
    {error && <p className="onboard-error" role="alert">{error}</p>}
    <button type="button" className="button secondary" disabled={busy} onClick={() => void refresh()}>
      Refresh discovered chatbots
    </button>
  </section>;
}
