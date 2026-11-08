"use strict";
const $ = (id) => document.getElementById(id);
let sessions = {};
let permissions = {};
let runtimeReady = false;
function setText(id, value) { $(id).textContent = value == null ? "—" : String(value); }
function refreshExpectation() {
  const actor = $("actor").value;
  const doc = $("diagnostics").open ? $("document").value : "";
  setText("expectation", doc
    ? `Diagnostic: expected SharePoint permission is ${permissions[actor]?.[doc] ?? "Unknown"} for ${actor}`
    : "Automatic retrieval: AccessProof decides which relevant chunks this employee can use.");
}
function showIdentity(actor, data) {
  const signedIn = data?.state === "SIGNED_IN";
  sessions[actor] = signedIn;
  setText(actor + "-status", signedIn
    ? `✓ Verified Microsoft session: ${data.user || actor} (expires in ${Math.ceil(data.expires_in_seconds / 60)} min)`
    : "Sign-in required. A name selected in the UI is not authentication.");
  const link = $(actor + "-login");
  link.hidden = signedIn || !data?.sign_in_url;
  if (!link.hidden) link.href = data.sign_in_url;
  else link.removeAttribute("href");
}
async function refresh() {
  try {
    const [response, readinessResponse] = await Promise.all([
      fetch("/api/identities", {cache: "no-store", credentials: "same-origin"}),
      fetch("/api/readiness", {cache: "no-store", credentials: "same-origin"}),
    ]);
    if (!response.ok || !readinessResponse.ok) throw new Error(`Operator session unavailable (${response.status})`);
    const data = await response.json();
    const health = await readinessResponse.json();
    runtimeReady = health.ready_to_test === true;
    setText("runtime-status", runtimeReady
      ? "✓ Gateway and Guard are ready for human validation"
      : "NOT READY — protected chatbot testing is blocked");
    setText("runtime-details", `Gateway: ${health.gateway_ready ? "Ready" : "Not ready"} · ` +
      `Guard: ${health.guard_ready ? "Ready" : "Not ready"} · ` +
      `Identity: ${health.identity_ready ? "Ready" : "Not ready"} · ` +
      `Authorization revisions: ${health.authorization_revisions_ready ? "Ready" : "Not ready"} · ` +
      `Signed index: ${health.rag_signed_index_ready ? "Fresh and verified" : (health.signed_index_reason || "Not ready")} · ` +
      `Indexed docs: ${health.indexed_documents} · Guard policy: ${health.guard_policy_version ?? "Unknown"} · ` +
      `Independent SharePoint provider verification: ${health.live_provider_verified ? "Verified" : "Not verified"}`);
    permissions = data.expected || {};
    for (const actor of ["alice", "bob"]) showIdentity(actor, data.actors?.[actor]);
    if ($("document").options.length < 2) {
      $("document").replaceChildren(new Option("Use automatic retrieval (default)", ""));
      for (const doc of data.documents || []) {
        const option = new Option(doc, doc);
        $("document").add(option);
      }
      $("document").value = "";
    }
    $("ask").disabled = !runtimeReady || !sessions[$("actor").value];
    refreshExpectation();
  } catch (error) {
    $("ask").disabled = true;
    setText("result-state", `Sign-in status unavailable: ${error.message}`);
  }
}
$("refresh").addEventListener("click", refresh);
$("actor").addEventListener("change", () => {
  $("ask").disabled = !runtimeReady || !sessions[$("actor").value];
  refreshExpectation();
});
$("document").addEventListener("change", refreshExpectation);
$("diagnostics").addEventListener("toggle", refreshExpectation);
$("chat-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const actor = $("actor").value;
  // A collapsed diagnostic panel is never a hidden file-selection override.
  const document_name = $("diagnostics").open ? $("document").value : "";
  if (!runtimeReady || !sessions[actor]) { setText("result-state", "Guard/Gateway must be ready and the employee must sign in before sending a request."); return; }
  $("ask").disabled = true;
  setText("result-state", "Finding relevant SharePoint chunks, rechecking cached content permissions, then generating a protected answer…");
  setText("decision", "In progress");
  setText("actual", "Pending");
  setText("expected", document_name ? permissions[actor]?.[document_name] ?? "Unknown" : "Not predetermined — live Gateway decision");
  setText("audit", "Not independently checked");
  setText("answer", "Generating answer from authorized context…");
  setText("cache-status", "Signed chunk cache: checking current employee permissions on every hit.");
  try {
    const res = await fetch("/api/chat", {
      method: "POST", credentials: "same-origin", cache: "no-store",
      headers: {"Content-Type": "application/json", "X-AccessProof-Human-Test": "1"},
      body: JSON.stringify(document_name
        ? {actor, document_name, question: $("question").value}
        : {actor, question: $("question").value}),
    });
    const result = await res.json();
    if (!res.ok || result.outcome === "INCONCLUSIVE") {
      setText("result-state", "The protected answer is temporarily unavailable");
      setText("decision", `Unavailable (${result.http_status || res.status})`);
      setText("actual", result.reason || result.detail || "Protected route unavailable");
      setText("answer", "I couldn't complete a secure response. Please retry after checking Gateway readiness.");
      setText("cache-status", "Cache authorization status unavailable; no content released.");
    } else {
      setText("decision", result.outcome);
      setText("actual", result.outcome === "ALLOWED" ? "ALLOW" : "DENY");
      const diagnostic = result.retrieval_mode === "diagnostic" && result.expected !== "NOT_PREDETERMINED";
      const matches = result.outcome === "ALLOWED" ? result.expected === "ALLOW" : result.expected === "DENY";
      setText("result-state", result.outcome === "ALLOWED"
        ? "Answer generated from currently authorized SharePoint context"
        : "No accessible information was available for this question");
      // Do not reveal that a restricted file exists or show its title.
      setText("answer", result.outcome === "ALLOWED"
        ? result.answer
        : "I couldn't find information available to you that answers this question.");
      setText("cache-status", result.outcome === "ALLOWED"
        ? `Signed chunk cache: ${result.cache_hit ? "HIT" : "MISS"} · ${result.cache_authorization === "CURRENT_EMPLOYEE_RECHECKED_BY_GATEWAY" ? "permissions rechecked by Gateway" : "authorization verification unavailable"}`
        : "No unauthorized cached information was released.");
      if (diagnostic) setText("expected", matches ? "Diagnostic expectation matched" : "UNEXPECTED DIAGNOSTIC RESULT — investigate");
      if (result.decision_id) setText("audit", `Gateway decision ID: ${result.decision_id}; Guard audit still requires confirmation`);
    }
  } catch (error) {
    setText("result-state", "The protected answer is temporarily unavailable");
    setText("decision", "No reliable decision");
    setText("answer", error.message);
  } finally {
    $("ask").disabled = !runtimeReady || !sessions[$("actor").value];
  }
});
void refresh();
setInterval(() => { if (document.visibilityState === "visible") void refresh(); }, 7000);
