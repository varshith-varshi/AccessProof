import { expect, test } from "@playwright/test";

const decisionBuckets = () => ({ layer1: { allow: 0, block: 0, would_allow: 0, would_block: 0 }, layer2: { allow: 0, block: 0, would_allow: 0, would_block: 0 } });
const protectionBlock = () => ({
  applications_registered: 0, applications_protected_verified: 0, applications_not_verified: 0, applications_unsupported: 0,
  guards: { online: 0, offline: 0, not_enrolled: 0, revoked: 0 }, sources_fresh: 0, sources_total: 0,
  decisions_24h: { ...decisionBuckets(), telemetry: "NO_DATA", total: 0 }, latest_decision_at: null,
});
const dashboardJson = (overrides: Record<string, unknown> = {}) => ({
  ai_applications: 0, guards_online: 0, guards_total: 0, permission_sources: 0, blocked_requests: 0,
  recent_activity: [], protection: protectionBlock(), ...overrides,
});
const protectionOverviewJson = (applications: unknown[] = []) => ({
  generated_at: "2026-10-24T10:00:00Z",
  state_counts: {
    NOT_CONFIGURED: 0, CONNECTED: 0, VALIDATING: 0, SHADOW: 0, PROTECT_PENDING: 0, PROTECTED_VERIFIED: 0,
    DEGRADED: 0, STALE: 0, BLOCKED: 0, CERTIFICATION_EXPIRED: 0, UNSUPPORTED: 0, UNKNOWN: 0,
  },
  totals: {
    applications_registered: applications.length, applications_protected_verified: 0,
    applications_not_verified: applications.length, applications_unsupported: 0,
    guards_total: 0, guards_online: 0, guards: { online: 0, offline: 0, not_enrolled: 0, revoked: 0 },
    sources_total: 0, sources_fresh: 0, sources_stale: 0,
  },
  applications,
});


test("browser console and network remain clean on public flow", async ({ page }) => {
  const consoleErrors: string[] = [];
  const failedRequests: string[] = [];
  page.on("console", message => {
    if (message.type() === "error") consoleErrors.push(message.text());
  });
  page.on("requestfailed", request => failedRequests.push(`${request.method()} ${request.url()} ${request.failure()?.errorText ?? "unknown"}`));
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Make enterprise AI respect enterprise permissions." })).toBeVisible();
  expect(consoleErrors, consoleErrors.join("\n")).toEqual([]);
  expect(failedRequests, failedRequests.join("\n")).toEqual([]);
});

test("public landing and authentication pages are usable", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Make enterprise AI respect enterprise permissions." })).toBeVisible();
  await expect(page.getByRole("link", { name: "Request a pilot" }).first()).toBeVisible();
  await page.goto("/login");
  await expect(page.getByLabel("Email")).toBeVisible();
  await expect(page.getByLabel("Password")).toBeVisible();
});

test("protected routes redirect anonymous users", async ({ page }) => {
  await page.goto("/guards");
  await expect(page).toHaveURL(/\/login\?next=%2Fguards/);
});

test("authenticated dashboard renders current authorization activity", async ({ context, page }) => {
  await context.addCookies([{ name: "accessproof_session", value: "test-session", domain: "127.0.0.1", path: "/" }]);
  await page.route("**/api/v1/current/dashboard", route => route.fulfill({ json: dashboardJson({ ai_applications: 1, guards_online: 1, guards_total: 1, permission_sources: 1, protection: { ...protectionBlock(), applications_registered: 1, applications_protected_verified: 1, applications_not_verified: 0, guards: { online: 1, offline: 0, not_enrolled: 0, revoked: 0 }, sources_total: 1, sources_fresh: 1 } }) }));
  await page.goto("/dashboard");
  await expect(page.getByRole("heading", { name: "Authorization control plane", exact: true })).toBeVisible();
  await expect(page.locator("article.card").filter({ hasText: "Verified protection" }).locator("strong")).toHaveText("1/1");
  await expect(page.getByText("Revocation-to-first-denial timing")).toBeVisible();
  await expect(page.getByText("NO DATA").first()).toBeVisible();
});

test("Guard inventory and secure enrollment flow render", async ({ context, page }) => {
  await context.addCookies([{ name: "accessproof_session", value: "test-session", domain: "127.0.0.1", path: "/" }]);
  // Simulate a slow periodic status fetch. The table should stay visible.
  let guardReads = 0;
  let notifyPoll!: () => void;
  let releasePoll!: () => void;
  const pollStarted = new Promise<void>(resolve => { notifyPoll = resolve; });
  const pendingPoll = new Promise<void>(resolve => { releasePoll = resolve; });
  await page.route("**/api/v1/guards", async route => {
    if (route.request().method() === "POST") return route.fulfill({ status: 201, json: { id: "guard-new", name: "finance-prod", environment: "production", status: "not_enrolled", health: "not_enrolled" } });
    guardReads++;
    if (guardReads === 3) {
      notifyPoll();
      await pendingPoll;
    }
    return route.fulfill({ json: [{ id: "guard-123456789", name: "Finance Guard", environment: "production", version: "1.0.0", status: "enrolled", health: "online", active_policy_version: 18, last_heartbeat_at: "2026-10-15T10:00:00Z", enrolled_at: "2026-10-10T10:00:00Z", revoked_at: null }] });
  });
  await page.route("**/api/v1/guards/guard-new/enrollments", route => route.fulfill({ status: 201, json: { enrollment_token: "AP-GUARD-ONE-TIME-TEST-TOKEN-123456789", expires_in_seconds: 900, guard_id: "guard-new" } }));
  await page.goto("/guards");
  await expect(page.getByText("Finance Guard")).toBeVisible();
  await expect(page.getByText("Online")).toBeVisible();
  await page.getByRole("button", { name: "Create Guard" }).first().click();
  await page.getByLabel("Guard name").fill("finance-prod");
  await page.getByRole("button", { name: "Create and generate token" }).click();
  await expect(page.getByText("Connect this Guard within 15 minutes.")).toBeVisible();
  await expect(page.getByRole("link", { name: /Download AccessProof Guard/ })).toHaveAttribute("href", "/api/v1/guards/download");
  await expect(page.getByText("Open the launcher for this computer.")).toBeVisible();
  await expect(page.getByRole("link", { name: /127.0.0.1:8080\/setup/ })).toBeVisible();
  await pollStarted;
  // The background request is intentionally held open: no table skeleton.
  await expect(page.getByText("Finance Guard")).toBeVisible();
  await expect(page.getByRole("table").getByText("Last heartbeat")).toBeVisible();
  releasePoll();
});

test("Google Workspace sources use operator-owned OAuth without customer secrets", async ({ context, page }) => {
  await context.addCookies([{ name: "accessproof_session", value: "test-session", domain: "127.0.0.1", path: "/" }]);
  let creations = 0;
  let consents = 0;
  await page.route("**/api/v1/current/sources/google-oauth/status", route =>
    route.fulfill({ json: { configured: true } }));
  await page.route("**/api/v1/current/sources", async route => {
    if (route.request().method() === "POST") {
      const body = route.request().postDataJSON();
      expect(body).toMatchObject({
        provider: "google-drive", name: "Finance", boundary: "drive-root", credentials: {},
      });
      creations++;
      return route.fulfill({ status: 201, json: { id: "source-1", ...body, status: "not_configured" } });
    }
    return route.fulfill({ json: [] });
  });
  await page.route("**/api/v1/current/sources/source-1/google-oauth/begin", route => {
    expect(route.request().method()).toBe("POST");
    consents++;
    return route.fulfill({ json: { authorization_url: "https://accounts.google.com/o/oauth2/v2/auth?client_id=synthetic" } });
  });
  await page.route("https://accounts.google.com/**", route =>
    route.fulfill({ status: 200, contentType: "text/html", body: "<h1>Mock Google consent</h1>" }));
  await page.goto("/sources");
  await page.getByRole("button", { name: "Connect source" }).first().click();
  await page.getByLabel("Connection name").fill("Finance");
  await page.getByLabel("Approved Google Drive root folder ID").fill("drive-root");
  await expect(page.getByLabel("Google access token")).toHaveCount(0);
  await expect(page.getByLabel("Provider")).toHaveCount(0);
  await page.getByRole("button", { name: "Connect Google Workspace" }).click();
  await expect.poll(() => creations).toBe(1);
  await expect.poll(() => consents).toBe(1);
});

test("synchronized employees render provider-stable identities", async ({ context, page }) => {
  await context.addCookies([{ name: "accessproof_session", value: "test-session", domain: "127.0.0.1", path: "/" }]);
  await page.route("**/api/v1/current/employees", route => route.fulfill({ json: [{ id: "employee-1", name: "Alice Example", email: "alice@example.com", provider: "microsoft365", stable_id: "entra-object-1", status: "active", last_synced_at: "2026-10-16T00:00:00Z", groups: [{ id: "group-1", name: "Engineering", provider: "microsoft365", stable_id: "group-object-1" }] }] }));
  await page.goto("/employees");
  await expect(page.getByText("Alice Example")).toBeVisible();
  await expect(page.getByText("entra-object-1")).toBeVisible();
  await expect(page.getByText("Engineering")).toBeVisible();
});

test("adapter catalog distinguishes enforcement from connectivity", async ({ context, page }) => {
  await context.addCookies([{ name: "accessproof_session", value: "test-session", domain: "127.0.0.1", path: "/" }]);
  await page.route("**/api/v1/current/adapters", route => route.fulfill({ json: [
    { id: "langchain-python", name: "LangChain Python", category: "RAG framework", status: "AVAILABLE", language: "Python", contract_version: "accessproof.rag/v1", pre_generation_filtering: true, output_verification: true, shadow_mode: true, protect_mode: true, installation: "Use packages.rag_sdk.LangChainAdapter", limitation: "Requires stable metadata" },
    { id: "generic-http", name: "Generic HTTP target", category: "Connectivity", status: "PARTIAL", language: "Any", contract_version: "target-config/v1", pre_generation_filtering: false, output_verification: false, shadow_mode: true, protect_mode: false, installation: "Configure a target", limitation: "Connectivity alone is not Layer 1" },
  ] }));
  await page.goto("/integrations");
  await expect(page.getByRole("heading", { name: "Adapters", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Connect your RAG in three steps" })).toBeVisible();
  await expect(page.getByRole("link", { name: "1. Connect permission source" })).toHaveAttribute("href", "/sources");
  await expect(page.getByRole("link", { name: "2. Create a Guard" })).toHaveAttribute("href", "/guards");
  await expect(page.getByRole("link", { name: "3. Register AI application" })).toHaveAttribute("href", "/applications");
  await expect(page.getByText("LangChain Python")).toBeVisible();
  await expect(page.getByText("Generic HTTP target")).toBeVisible();
  await expect(page.getByText("Connectivity alone is not Layer 1")).toBeVisible();
});

test("mobile navigation exposes product routes", async ({ context, page }, testInfo) => {
  test.skip(testInfo.project.name !== "mobile", "mobile-only assertion");
  await context.addCookies([{ name: "accessproof_session", value: "test-session", domain: "127.0.0.1", path: "/" }]);
  await page.route("**/api/v1/current/dashboard", route => route.fulfill({ json: dashboardJson() }));
  await page.goto("/dashboard");
  await page.getByRole("button", { name: "Open navigation" }).click();
  await expect(page.getByRole("link", { name: "Blocked requests" })).toBeVisible();
});

test("one-click security preflight reports action required without manual audit IDs", async ({ context, page }) => {
  await context.addCookies([{ name: "accessproof_session", value: "test-session", domain: "127.0.0.1", path: "/" }]);
  await page.route("**/api/v1/current/dashboard", route => route.fulfill({
    json: dashboardJson({ ai_applications: 1, guards_online: 1, guards_total: 1, permission_sources: 1 })
  }));
  await page.route("**/api/v1/current/protection/overview", route => route.fulfill({
    json: protectionOverviewJson([{
      application_id: "rag-e2e", name: "RAG E2E", mode: "shadow", effective_state: "BLOCKED",
      state_message: "The bound Guard or permission source is revoked or disconnected. Requests must fail closed.",
      reason_code: "GUARD_ENROLLED",
      adapter: { type: "generic-python", contract_version: "accessproof.rag/v1", protect_capable: true },
      guard: { id: "guard-1", name: "Guard", health: "not_enrolled", heartbeat_age_seconds: null, policy_version: null },
      source: { id: "source-1", name: "Source", provider: "google-drive", status: "not_configured", acl_sync_age_seconds: null, directory_sync_age_seconds: null, acl_fresh: false, directory_fresh: false },
      route_certification: { required: false, expired: false, status: "NOT_APPLICABLE", certified: false, age_seconds: null, evidence_level: null, certification_scope: "REFERENCE_GATEWAY_ROUTE_ONLY" },
      decision_telemetry: { telemetry: "NO_DATA", window_hours: 24, layer1: null, layer2: null },
      latest_decision_at: null,
      failed_checks: [{ code: "GUARD_ENROLLED", reason: "Enroll the selected Guard." }],
      checks: [],
    }]),
  }));
  await page.route("**/api/v1/current/ai-applications", route => route.fulfill({ json: [{
    id: "app-1", application_id: "rag-e2e", name: "RAG E2E", mode: "shadow",
    guard_id: "guard-1", source_id: "source-1", adapter_type: "generic-python",
    adapter_contract_version: "accessproof.rag/v1",
    readiness: [{ code: "LAYER1_INTEGRATION_CONFIRMED", ok: false, reason: "Run an approved Guard test" }]
  }] }));
  await page.route("**/api/v1/guards", route => route.fulfill({ json: [] }));
  await page.route("**/api/v1/current/sources", route => route.fulfill({ json: [] }));
  await page.route("**/api/v1/current/adapters", route => route.fulfill({ json: [] }));
  let submitted = 0;
  await page.route("**/api/v1/current/ai-applications/rag-e2e/protection/enable", route => {
    expect(route.request().method()).toBe("POST");
    expect(route.request().postData()).toBeNull();
    submitted++;
    return route.fulfill({ status: 202, json: {
      application_id: "rag-e2e", state: "action_required", reason_code: "CUSTOMER_RAG_CHALLENGE_AGENT_REQUIRED",
      message: "Connect the trusted RAG verification agent.", last_checked_at: "2026-10-22T09:00:00Z", run_id: "run-1", guard_acknowledged: false,
      checks: [{ code: "CUSTOMER_RAG_CHALLENGE_AGENT_REQUIRED", ok: false, reason: "Connect your verified RAG test agent" }],
    } });
  });
  await page.goto("/applications");
  await expect(page.getByText("RAG E2E")).toBeVisible();
  await expect(page.getByLabel("Authorized retrieval request ID")).toHaveCount(0);
  await page.getByRole("button", { name: "Enable Protection" }).click();
  await expect(page.getByRole("heading", { name: "Action required" })).toBeVisible();
  await expect(page.getByRole("status").filter({ hasText: "Connect the trusted" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Retry checks" })).toBeVisible();
  expect(submitted).toBe(1);
});

test("application registration uses the selected adapter contract", async ({ context, page }) => {
  await context.addCookies([{ name: "accessproof_session", value: "test-session", domain: "127.0.0.1", path: "/" }]);
  await page.route("**/api/v1/current/dashboard", route => route.fulfill({ json: dashboardJson({ guards_online: 1, guards_total: 1, permission_sources: 1 }) }));
  await page.route("**/api/v1/current/protection/overview", route => route.fulfill({ json: protectionOverviewJson() }));
  await page.route("**/api/v1/current/ai-applications", async route => {
    if (route.request().method() === "POST") {
      expect(route.request().postDataJSON()).toMatchObject({
        application_id: "http-rag", adapter_type: "generic-http", adapter_contract_version: "target-config/v1",
      });
      return route.fulfill({ status: 201, json: { id: "app-http" } });
    }
    return route.fulfill({ json: [] });
  });
  await page.route("**/api/v1/guards", route => route.fulfill({ json: [{ id: "guard-1", name: "RAG Guard", health: "online" }] }));
  await page.route("**/api/v1/current/sources", route => route.fulfill({ json: [{ id: "source-1", name: "Drive", provider: "google-drive", status: "connected" }] }));
  await page.route("**/api/v1/current/adapters", route => route.fulfill({ json: [{ id: "generic-http", name: "Generic HTTP target", status: "PARTIAL", contract_version: "target-config/v1", installation: "Configure a target", pre_generation_filtering: false, output_verification: false, protect_mode: false }] }));
  await page.goto("/applications");
  await page.getByRole("button", { name: "Register application" }).first().click();
  await page.getByLabel("Application ID").fill("http-rag");
  await page.getByLabel("Display name").fill("HTTP RAG");
  await page.getByLabel("Integration adapter").selectOption("generic-http");
  await page.getByLabel("Guard selector").selectOption("guard-1");
  await page.getByLabel("Permission source selector").selectOption("source-1");
  await page.getByRole("button", { name: "Register application" }).last().click();
  await expect(page.getByText("No AI applications yet")).toBeVisible();
});

test.skip("Microsoft SharePoint setup shows unresolved permission certification", async ({ context, page }) => {
  await context.addCookies([{ name: "accessproof_session", value: "test-session", domain: "127.0.0.1", path: "/" }]);
  let requests = 0;
  await page.route("**/api/v1/current/sources", async route => {
    if (route.request().method() === "POST") {
      const body = route.request().postDataJSON();
      expect(body).toMatchObject({
        provider: "microsoft365",
        name: "SharePoint Preview",
        boundary: "approved-root",
        credentials: {
          access_token: "synthetic-graph-token",
          drive_id: "d1",
          test_root_item_id: "approved-root",
          tenant_id: "11111111-2222-3333-4444-555555555555",
        },
      });
      requests++;
      return route.fulfill({ status: 201, json: { id: "ms-source", ...body, status: "not_configured" } });
    }
    return route.fulfill({ json: [] });
  });
  await page.goto("/sources");
  await page.getByRole("button", { name: "Connect source" }).first().click();
  await page.getByLabel("Provider").selectOption("microsoft365");
  await expect(page.getByText(/Microsoft 365 preview \/ Shadow testing only\./i)).toBeVisible();
  await page.getByLabel("Connection name").fill("SharePoint Preview");
  await page.getByLabel("Microsoft drive ID").fill("d1");
  await page.getByLabel("Microsoft Entra tenant ID").fill("11111111-2222-3333-4444-555555555555");
  await page.getByLabel("Approved folder item ID").fill("approved-root");
  await page.getByText("Advanced: manual credentials for approved pilot environments only").click();
  await page.getByLabel("Microsoft Graph access token").fill("synthetic-graph-token");
  await page.getByRole("region", { name: "Connect a source" }).getByRole("button", { name: "Connect source" }).click();
  await expect.poll(() => requests).toBe(1);
  await expect(page.getByRole("heading", { name: "Permission sources" })).toBeVisible();
});

test.skip("Microsoft administrator consent starts only from a configured source", async ({ context, page }) => {
  await context.addCookies([{ name: "accessproof_session", value: "test-session", domain: "127.0.0.1", path: "/" }]);
  let consentRequests = 0;
  await page.route("**/api/v1/current/sources", route => route.fulfill({ json: [{
    id: "microsoft-draft", name: "Finance SharePoint", boundary: "root",
    provider: "microsoft365", status: "not_configured", last_error: null,
    last_validated_at: null,
  }] }));
  await page.route("**/api/v1/current/sources/microsoft-draft/microsoft-admin-consent/begin", route => {
    expect(route.request().method()).toBe("POST");
    consentRequests++;
    return route.fulfill({ json: {
      authorization_url: "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0/adminconsent?client_id=synthetic&state=fake-test",
    } });
  });
  await page.route("https://login.microsoftonline.com/**", route =>
    route.fulfill({ status: 200, contentType: "text/html", body: "<h1>Simulated Microsoft consent</h1>" }));
  await page.goto("/sources");
  await expect(page.getByText("Finance SharePoint")).toBeVisible();
  await expect(page.getByText("Effective permissions not yet certified for protection")).toBeVisible();
  await page.getByRole("button", { name: "Authorize Microsoft" }).click();
  await expect.poll(() => consentRequests).toBe(1);
});

test("protection page renders per-application backend truth and NO DATA telemetry", async ({ context, page }) => {
  await context.addCookies([{ name: "accessproof_session", value: "test-session", domain: "127.0.0.1", path: "/" }]);
  const verified = {
    application_id: "finance-rag", name: "Finance RAG", mode: "protect", effective_state: "PROTECTED_VERIFIED",
    state_message: "All current backend checks passed. This status is scoped to this application and expires when route, Guard, or source evidence becomes stale.",
    reason_code: "PROTECTED_VERIFIED",
    adapter: { type: "accessproof-gateway", contract_version: "accessproof.rag/v1", protect_capable: true },
    guard: { id: "guard-1", name: "Finance Guard", health: "online", heartbeat_age_seconds: 30, policy_version: 4 },
    source: { id: "source-1", name: "Finance Drive", provider: "google-drive", status: "connected", acl_sync_age_seconds: 120, directory_sync_age_seconds: 300, acl_fresh: true, directory_fresh: true },
    route_certification: { required: true, expired: false, status: "CERTIFIED", certified: true, age_seconds: 120, evidence_level: "PRODUCTION_OBSERVED", certification_scope: "REFERENCE_GATEWAY_ROUTE_ONLY" },
    decision_telemetry: { telemetry: "OBSERVED", window_hours: 24, layer1: { allow: 7, block: 2, would_allow: 0, would_block: 0 }, layer2: { allow: 6, block: 1, would_allow: 0, would_block: 0 } },
    latest_decision_at: "2026-10-24T09:59:00Z", failed_checks: [], checks: [],
  };
  const stale = {
    ...verified, application_id: "ops-rag", name: "Ops RAG", mode: "protect", effective_state: "STALE",
    state_message: "Previously configured protection cannot be verified because Guard or source evidence is stale. Treat requests as unverified.",
    reason_code: "GUARD_HEARTBEAT_RECENT",
    route_certification: { required: true, expired: true, status: "EXPIRED", certified: false, age_seconds: 90000, evidence_level: "PRODUCTION_OBSERVED", certification_scope: "REFERENCE_GATEWAY_ROUTE_ONLY" },
    decision_telemetry: { telemetry: "NO_DATA", window_hours: 24, layer1: null, layer2: null },
    latest_decision_at: null,
    failed_checks: [{ code: "GUARD_HEARTBEAT_RECENT", reason: "The selected Guard has no recent heartbeat." }],
  };
  await page.route("**/api/v1/current/protection/overview", route => route.fulfill({
    json: {
      ...protectionOverviewJson([verified, stale]),
      totals: {
        applications_registered: 2, applications_protected_verified: 1, applications_not_verified: 1, applications_unsupported: 0,
        guards_total: 1, guards_online: 1, guards: { online: 1, offline: 0, not_enrolled: 0, revoked: 0 },
        sources_total: 1, sources_fresh: 1, sources_stale: 0,
      },
      state_counts: { ...protectionOverviewJson().state_counts, PROTECTED_VERIFIED: 1, STALE: 1 },
    },
  }));
  await page.goto("/protection");
  await expect(page.getByRole("heading", { name: "Protection", exact: true })).toBeVisible();
  await expect(page.getByText("1/2")).toBeVisible();
  await expect(page.getByText("Protected Verified").first()).toBeVisible();
  await expect(page.getByText("Stale").first()).toBeVisible();
  await expect(page.getByText("Route certificate: Certified · verified 2m ago")).toBeVisible();
  await expect(page.getByText("Route certificate: Expired")).toBeVisible();
  await expect(page.getByText("NO DATA").first()).toBeVisible();
  await expect(page.getByText("No Guard decisions recorded in 24h")).toBeVisible();
  await page.getByText("1 failing check").click();
  await expect(page.getByText("The selected Guard has no recent heartbeat.")).toBeVisible();
});

test("reports page generates and verifies a signed evidence export", async ({ context, page }) => {
  await context.addCookies([{ name: "accessproof_session", value: "test-session", domain: "127.0.0.1", path: "/" }]);
  const report = {
    schema: "accessproof.control_plane_report/v1", report_id: "report-1", report_type: "APPLICATION_COVERAGE",
    organization_id: "org-1", generated_at: "2026-10-24T10:00:00Z", expires_at: "2026-11-23T10:00:00Z",
    evidence_levels: {
      control_plane_state: "DIRECTLY_OBSERVED_BY_ACCESSPROOF", guard_decisions: "ASSERTED_BY_CUSTOMER_MACHINE",
      provider_effective_permissions: "NOT_OBSERVED", revocation_to_first_denial_timing: "NOT_OBSERVED",
    },
    summary: {
      applications_registered: 2, applications_protected_verified: 1, applications_not_verified: 1,
      guards_online: 1, guards_total: 1, sources_fresh: 1, sources_total: 1,
      decisions_24h: { telemetry: "NO_DATA", total: 0, layer1: { allow: 0, block: 0, would_allow: 0, would_block: 0 }, layer2: { allow: 0, block: 0, would_allow: 0, would_block: 0 } },
    },
    limitations: ["Control-plane observations are directly recorded by AccessProof for this tenant only."],
  };
  const signature = { algorithm: "Ed25519", key_id: "ed25519:test", payload_sha256: "a".repeat(64), public_key: "test", signature: "test" };
  const verification = {
    report_id: "report-1", report_type: "APPLICATION_COVERAGE", verified: true,
    signature_valid: true, scope_valid: true, expired: false,
    generated_at: report.generated_at, expires_at: report.expires_at, report_hash: signature.payload_sha256,
    key_id: signature.key_id, evidence_levels: report.evidence_levels, limitations: report.limitations,
  };
  await page.route("**/api/v1/current/reports", async route => {
    if (route.request().method() === "POST") {
      expect(route.request().postDataJSON()).toMatchObject({ report_type: "APPLICATION_COVERAGE" });
      return route.fulfill({ status: 201, json: { report, signature, verification } });
    }
    return route.fulfill({ json: [{
      id: "report-1", report_type: "APPLICATION_COVERAGE", generated_at: report.generated_at,
      expires_at: report.expires_at, report_hash: signature.payload_sha256, key_id: signature.key_id,
      evidence_levels: report.evidence_levels, summary: report.summary,
    }] });
  });
  await page.route("**/api/v1/current/reports/report-1", route => route.fulfill({ json: { report, signature, verification } }));
  await page.goto("/reports");
  await page.getByRole("button", { name: "Generate report" }).first().click();
  await page.getByRole("button", { name: "Generate and sign report" }).click();
  const detail = page.getByLabel("Report detail");
  await expect(detail.getByRole("heading", { name: /Application coverage/ })).toBeVisible();
  await expect(detail.getByText("Signature and scope verified")).toBeVisible();
  await expect(detail.getByText("Asserted by customer Guard")).toBeVisible();
  await expect(detail.getByText("Not observed").first()).toBeVisible();
  await expect(detail.getByText("NO DATA").first()).toBeVisible();
  await expect(detail.getByRole("link", { name: "Download signed JSON" })).toHaveAttribute("href", "/api/v1/current/reports/report-1/download");
});


test("Google OAuth operator readiness blocks unusable customer drafts", async ({ context, page }) => {
  await context.addCookies([{ name: "accessproof_session", value: "test-session", domain: "127.0.0.1", path: "/" }]);
  let created = 0;
  await page.route("**/api/v1/current/sources", route => {
    if (route.request().method() === "POST") created++;
    return route.fulfill({ json: [] });
  });
  await page.route("**/api/v1/current/sources/google-oauth/status", route =>
    route.fulfill({ json: { configured: false, message: "Operator setup required." } }));
  await page.route("**/api/v1/current/sources/microsoft-admin-consent/status", route =>
    route.fulfill({ json: { configured: false } }));
  await page.goto("/sources");
  await page.getByRole("button", { name: "Connect source" }).first().click();
  await expect(page.getByText(/Google connection is not yet configured on the AccessProof server/i)).toBeVisible();
  await page.getByLabel("Connection name").fill("Finance");
  await page.getByLabel("Approved Google Drive root folder ID").fill("approved-root");
  await page.getByRole("button", { name: "Connect Google Workspace" }).click();
  await expect(page.getByText(/No source was created/i).last()).toBeVisible();
  expect(created).toBe(0);
});

test("Google OAuth return acknowledges durable server-side sync without browser POST", async ({ context, page }) => {
  await context.addCookies([{ name: "accessproof_session", value: "test-session", domain: "127.0.0.1", path: "/" }]);
  const sourceId = "11111111-1111-4111-8111-111111111111";
  let browserSyncCalls = 0;
  await page.route("**/api/v1/current/sources", route => route.fulfill({
    json: [{ id: sourceId, name: "Finance Workspace", boundary: "approved-root",
      provider: "google-drive", status: "connected",
      directory_sync: { status: "queued", fresh: false, last_success_at: null, last_error_code: null },
      acl_sync: { status: "queued", fresh: false, last_success_at: null, last_error_code: null },
    }],
  }));
  await page.route("**/api/v1/current/sources/google-oauth/status", route =>
    route.fulfill({ json: { configured: true } }));
  await page.route(`**/api/v1/current/sources/${sourceId}/sync-directory`, route => {
    browserSyncCalls++;
    return route.fulfill({ status: 503, json: {} });
  });
  await page.goto(`/sources?google=consent-complete&source_id=${sourceId}`);
  await expect(page.getByText(/synchronization are queued securely on the server/i)).toBeVisible();
  await expect(page.getByText("Workspace directory: Queued")).toBeVisible();
  await expect(page.getByText("Drive ACLs: Queued")).toBeVisible();
  await page.reload();
  expect(browserSyncCalls).toBe(0);
});
