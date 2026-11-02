import { expect, test } from "@playwright/test";

// Browser fixtures only test UX; they are NOT source or production certificates.
const source = {
  id: "source-sharepoint-synthetic", name: "Synthetic SharePoint",
  provider: "sharepoint", status: "connected", boundary: "synthetic-root",
  acl_sync: { fresh: true, status: "healthy", last_success_at: null, last_error_code: null },
  directory_sync: { fresh: true, status: "healthy", last_success_at: null, last_error_code: null },
};
const guard = {
  id: "synthetic-guard", name: "Test Guard", health: "online", status: "online",
  enrolled_at: "2026-10-31T00:00:00Z", revoked_at: null, active_policy_version: 8,
};
const app = {
  id: "synthetic-app", application_id: "synthetic-sharepoint-rag", name: "Synthetic SharePoint RAG",
  source_id: source.id, source_ids: [source.id], guard_id: guard.id,
  adapter_type: "accessproof-gateway", adapter_contract_version: "accessproof.rag/v1",
  readiness: [], mode: "protect_pending",
};

async function mockSetup(page: import("@playwright/test").Page, options?: { paired?: boolean; verified?: boolean }) {
  await page.context().addCookies([
    { name: "accessproof_session", value: "synthetic-not-a-real-session", url: "http://127.0.0.1:3011" },
  ]);
  await page.route("**/api/v1/current/sources", route => route.fulfill({ json: [source] }));
  await page.route("**/api/v1/guards", route => route.fulfill({ json: [guard] }));
  await page.route("**/api/v1/current/ai-applications", route => route.fulfill({ json: [app] }));
  await page.route("**/api/v1/current/protection/overview", route => route.fulfill({
    json: { applications: [{
      application_id: app.application_id,
      effective_state: options?.verified ? "PROTECTED_VERIFIED" : "NOT_VERIFIED",
      state_message: "Source not certified; Protect remains pending.",
      failed_checks: [{ code: "MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED", reason: "Approval required" }],
      decision_telemetry: { telemetry: "OBSERVED", layer1: { allow: 2, block: 3 }, layer2: { allow: 1, block: 1 } },
    }] },
  }));
  await page.route("**/api/v1/current/ai-applications/*/gateway-pairing", route => route.fulfill({
    json: options?.paired === false ? { state: "awaiting_customer_install" } : {
      state: "installation_reported_unverified", deployment_sha256: "a".repeat(64), route_sha256: "b".repeat(64),
      verification: {
        state: "action_required", checked_at: "2026-11-01T12:00:00Z",
        checks_passed: 14, checks_total: 23,
        failed_check_codes: ["MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED"],
        production_certification: false, protect_activated: false,
      },
    },
  }));
  await page.route("**/api/v1/current/ai-applications/*/verification-run", route => route.fulfill({
    json: {
      run_id: options?.paired === false ? null : "test-run",
      state: "WAITING_FOR_AUTHORIZATION", checks_passed: 14, checks_total: 23,
      deployment_sha256: "a".repeat(64), route_sha256: "b".repeat(64),
      steps: [{ code: "MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED", state: "WAITING_FOR_ADMIN" }],
      guard: { connectivity: "CONNECTED", security_readiness: "DEGRADED", heartbeat_age_seconds: 0.4 },
    },
  }));
  await page.route("**/api/v1/current/ai-applications/*/protection/challenge", route => route.fulfill({
    json: { state: "not_requested", challenge_id: null, certified_for_reference_route: false },
  }));
}

test("customer journey needs no RAG URL and hides unusable challenge actions", async ({ page }) => {
  await mockSetup(page);
  const unsafeCalls: string[] = [];
  await page.route("**/api/v1/current/ai-applications/*/protection/enable", route => {
    unsafeCalls.push("enable");
    return route.fulfill({ status: 403, json: {} });
  });
  await page.route("**/api/v1/current/ai-applications/*/protection/challenge", route => {
    unsafeCalls.push("challenge");
    return route.fulfill({ status: 403, json: {} });
  });
  await page.goto("/onboarding?application=synthetic-sharepoint-rag");
  await expect(page.getByRole("heading", { name: "Connect SharePoint" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Connect your RAG", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Test protection in your RAG" })).toBeVisible();
  await expect(page.getByRole("region", { name: "Live RAG test instructions" })).toBeVisible();
  await expect(page.getByRole("region", { name: "Observed live Guard decisions" })).toBeVisible();
  await expect(page.getByRole("textbox", { name: "RAG application URL" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Open my RAG" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Generate live Gateway challenge" })).toHaveCount(0);
  await expect(page.getByText("14/23")).toHaveCount(0);
  await expect(page.getByText(/security prerequisites need attention/i)).toHaveCount(0);
  await expect(page.getByText("2 / 3")).toBeVisible();
  await expect(page.getByText("Offline / checking")).toHaveCount(0);
  expect(unsafeCalls).toEqual([]);
});

test("observing real RAG requests updates backend decision counters without enabling Protect", async ({ page }) => {
  await mockSetup(page);
  let layer1 = 2;
  let layer2 = 1;
  await page.route("**/api/v1/current/protection/overview", route => route.fulfill({
    json: { applications: [{
      application_id: app.application_id,
      effective_state: "NOT_VERIFIED",
      decision_telemetry: {
        telemetry: "OBSERVED",
        layer1: { allow: layer1, block: 3 },
        layer2: { allow: layer2, block: 1 },
      },
    }] },
  }));
  let unsafeCalls = 0;
  await page.route("**/api/v1/current/ai-applications/*/protection/enable", route => {
    unsafeCalls++; return route.fulfill({ status: 403 });
  });
  await page.goto("/onboarding?application=synthetic-sharepoint-rag");
  await page.getByRole("button", { name: "Start observing test requests" }).click();
  await expect(page.getByText("0 allowed · 0 blocked").first()).toBeVisible();
  layer1 = 3;
  layer2 = 2;
  await page.getByRole("button", { name: "Refresh observed decisions" }).click();
  await expect(page.getByText("1 allowed · 0 blocked").first()).toBeVisible();
  await expect(page.getByText("Not active", { exact: true })).toBeVisible();
  expect(unsafeCalls).toBe(0);
});

test("pre-pairing flow explains adapter limits and how to install without RAG URL", async ({ page }) => {
  await mockSetup(page, { paired: false });
  await page.goto("/onboarding?application=synthetic-sharepoint-rag");
  await expect(page.getByRole("link", { name: "Download Gateway" })).toHaveAttribute("href", /guard-readiness-r10-20261101/);
  await expect(page.getByRole("button", { name: "Generate one-time pairing file" })).toBeEnabled();
  await expect(page.getByText(/signed retrieval, identity forwarding, and buffered answer enforcement/)).toBeVisible();
  await expect(page.getByText("python3 ~/Downloads/accessproof-gateway-connector.zip")).toBeVisible();
  await expect(page.getByRole("button", { name: "Start observing test requests" })).toHaveCount(0);
  await expect(page.getByText("First, connect your Gateway")).toBeVisible();
  await expect(page.getByText("1 / 3")).toBeVisible();
});
