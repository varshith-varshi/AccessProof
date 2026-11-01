import { expect, test } from "@playwright/test";

// Synthetic fixtures are intentionally *not* proof of provider certification.
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
  readiness: [], mode: "shadow",
};

test("onboarding restores complete steps and displays fail-closed readiness", async ({ page, context }) => {
  await context.addCookies([{ name: "accessproof_session", value: "synthetic-not-a-real-session", url: "http://127.0.0.1:3011" }]);
  await page.route("**/api/v1/current/sources", r => r.fulfill({ json: [source] }));
  await page.route("**/api/v1/guards", r => r.fulfill({ json: [guard] }));
  await page.route("**/api/v1/current/ai-applications", r => r.fulfill({ json: [app] }));
  await page.route("**/api/v1/current/protection/overview", r => r.fulfill({ json: {
    applications: [{ application_id: app.application_id, effective_state: "NOT_VERIFIED",
      state_message: "Current effective SharePoint access not certified.",
      failed_checks: [{ code: "MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED", ok: false,
        reason: "Live employee SharePoint effective access is missing." }] }],
  } }));
  await page.route("**/api/v1/current/ai-applications/*/gateway-pairing", r =>
    r.fulfill({ json: {
      state: "installation_reported_unverified", deployment_sha256: "a".repeat(64),
      route_sha256: "b".repeat(64),
      verification: {
        state: "action_required", checked_at: "2026-11-01T12:00:00Z",
        checks_passed: 12, checks_total: 21,
        failed_check_codes: ["MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED"],
        production_certification: false, protect_activated: false,
      },
    } }));
  await page.goto("/onboarding?application=synthetic-sharepoint-rag");
  const sidebar = page.getByRole("navigation", { name: "Primary navigation" });
  await expect(sidebar.getByRole("link", { name: "Get Started" })).toHaveAttribute("href", "/onboarding");
  await expect(page.getByText("Connect SharePoint", { exact: true })).toBeVisible();
  await expect(page.getByText("Connect your RAG", { exact: true })).toBeVisible();
  await expect(page.getByText("Verify & protect", { exact: true })).toBeVisible();
  await expect(page.getByText("Guard connected · policy 8 · verify readiness")).toBeVisible();
  await expect(page.getByText("1 security prerequisites need attention")).toBeVisible();
  await expect(page.getByText("Live employee SharePoint effective access is missing.")).toBeVisible();
  await expect(page.getByText("python3 ~/Downloads/accessproof-gateway-connector.zip --doctor")).toBeVisible();
  await expect(page.getByText("Not protected yet")).toBeVisible();
  await expect(page.getByRole("status", { name: "Automatic security verification" })).toContainText("12/21 control-plane security checks passed");
  await expect(page.getByRole("button", { name: "Download security challenge" })).toBeDisabled();
  await expect(page.getByText("2 / 3")).toBeVisible();
});

test("onboarding does not claim protection for empty sources or failed provider APIs", async ({ page, context }) => {
  await context.addCookies([{ name: "accessproof_session", value: "synthetic-not-a-real-session", url: "http://127.0.0.1:3011" }]);
  await page.route("**/api/v1/current/sources", r => r.fulfill({ status: 503, json: { detail: "source not available" } }));
  await page.route("**/api/v1/guards", r => r.fulfill({ json: [] }));
  await page.route("**/api/v1/current/ai-applications", r => r.fulfill({ json: [] }));
  await page.route("**/api/v1/current/protection/overview", r => r.fulfill({ json: { applications: [] } }));
  await page.goto("/onboarding");
  await expect(page.getByText("Sources unavailable")).toBeVisible();
  await expect(page.getByText("No SharePoint connection")).toBeVisible();
  await expect(page.getByText("0 / 3")).toBeVisible();
  await expect(page.getByText("Not protected yet")).toBeVisible();
});


test("unpaired installer download is versioned to avoid a stale cached ZIP", async ({ page, context }) => {
  await context.addCookies([{ name: "accessproof_session", value: "synthetic-not-a-real-session", url: "http://127.0.0.1:3011" }]);
  await page.route("**/api/v1/current/sources", r => r.fulfill({ json: [source] }));
  await page.route("**/api/v1/guards", r => r.fulfill({ json: [guard] }));
  await page.route("**/api/v1/current/ai-applications", r => r.fulfill({ json: [app] }));
  await page.route("**/api/v1/current/protection/overview", r => r.fulfill({ json: { applications: [] } }));
  await page.route("**/api/v1/current/ai-applications/*/gateway-pairing", r =>
    r.fulfill({ json: { state: "awaiting_customer_install" } }));
  await page.goto("/onboarding");
  await expect(page.getByRole("link", { name: "Download Gateway installer" })).toHaveAttribute(
    "href", /auto-verify-r8-20261101/
  );
});
