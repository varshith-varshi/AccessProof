import { mkdirSync } from "node:fs";
import { expect, test, type Page } from "@playwright/test";

const application = { id: "app-row", application_id: "finance-rag", name: "Finance RAG", mode: "protect_pending", guard_id: "guard-1", source_id: "source-1", source_ids: ["source-1"], adapter_type: "accessproof-gateway", adapter_contract_version: "accessproof.rag/v1", readiness: [] };
const source = { id: "source-1", name: "HR knowledge library", provider: "sharepoint", boundary: "root-1", status: "connected", acl_sync: { fresh: true, status: "fresh" }, directory_sync: { fresh: true, status: "fresh" } };
const guard = { id: "guard-1", name: "Guard 1", health: "online", status: "online", active_policy_version: 9 };
const account = { user: { id: "person-1", email: "owner@company.example", email_verified: true }, active_organization_id: "org-1", role: "OWNER", organizations: [{ id: "org-1", name: "Company", role: "OWNER" }] };
async function setup(page: Page, role = "OWNER") {
  await page.context().addCookies([{ name: "accessproof_session", value: "fixture", domain: "127.0.0.1", path: "/" }]);
  await page.route("**/api/v1/auth/me", route => route.fulfill({ json: { ...account, role } }));
  await page.route("**/api/v1/current/sources/google-oauth/status", route => route.fulfill({ json: { configured: true } }));
  await page.route("**/api/v1/current/sources/microsoft-admin-consent/status", route => route.fulfill({ json: { configured: true } }));
  await page.route("**/api/v1/current/sources", route => route.fulfill({ json: [source] }));
  await page.route("**/api/v1/guards", route => route.fulfill({ json: [guard] }));
  await page.route("**/api/v1/current/ai-applications", route => route.fulfill({ json: [application] }));
  await page.route("**/api/v1/current/dashboard", route => route.fulfill({ json: { recent_activity: [] } }));
  await page.route("**/api/v1/current/protection/overview", route => route.fulfill({ json: { applications: [{ application_id: application.application_id, effective_state: "NOT_VERIFIED" }] } }));
  await page.route("**/api/v1/current/ai-applications/*/gateway-pairing", route => route.fulfill({ json: { state: "installation_reported_unverified", gateway_connectivity: { connection: "CONNECTED", enforcement_ready_reported: true, heartbeat_age_seconds: 1, reason: null } } }));
  await page.route("**/api/v1/current/ai-applications/*/verification-run", route => route.fulfill({ json: { state: "verified", guard: { connectivity: "CONNECTED", security_readiness: "READY", heartbeat_age_seconds: 1 } } }));
  await page.route("**/api/v1/current/ai-applications/*/protection/status", route => route.fulfill({ json: { route_certificate: { certified: true, status: "valid" }, checks: [{ code: "CUSTOMER_RAG_CUTOVER_NOT_VERIFIED", ok: true, reason: null }, { code: "HUMAN_ACTIVATION_APPROVAL_REQUIRED", ok: false, reason: "Owner approval required" }] } }));
}

test("SharePoint form keeps fields in distinct grid cells on desktop and mobile", async ({ page }) => {
  await setup(page);
  for (const width of [1440, 980, 390]) {
    await page.setViewportSize({ width, height: 920 });
    await page.goto("/sources");
    await page.getByRole("button", { name: "Connect source" }).first().click();
    await page.getByLabel("Provider", { exact: true }).selectOption("sharepoint");
    if (width === 1440 && process.env.AP_CAPTURE_GUIDE === "1") {
      mkdirSync("../docs/assets/customer-onboarding", { recursive: true });
      await page.locator(".source-form").screenshot({ path: "../docs/assets/customer-onboarding/sharepoint-form-fixed.png" });
    }
    const tenant = await page.getByLabel("Entra tenant ID").boundingBox();
    const site = await page.getByLabel("SharePoint site ID").boundingBox();
    const action = await page.getByRole("button", { name: "Connect Microsoft 365 + SharePoint" }).boundingBox();
    expect(tenant && site && action).toBeTruthy();
    if (!tenant || !site || !action) continue;
    const overlapX = Math.max(0, Math.min(tenant.x + tenant.width, site.x + site.width) - Math.max(tenant.x, site.x));
    const overlapY = Math.max(0, Math.min(tenant.y + tenant.height, site.y + site.height) - Math.max(tenant.y, site.y));
    expect(overlapX * overlapY, `${width}px: no field overlap`).toBe(0);
    expect(action.x).toBeGreaterThanOrEqual(0);
    expect(action.x + action.width).toBeLessThan(width + 1);
  }
});

test("SharePoint table keeps actions reachable without a horizontal scroll", async ({ page }) => {
  await setup(page);
  await page.setViewportSize({ width: 1180, height: 800 });
  await page.goto("/sources");
  const button = page.getByRole("button", { name: "Sync permissions" });
  await expect(button).toBeVisible();
  const pos = await button.boundingBox();
  expect(pos).not.toBeNull();
  expect(pos!.x + pos!.width).toBeLessThan(1180);
});

test("Owner approval calls audited backend only after exact confirmation", async ({ page }) => {
  await setup(page);
  let approved: unknown = null;
  let enabled = 0;
  await page.route("**/api/v1/current/ai-applications/*/protection/approve", async route => {
    approved = route.request().postDataJSON();
    await route.fulfill({ status: 201, json: { state: "approved_awaiting_guard_ack" } });
  });
  await page.route("**/api/v1/current/ai-applications/*/protection/enable", route => { enabled++; return route.fulfill({ status: 202, json: { state: "validating" } }); });
  await page.goto("/applications");
  await page.getByRole("button", { name: "Check & Enable Protection" }).click();
  const approveButton = page.getByRole("button", { name: "Approve Protect as Owner" });
  await expect(approveButton).toBeDisabled();
  await page.getByLabel("Owner approval confirmation").fill("APPROVE PROTECT finance-rag");
  await expect(approveButton).toBeEnabled();
  if (process.env.AP_CAPTURE_GUIDE === "1") {
    mkdirSync("../docs/assets/customer-onboarding", { recursive: true });
    await page.locator(".owner-approval-panel").screenshot({ path: "../docs/assets/customer-onboarding/owner-approval-fixed.png" });
  }
  await approveButton.click();
  await expect(page.getByText(/Owner approval recorded/)).toBeVisible();
  expect(approved).toEqual({ confirm_text: "APPROVE PROTECT finance-rag", reviewer: "owner@company.example" });
  expect(enabled).toBe(0);
});

test("Non-owner account cannot see approval action", async ({ page }) => {
  await setup(page, "ADMIN");
  await page.goto("/applications");
  await page.getByRole("button", { name: "Check & Enable Protection" }).click();
  await expect(page.getByText(/Only a signed-in organization Owner/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Approve Protect as Owner" })).toHaveCount(0);
});

test("Incomplete certification blocks owner approval", async ({ page }) => {
  await setup(page);
  await page.route("**/api/v1/current/ai-applications/*/protection/status", route => route.fulfill({ json: { route_certificate: { certified: false, status: "missing" }, checks: [{ code: "CUSTOMER_RAG_CUTOVER_NOT_VERIFIED", ok: false, reason: "Actual cutover required" }, { code: "HUMAN_ACTIVATION_APPROVAL_REQUIRED", ok: false, reason: "Owner approval required" }] } }));
  await page.goto("/applications");
  await page.getByRole("button", { name: "Check & Enable Protection" }).click();
  await expect(page.getByRole("button", { name: "Approve Protect as Owner" })).toBeDisabled();
  await expect(page.getByLabel("Owner approval confirmation")).toBeDisabled();
});
