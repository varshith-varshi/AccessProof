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
  await page.route("**/api/v1/current/ai-applications/*/protection/status", route => route.fulfill({ json: { route_certificate: { certified: true, status: "valid" }, checks: [{ code: "GATEWAY_LIVE_AND_ENFORCEMENT_READY", ok: true, reason: null }, { code: "PERMISSION_SOURCE_USABLE", ok: true, reason: null }] } }));
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

test("Owner enables Protect directly without approval confirmation", async ({ page }) => {
  await setup(page);
  let enabled = 0;
  await page.route("**/api/v1/current/ai-applications/*/protection/enable", route => {
    enabled++;
    return route.fulfill({ status: 202, json: { state: "validating", reason_code: "GUARD_PROTECT_ACK_REQUIRED", message: "Awaiting Guard" } });
  });
  await page.goto("/applications");
  await page.getByRole("button", { name: "Check & Enable Protection" }).click();
  await expect(page.getByText("Owner approval required")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Approve Protect as Owner" })).toHaveCount(0);
  const enableButton = page.getByRole("button", { name: "Enable Protection", exact: true });
  await expect(enableButton).toBeEnabled();
  await enableButton.click();
  await expect(page.getByText(/Awaiting Guard/)).toBeVisible();
  expect(enabled).toBe(1);
});

test("Admin can request activation without an Owner approval step", async ({ page }) => {
  await setup(page, "ADMIN");
  await page.goto("/applications");
  await page.getByRole("button", { name: "Check & Enable Protection" }).click();
  await expect(page.getByRole("button", { name: "Approve Protect as Owner" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Enable Protection", exact: true })).toBeEnabled();
});

test("Missing source certification disables activation, not an approval form", async ({ page }) => {
  await setup(page);
  await page.route("**/api/v1/current/ai-applications/*/protection/status", route => route.fulfill({
    json: { route_certificate: { certified: false, status: "missing" },
      checks: [{ code: "MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED", ok: false, reason: "Live SharePoint certification required" }] },
  }));
  await page.goto("/applications");
  await page.getByRole("button", { name: "Check & Enable Protection" }).click();
  await expect(page.getByRole("button", { name: "Enable Protection", exact: true })).toBeDisabled();
  await expect(page.getByText(/Live SharePoint certification required/)).toBeVisible();
  await expect(page.getByLabel("Owner approval confirmation")).toHaveCount(0);
});

test("Unverified installation receipt cannot complete Gateway onboarding", async ({ page }) => {
  await setup(page);
  await page.route("**/api/v1/current/ai-applications/*/gateway-pairing", route => route.fulfill({
    json: {
      state: "installation_reported_unverified",
      gateway_connectivity: { connection: "DISCONNECTED", enforcement_ready_reported: false,
        heartbeat_age_seconds: null, reason: "NO_HEARTBEAT_YET" },
    },
  }));
  await page.goto("/onboarding?application=finance-rag");
  await expect(page.getByText("Installation receipt received, Gateway not verified")).toBeVisible();
  await expect(page.getByText("Installation unverified")).toBeVisible();
  await expect(page.getByText("Gateway heartbeat", { exact: true })).toBeVisible();
  await expect(page.getByText("Not verified", { exact: true })).toBeVisible();
});

test("Uploaded manifest cannot issue challenge without a live enforcement-ready Gateway", async ({ page }) => {
  await setup(page);
  await page.route("**/api/v1/current/ai-applications/*/gateway-pairing", route => route.fulfill({
    json: {
      state: "installation_reported_unverified",
      gateway_connectivity: { connection: "DISCONNECTED", enforcement_ready_reported: false,
        heartbeat_age_seconds: null, reason: "NO_HEARTBEAT_YET" },
    },
  }));
  let issued = 0;
  await page.route("**/api/v1/current/ai-applications/*/protection/challenge", route => {
    issued++;
    return route.fulfill({ status: 409, json: { detail: "LIVE_ENFORCEMENT_READY_GATEWAY_REQUIRED" } });
  });
  await page.goto("/applications");
  await page.getByRole("button", { name: "Set up Gateway" }).click();
  await page.getByLabel("Gateway installation manifest").setInputFiles({
    name: "installation.json", mimeType: "application/json",
    buffer: Buffer.from(JSON.stringify({
      reference_contract: "accessproof.gateway/v1", application_id: "finance-rag",
      deployment_sha256: "a".repeat(64), route_sha256: "b".repeat(64),
    })),
  });
  await expect(page.getByText(/Manifest loaded \(not proof of installation\)/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Issue optional security challenge" })).toBeDisabled();
  expect(issued).toBe(0);
});

test("First-time SharePoint source can stage Protect before independent certificate", async ({ page }) => {
  await setup(page);
  let enableRequests = 0;
  await page.route("**/api/v1/current/ai-applications/*/verification-run", route => route.fulfill({
    json: { state: "paired", guard: { connectivity: "CONNECTED", security_readiness: "DEGRADED",
      heartbeat_age_seconds: 1 } },
  }));
  await page.route("**/api/v1/current/ai-applications/*/gateway-pairing", route => route.fulfill({
    json: { state: "installation_reported_unverified", gateway_connectivity: {
      connection: "CONNECTED", enforcement_ready_reported: false,
      heartbeat_age_seconds: 1, reason: "GUARD_NOT_READY",
    } },
  }));
  await page.route("**/api/v1/current/ai-applications/*/protection/status", route => route.fulfill({
    json: { state: "protection_not_enabled", route_certificate: { certified: false, status: "missing" },
      checks: [
        { code: "PERMISSION_SOURCE_USABLE", ok: true, reason: null },
        { code: "MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED", ok: false,
          required_for_activation: false, reason: "Validation-first Protect may be enabled." },
        { code: "PRODUCTION_OIDC_READY", ok: false, reason: "Guard waiting for Protect binding" },
        { code: "GATEWAY_LIVE_AND_ENFORCEMENT_READY", ok: false, reason: "Guard waiting for Protect binding" },
      ] },
  }));
  await page.route("**/api/v1/current/ai-applications/*/protection/enable", route => {
    enableRequests++;
    return route.fulfill({ status: 202, json: {
      state: "validating", guard_acknowledged: false,
      reason_code: "WAITING_FOR_GUARD_AND_GATEWAY_READINESS",
      message: "Integration verification is incomplete.",
    } });
  });
  await page.goto("/applications");
  await page.getByRole("button", { name: "Check & Enable Protection" }).click();
  await expect(page.getByText(/Source certification pending — manual validation/)).toBeVisible();
  const button = page.getByRole("button", { name: "Enable Protection", exact: true });
  await expect(button).toBeEnabled();
  await button.click();
  await expect(page.getByText("Protection not active yet")).toBeVisible();
  expect(enableRequests).toBe(1);
});

test("Missing source authorization still blocks validation-first Protect", async ({ page }) => {
  await setup(page);
  await page.route("**/api/v1/current/ai-applications/*/protection/status", route => route.fulfill({
    json: { checks: [
      { code: "MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED", ok: false,
        required_for_activation: false, reason: "Certification pending" },
      { code: "PERMISSION_SOURCE_USABLE", ok: false, reason: "ACL synchronization incomplete" },
    ] },
  }));
  await page.goto("/applications");
  await page.getByRole("button", { name: "Check & Enable Protection" }).click();
  await expect(page.getByRole("button", { name: "Enable Protection", exact: true })).toBeDisabled();
  await expect(page.getByText(/ACL synchronization incomplete/)).toBeVisible();
});

test("Protect badge and activation panel update automatically after Guard acknowledgment", async ({ page }) => {
  await setup(page);
  let acknowledged = false;
  let enableRequests = 0;
  const certificatePending = {
    code: "MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED", ok: false,
    reason: "Independent source validation still pending", required_for_activation: false,
  };
  await page.route("**/api/v1/current/ai-applications", route => route.fulfill({
    json: [{ ...application, mode: acknowledged ? "protect" : "protect_pending",
      readiness: [certificatePending] }],
  }));
  await page.route("**/api/v1/current/protection/overview", route => route.fulfill({
    json: { applications: [{
      application_id: application.application_id,
      effective_state: acknowledged ? "PROTECTED_MANUAL_VALIDATION_PENDING" : "PROTECT_PENDING",
    }] },
  }));
  await page.route("**/api/v1/current/ai-applications/*/protection/status", route => route.fulfill({
    json: {
      state: acknowledged ? "protected" : "validating",
      guard_acknowledged: acknowledged,
      reason_code: acknowledged ? "MANUAL_SOURCE_VALIDATION_PENDING" : "GUARD_PROTECT_ACK_REQUIRED",
      message: acknowledged ? "Protect enforcement is active; independent source validation is still pending."
        : "Awaiting Guard acknowledgment",
      route_certificate: { certified: false, status: "missing" },
      checks: [{ code: "GATEWAY_LIVE_AND_ENFORCEMENT_READY", ok: true, reason: null },
        certificatePending],
    },
  }));
  await page.route("**/api/v1/current/ai-applications/*/protection/enable", route => {
    enableRequests += 1;
    return route.fulfill({ status: 202, json: {
      state: "validating", guard_acknowledged: false,
      reason_code: "GUARD_PROTECT_ACK_REQUIRED", message: "Awaiting Guard acknowledgment",
    } });
  });
  await page.goto("/applications");
  await expect(page.getByText("Mode: protect_pending")).toBeVisible();
  await page.getByRole("button", { name: "Check & Enable Protection" }).click();
  await page.getByRole("button", { name: "Enable Protection", exact: true }).click();
  await expect(page.getByText("Protection not active yet")).toBeVisible();
  acknowledged = true;
  // Neither the user nor Playwright reloads the page or calls Enable again.
  await expect(page.getByText("Protection active — now test your RAG")).toBeVisible({ timeout: 15_000 });
  await expect(page.getByText("Mode: protect", { exact: true })).toBeVisible({ timeout: 15_000 });
  await expect(page.getByText("Protect active · manual validation pending")).toBeVisible();
  await expect(page.getByText("Enforcement ready")).toBeVisible();
  await expect(page.getByText("Requires activation review")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Protect Active" })).toBeDisabled();
  expect(enableRequests).toBe(1);
});

test("Opening activation panel on an already active RAG shows Protect active", async ({ page }) => {
  await setup(page);
  await page.route("**/api/v1/current/ai-applications/*/protection/status", route => route.fulfill({
    json: {
      state: "protected", guard_acknowledged: true,
      reason_code: "MANUAL_SOURCE_VALIDATION_PENDING",
      message: "Protect enforcement is active; independent source validation is still pending.",
      route_certificate: { certified: false, status: "missing" },
      checks: [{ code: "MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED",
        ok: false, required_for_activation: false, reason: "Optional evidence pending" }],
    },
  }));
  await page.goto("/applications");
  await page.getByRole("button", { name: "Check & Enable Protection" }).click();
  await expect(page.getByText("Protection active — now test your RAG")).toBeVisible();
  await expect(page.getByRole("button", { name: "Protect Active" })).toBeDisabled();
  await expect(page.getByRole("heading", { name: "Manual validation after Protect activation" })).toBeVisible();
});
