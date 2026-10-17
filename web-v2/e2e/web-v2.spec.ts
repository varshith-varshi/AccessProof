import { expect, test } from "@playwright/test";

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
  await page.route("**/api/v1/current/dashboard", route => route.fulfill({ json: { ai_applications: 1, guards_online: 1, guards_total: 1, permission_sources: 1, blocked_requests: 0, recent_activity: [] } }));
  await page.goto("/dashboard");
  await expect(page.getByRole("heading", { name: "Authorization control plane", exact: true })).toBeVisible();
  await expect(page.getByText("1/1")).toBeVisible();
});

test("Guard inventory and secure enrollment flow render", async ({ context, page }) => {
  await context.addCookies([{ name: "accessproof_session", value: "test-session", domain: "127.0.0.1", path: "/" }]);
  await page.route("**/api/v1/guards", async route => {
    if (route.request().method() === "POST") return route.fulfill({ status: 201, json: { id: "guard-new", name: "finance-prod", environment: "production", status: "not_enrolled", health: "not_enrolled" } });
    return route.fulfill({ json: [{ id: "guard-123456789", name: "Finance Guard", environment: "production", version: "1.0.0", status: "enrolled", health: "online", active_policy_version: 18, last_heartbeat_at: "2026-10-15T10:00:00Z", enrolled_at: "2026-10-10T10:00:00Z", revoked_at: null }] });
  });
  await page.route("**/api/v1/guards/guard-new/enrollments", route => route.fulfill({ status: 201, json: { enrollment_token: "AP-GUARD-ONE-TIME-TEST-TOKEN-123456789", expires_in_seconds: 900, guard_id: "guard-new" } }));
  await page.goto("/guards");
  await expect(page.getByText("Finance Guard")).toBeVisible();
  await expect(page.getByText("Online")).toBeVisible();
  await page.getByRole("button", { name: "Create Guard" }).first().click();
  await page.getByLabel("Guard name").fill("finance-prod");
  await page.getByRole("button", { name: "Create and generate token" }).click();
  await expect(page.getByText("Copy this one-time token now.")).toBeVisible();
});

test("permission sources can be connected without a legacy project", async ({ context, page }) => {
  await context.addCookies([{ name: "accessproof_session", value: "test-session", domain: "127.0.0.1", path: "/" }]);
  await page.route("**/api/v1/current/sources", async route => {
    if (route.request().method() === "POST") {
      const body = route.request().postDataJSON();
      expect(body).toMatchObject({ provider: "google-drive", name: "Finance", boundary: "drive-root" });
      return route.fulfill({ status: 201, json: { id: "source-1", ...body, status: "not_configured" } });
    }
    return route.fulfill({ json: [] });
  });
  await page.goto("/sources");
  await page.getByRole("button", { name: "Connect source" }).first().click();
  await page.getByLabel("Connection name").fill("Finance");
  await page.getByLabel("Drive folder or shared-drive ID").fill("drive-root");
  await page.getByLabel("Google access token").fill("test-only-token");
  await page.getByRole("button", { name: "Connect source", exact: true }).last().click();
  await expect(page.getByRole("heading", { name: "Permission sources" })).toBeVisible();
});

test("synchronized employees render provider-stable identities", async ({ context, page }) => {
  await context.addCookies([{ name: "accessproof_session", value: "test-session", domain: "127.0.0.1", path: "/" }]);
  await page.route("**/api/v1/current/employees", route => route.fulfill({ json: [{ id: "employee-1", name: "Alice Example", email: "alice@example.com", provider: "microsoft365", stable_id: "entra-object-1", status: "active", last_synced_at: "2026-10-16T00:00:00Z", groups: [{ id: "group-1", name: "Engineering", provider: "microsoft365", stable_id: "group-object-1" }] }] }));
  await page.goto("/employees");
  await expect(page.getByText("Alice Example")).toBeVisible();
  await expect(page.getByText("entra-object-1")).toBeVisible();
  await expect(page.getByText("Engineering")).toBeVisible();
});

test("mobile navigation exposes product routes", async ({ context, page }, testInfo) => {
  test.skip(testInfo.project.name !== "mobile", "mobile-only assertion");
  await context.addCookies([{ name: "accessproof_session", value: "test-session", domain: "127.0.0.1", path: "/" }]);
  await page.route("**/api/v1/current/dashboard", route => route.fulfill({ json: { ai_applications: 0, guards_online: 0, guards_total: 0, permission_sources: 0, blocked_requests: 0, recent_activity: [] } }));
  await page.goto("/dashboard");
  await page.getByRole("button", { name: "Open navigation" }).click();
  await expect(page.getByRole("link", { name: "Blocked requests" })).toBeVisible();
});
