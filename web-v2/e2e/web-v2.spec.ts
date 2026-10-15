import { expect, test } from "@playwright/test";

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

test("authenticated dashboard renders real API response", async ({ context, page }) => {
  await context.addCookies([{ name: "accessproof_session", value: "test-session", domain: "127.0.0.1", path: "/" }]);
  await page.route("**/api/v1/dashboard", route => route.fulfill({ json: { projects: 2, outcomes: {}, runner_health: { online: 1, total: 1, offline: 0 }, broken_connections: 0, recent_runs: [] } }));
  await page.goto("/dashboard");
  await expect(page.getByRole("heading", { name: "Authorization control plane" })).toBeVisible();
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

test("mobile navigation exposes product routes", async ({ context, page }, testInfo) => {
  test.skip(testInfo.project.name !== "mobile", "mobile-only assertion");
  await context.addCookies([{ name: "accessproof_session", value: "test-session", domain: "127.0.0.1", path: "/" }]);
  await page.route("**/api/v1/dashboard", route => route.fulfill({ json: { projects: 0, outcomes: {}, runner_health: { online: 0, total: 0, offline: 0 }, broken_connections: 0, recent_runs: [] } }));
  await page.goto("/dashboard");
  await page.getByRole("button", { name: "Open navigation" }).click();
  await expect(page.getByRole("link", { name: "Blocked requests" })).toBeVisible();
});
