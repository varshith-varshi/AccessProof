import { expect, test, type Page } from "@playwright/test";

const me = {
  user: { id: "u1", email: "owner@northwind.example", email_verified: true, mfa_enabled: false },
  active_organization_id: "org-1", role: "OWNER",
  organizations: [{ id: "org-1", name: "Northwind Labs", role: "OWNER" }, { id: "org-2", name: "Contoso", role: "VIEWER" }],
};
const emptyDashboard = {
  ai_applications: 0, guards_online: 0, guards_total: 0, permission_sources: 0, blocked_requests: 0, recent_activity: [],
  protection: {
    applications_registered: 0, applications_protected_verified: 0, applications_not_verified: 0, applications_unsupported: 0,
    guards: { online: 0, offline: 0, not_enrolled: 0, revoked: 0 }, sources_fresh: 0, sources_total: 0,
    decisions_24h: { telemetry: "NO_DATA", total: 0, layer1: { allow: 0, block: 0, would_allow: 0, would_block: 0 }, layer2: { allow: 0, block: 0, would_allow: 0, would_block: 0 } },
    latest_decision_at: null,
  },
};

async function signedIn(page: Page) {
  await page.context().addCookies([{ name: "accessproof_session", value: "test-session", domain: "127.0.0.1", path: "/" }]);
  await page.route("**/api/v1/auth/me", route => route.fulfill({ json: me }));
}

test("app shell shows the real workspace, role and signed-in account", async ({ page }, testInfo) => {
  await signedIn(page);
  await page.route("**/api/v1/current/dashboard", route => route.fulfill({ json: emptyDashboard }));
  await page.goto("/dashboard");
  if (testInfo.project.name === "mobile") await page.getByRole("button", { name: "Open navigation" }).click();
  await expect(page.getByRole("button", { name: /Northwind Labs/ })).toBeVisible();
  await expect(page.getByText("owner@northwind.example")).toBeVisible();
  await page.getByRole("button", { name: /Northwind Labs/ }).click();
  await expect(page.getByRole("menuitem", { name: /Contoso/ })).toBeVisible();
});

test("first-run dashboard guides the customer to the next setup step", async ({ page }) => {
  await signedIn(page);
  await page.route("**/api/v1/current/dashboard", route => route.fulfill({ json: { ...emptyDashboard, permission_sources: 1 } }));
  await page.goto("/dashboard");
  await expect(page.getByRole("heading", { name: "Finish setting up protection" })).toBeVisible();
  await expect(page.getByText("1 of 4 steps complete")).toBeVisible();
  await expect(page.getByRole("link", { name: "Continue setup" })).toHaveAttribute("href", "/guards");
});

test("settings renames the workspace and shows a confirmation", async ({ page }) => {
  await signedIn(page);
  let renamed = "";
  await page.route("**/api/v1/organization", async route => {
    renamed = JSON.parse(route.request().postData() ?? "{}").name;
    await route.fulfill({ json: { id: "org-1", name: renamed, role: "OWNER", mutations_disabled: false } });
  });
  await page.goto("/settings");
  const field = page.getByLabel("Workspace name");
  await expect(field).toHaveValue("Northwind Labs");
  await field.fill("Northwind AI");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByText("Workspace name saved.")).toBeVisible();
  expect(renamed).toBe("Northwind AI");
});

test("settings invites a teammate with a chosen role", async ({ page }) => {
  await signedIn(page);
  await page.route("**/api/v1/organization/members", route => route.fulfill({ json: [
    { membership_id: "m1", user_id: "u1", email: "owner@northwind.example", role: "OWNER" },
  ] }));
  let invited: Record<string, string> = {};
  await page.route("**/api/v1/organization/invitations", async route => {
    invited = JSON.parse(route.request().postData() ?? "{}");
    await route.fulfill({ status: 201, json: { id: "i1", email: invited.email } });
  });
  await page.goto("/settings");
  await page.getByRole("tab", { name: "Team" }).click();
  await page.getByLabel("Email").fill("dana@northwind.example");
  await page.getByLabel("Role").selectOption("VIEWER");
  await page.getByRole("button", { name: "Send invite" }).click();
  await expect(page.getByText("Invitation sent to dana@northwind.example")).toBeVisible();
  expect(invited).toEqual({ email: "dana@northwind.example", role: "VIEWER" });
});

test("two-factor setup shows the key and recovery codes before enabling", async ({ page }) => {
  await signedIn(page);
  await page.route("**/api/v1/auth/sessions", route => route.fulfill({ json: [] }));
  await page.route("**/api/v1/auth/mfa/setup", route => route.fulfill({ json: {
    provisioning_uri: "otpauth://totp/AccessProof:owner?secret=JBSWY3DPEHPK3PXP&issuer=AccessProof",
    recovery_codes: ["aaaa-1111", "bbbb-2222"],
  } }));
  await page.goto("/settings");
  await page.getByRole("tab", { name: "Account & security" }).click();
  await page.getByRole("button", { name: "Set up two-factor" }).click();
  await expect(page.getByText("JBSW Y3DP EHPK 3PXP")).toBeVisible();
  await expect(page.getByText("aaaa-1111")).toBeVisible();
  await expect(page.getByRole("button", { name: "Turn on" })).toBeVisible();
});

test("invitation link asks anonymous users to sign in and keeps the token", async ({ page }) => {
  await page.route("**/api/v1/auth/invitations/accept", route => route.fulfill({ status: 401, json: { detail: "Not authenticated" } }));
  await page.goto("/accept-invitation?token=abc123");
  const signIn = page.getByRole("link", { name: "Sign in to accept" });
  await expect(signIn).toBeVisible();
  await expect(signIn).toHaveAttribute("href", "/login?next=%2Faccept-invitation%3Ftoken%3Dabc123");
});

test("landing page offers self-serve signup and a security page", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("link", { name: "Start free" }).first()).toHaveAttribute("href", "/register");
  await expect(page.getByRole("heading", { name: "What happens when Bob asks" }).or(page.getByText("What happens when Bob asks"))).toBeVisible();
  await page.goto("/security");
  await expect(page.getByRole("heading", { name: "How AccessProof protects your data" })).toBeVisible();
  await expect(page.getByText("has not yet completed a third-party security audit", { exact: false })).toBeVisible();
});
