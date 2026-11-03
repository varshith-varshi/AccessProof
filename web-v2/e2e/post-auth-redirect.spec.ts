import { expect, test } from "@playwright/test";
import { safeNextPath } from "../lib/api";

// Browsers strip tab/CR/LF in URLs and treat "\" as "/", so these all used to
// resolve to the protocol-relative //evil.example after sign-in.
const hostile = [
  "/\t/evil.example/x", "/\n/evil.example", "/\r\\evil.example", "/\\evil.example",
  "//evil.example", "https://evil.example", "javascript:alert(1)", "/ /evil.example",
  "/\u0000/evil.example", " /settings",
];

test("safeNextPath rejects every off-origin or control-character target", () => {
  for (const value of hostile) expect(safeNextPath(value), JSON.stringify(value)).toBeNull();
  expect(safeNextPath("/settings")).toBe("/settings");
  expect(safeNextPath("/accept-invitation?token=abc123")).toBe("/accept-invitation?token=abc123");
  expect(safeNextPath("/%2F/evil.example")).toBe("/%2F/evil.example");
});

test("signing in with a hostile next= stays on the AccessProof origin", async ({ page, baseURL }) => {
  await page.route("**/api/v1/**", route => route.fulfill({ status: 401, json: { detail: "Not authenticated" } }));
  await page.route("**/api/v1/auth/login", route => route.fulfill({ json: { session_token: "t", organizations: [{ id: "org-1", role: "OWNER" }] } }));
  await page.route(url => url.hostname === "evil.example", route => route.fulfill({ status: 200, body: "PHISH" }));
  await page.goto(`/login?next=${encodeURIComponent("/\t/evil.example/phish")}`);
  await page.getByLabel("Email").fill("alice@example.com");
  await page.getByLabel("Password").fill("correct horse battery staple");
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.waitForURL(url => url.pathname !== "/login", { timeout: 10_000 }).catch(() => undefined);
  expect(new URL(page.url()).origin).toBe(new URL(baseURL!).origin);
});
