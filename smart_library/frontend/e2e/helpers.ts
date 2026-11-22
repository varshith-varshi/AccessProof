import { expect, type APIRequestContext, type Page } from "@playwright/test";

export async function signIn(page: Page, name: string) {
  await page.goto("/login");
  await page.locator("label").filter({ hasText: new RegExp(`^${name[0]}${name}`) }).click();
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/(dashboard|admin)/);
}

export async function apiToken(request: APIRequestContext, memberId: string) {
  const r = await request.post("/auth/demo-login", { data: { member_id: memberId } });
  return { Authorization: `Bearer ${(await r.json()).access_token}` };
}
