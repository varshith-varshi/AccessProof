import { expect, test } from "@playwright/test";
import { signIn } from "./helpers";

test("mobile navigation works on landing and app", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Toggle menu" }).click();
  await expect(page.getByRole("banner").getByRole("link", { name: "Features" })).toBeVisible();
  await signIn(page, "Dave");
  await page.getByRole("button", { name: "Open menu" }).click();
  await page.getByRole("navigation", { name: "Member" }).getByRole("link", { name: "Catalogue" }).click();
  await expect(page.getByRole("heading", { name: "Explore books" })).toBeVisible();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1);
  expect(overflow).toBe(false);
});
