import { expect, test } from "@playwright/test";
import { apiToken, signIn } from "./helpers";

test("members cannot open the librarian console", async ({ page, request }) => {
  await signIn(page, "Dave");
  await page.goto("/admin");
  await expect(page.getByRole("heading", { name: "Access denied" })).toBeVisible();
  const r = await request.get("/admin/stats", { headers: await apiToken(request, "m-dave") });
  expect(r.status()).toBe(403);
});

test("librarian dashboard and reports use real data", async ({ page }) => {
  await signIn(page, "Libby");
  await expect(page).toHaveURL(/\/admin$/);
  await expect(page.getByRole("heading", { name: "Library overview" })).toBeVisible();
  await expect(page.getByText("Monthly borrowing activity")).toBeVisible();
  await expect(page.locator(".recharts-surface").first()).toBeVisible();
  await expect(page.getByRole("cell", { name: "Carol" })).toBeVisible();
  await page.getByRole("link", { name: "Reports" }).click();
  await expect(page.getByText("Most borrowed titles")).toBeVisible();
});

test("inventory: add and edit a book with validation", async ({ page }) => {
  await signIn(page, "Libby");
  await page.goto("/admin/books");
  await page.getByRole("button", { name: "Add book" }).click();
  await page.getByRole("button", { name: "Add book" }).last().click();
  await expect(page.getByText("Required").first()).toBeVisible();
  const form = page.getByRole("dialog");
  await form.getByLabel("Book ID").fill("b-e2e");
  await form.getByLabel("ISBN", { exact: true }).fill("9780000000999");
  await form.getByLabel("Title", { exact: true }).fill("Playwright Testing Handbook");
  await form.getByLabel("Author", { exact: true }).fill("QA Team");
  await form.getByLabel("Category", { exact: true }).fill("Computer Science");
  await form.getByLabel("Number of copies").fill("2");
  await page.getByRole("button", { name: "Add book" }).last().click();
  await expect(page.getByText("Book added")).toBeVisible();
  await page.getByPlaceholder("Search title, author, ISBN, category").fill("Playwright Testing");
  await page.getByRole("button", { name: "Edit Playwright Testing Handbook" }).click();
  await page.getByRole("dialog").getByLabel("Total copies").fill("4");
  await page.getByRole("button", { name: "Save changes" }).click();
  await expect(page.getByText("Book updated")).toBeVisible();
  await expect(page.getByRole("cell", { name: /4\s*\/\s*4/ })).toBeVisible();
});

test("audit log records and filters denied decisions", async ({ page, request }) => {
  // A checkout without an authorised-search attestation must be denied and audited.
  const denied = await request.post("/books/b-001/checkout", { headers: await apiToken(request, "m-dave"), data: {} });
  expect(denied.status()).toBe(403);
  await signIn(page, "Libby");
  await page.goto("/admin/audit");
  await page.getByLabel("Decision").selectOption("deny");
  await expect(page.locator("tbody").getByText("Denied").first()).toBeVisible();
  await expect(page.locator("tbody").getByText("Allowed")).toHaveCount(0);
  await expect(page.locator("tbody").getByText("missing_attestation").first()).toBeVisible();
});

test("access settings show guard status and policy", async ({ page }) => {
  await signIn(page, "Libby");
  await page.goto("/admin/settings");
  await expect(page.getByText("Ready — deciding requests")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Finance reports" })).toBeVisible();
  await page.getByRole("button", { name: "Sync policy now" }).click();
  await expect(page.getByText("Policy updated")).toBeVisible();
});
