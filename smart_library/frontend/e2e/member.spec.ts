import { expect, test } from "@playwright/test";
import { apiToken, signIn } from "./helpers";

test("landing page shows live data and navigation", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: /Your Library\.\s*Smarter Than Ever\./ })).toBeVisible();
  for (const f of ["Smart Book Search", "Easy Borrowing & Returns", "Digital E-Book Library", "Personalized Recommendations", "Online Reservations", "Secure Access Management"])
    await expect(page.getByRole("heading", { name: f })).toBeVisible();
  await expect(page.getByText("Titles on open shelves")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Popular with members" })).toBeVisible();
  // Restricted titles never reach the public page.
  await expect(page.getByText("Financial Forecast")).toHaveCount(0);
  await page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: "Sign In" }).click();
  await expect(page).toHaveURL(/\/login/);
  await expect(page.getByText("Demo Mode")).toBeVisible();
});

test("member signs in and sees a personalised dashboard", async ({ page }) => {
  await signIn(page, "Alice");
  await expect(page.getByRole("heading", { name: "Welcome back, Alice" })).toBeVisible();
  await expect(page.getByText("Books borrowed")).toBeVisible();
  await expect(page.getByText("Due soon").first()).toBeVisible();
  await expect(page.getByRole("heading", { name: "Recommended for you" })).toBeVisible();
});

test("search, filters and pagination in the catalogue", async ({ page }) => {
  await signIn(page, "Dave");
  await page.goto("/books");
  await expect(page.getByText(/results?/).first()).toBeVisible();
  await page.getByLabel("Search the catalogue").fill("Strang");
  await expect(page.getByRole("link", { name: "Introduction to Linear Algebra" }).first()).toBeVisible();
  await expect(page.getByText(/^1$/).first()).toBeVisible();
  await page.getByLabel("Search the catalogue").fill("zzzz-no-such-book");
  await expect(page.getByText("No books found")).toBeVisible();
  await page.getByRole("button", { name: "Clear search and filters" }).click();
  await page.getByLabel("Category").selectOption("Literature");
  await expect(page.getByRole("link", { name: "Moby-Dick" }).first()).toBeVisible();
  await page.getByRole("button", { name: "Clear all filters" }).click();
  await page.getByRole("button", { name: "Next page" }).click();
  await expect(page).toHaveURL(/page=2/);
});

test("unauthorised titles are hidden from search and direct links", async ({ page }) => {
  await signIn(page, "Bob");
  await page.goto("/books?q=Forecast");
  await expect(page.getByText("No books found")).toBeVisible();
  await page.goto("/books/b-008");
  await expect(page.getByText("Book not found")).toBeVisible();
});

test("borrow and return a book", async ({ page }) => {
  await signIn(page, "Dave");
  await page.goto("/books/b-036");
  await page.getByRole("button", { name: "Borrow book" }).click();
  await expect(page.getByText("Book borrowed")).toBeVisible();
  await expect(page.getByText(/You have this book on loan/)).toBeVisible();
  await page.goto("/my-books");
  const row = page.locator("div.flex.gap-4", { hasText: "Structure and Interpretation" }).first();
  await row.getByRole("button", { name: "Return" }).click();
  await page.getByRole("button", { name: "Confirm return" }).click();
  await expect(page.getByText("Book returned")).toBeVisible();
  await expect(page.getByRole("link", { name: "Structure and Interpretation of Computer Programs" })).toHaveCount(0);
});

test("renew a loan", async ({ page }) => {
  await signIn(page, "Dave");
  await page.goto("/my-books");
  const row = page.locator("div.flex.gap-4", { hasText: "Introduction to Linear Algebra" }).first();
  await row.getByRole("button", { name: "Renew" }).click();
  await expect(page.getByText("Loan renewed")).toBeVisible();
  await expect(row.getByText("Renewed 1×")).toBeVisible();
});

test("reserve an unavailable book and cancel it", async ({ page }) => {
  await signIn(page, "Erin");
  await page.goto("/books/b-023");
  await page.getByRole("button", { name: "Reserve book" }).click();
  await expect(page.getByText(/number 2 in the queue/).first()).toBeVisible();
  await page.goto("/reservations");
  await expect(page.getByText("Position #2")).toBeVisible();
  await page.getByRole("button", { name: "Cancel" }).click();
  await page.getByRole("button", { name: "Cancel reservation" }).click();
  await expect(page.getByText("Reservation cancelled")).toBeVisible();
});

test("access revocation between discovery and borrowing is enforced", async ({ page, request }) => {
  await signIn(page, "Alice");
  await page.goto("/books/b-009");
  await expect(page.getByRole("heading", { name: "FY2027 Library Budget" })).toBeVisible();
  const libby = await apiToken(request, "m-libby");
  const r = await request.delete("/admin/memberships", { headers: libby, data: { member_id: "m-alice", group_id: "finance" } });
  expect(r.ok()).toBeTruthy();
  await page.getByRole("button", { name: "Borrow book" }).click();
  await expect(page.getByText(/access to this title has been revoked/)).toBeVisible();
  await page.goto("/books?q=Budget");
  await expect(page.getByText("No books found")).toBeVisible();
  await request.post("/admin/memberships", { headers: libby, data: { member_id: "m-alice", group_id: "finance" } });
});

test("overdue loan handling and fines", async ({ page }) => {
  await signIn(page, "Carol");
  await page.goto("/fines");
  await expect(page.getByRole("heading", { name: "Overdue books" })).toBeVisible();
  await expect(page.getByText("Online payment is not available")).toBeVisible();
  await page.goto("/books/b-001");
  await expect(page.getByText("Return your overdue items before borrowing more.")).toBeVisible();
});

test("e-book reader validates access and offers reading controls", async ({ page }) => {
  await signIn(page, "Dave");
  await page.goto("/ebooks");
  await page.locator("div.card", { hasText: "Moby-Dick" }).getByRole("link", { name: "Read now" }).click();
  await expect(page.getByText("Call me Ishmael.", { exact: false })).toBeVisible();
  await page.getByRole("button", { name: "Larger text" }).click();
  await page.getByRole("button", { name: "dark page" }).click();
  await page.getByRole("button", { name: "Next" }).click();
  await expect(page.getByText("Section 2 of 2")).toBeVisible();
  // A restricted e-book is refused at the moment of reading.
  await page.goto("/ebooks/b-008/read");
  await expect(page.getByText("This e-book cannot be opened")).toBeVisible();
});
