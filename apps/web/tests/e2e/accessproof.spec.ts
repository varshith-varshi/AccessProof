import {expect,test,type Page} from "@playwright/test";

async function createAccount(page:Page,label:string){
  const email=`${label}-${Date.now()}@example.com`;
  const password="correct horse battery staple";
  await page.goto("/signup");
  await page.getByLabel("Organization name").fill(`${label} Org`);
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByLabel("Confirm").fill(password);
  await page.getByRole("button",{name:"Create organization"}).click();
  // The test server exposes a development-only token. Production sends this
  // link by email, and always requires the same verification before login.
  const devVerify=page.getByRole("button",{name:"Verify development account"});
  await expect(devVerify).toBeVisible();
  await devVerify.click();
  await expect(page.getByText(/Email verified/)).toBeVisible();
  await page.goto("/login");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button",{name:"Sign in with password"}).click();
  await expect(page).toHaveURL(/overview/);
  return email;
}

test("signup creates a working browser session and project",async({page})=>{
  await createAccount(page,"e2e-project");
  await page.goto("/projects");
  await page.getByPlaceholder("Project name").fill("Staging RAG");
  await page.getByRole("button",{name:"Create project"}).click();
  await expect(page.getByRole("cell",{name:"Staging RAG"})).toBeVisible();
});

test("organization emergency mutation switch roundtrips",async({page})=>{
  await createAccount(page,"e2e-org");
  await page.goto("/organization");
  await expect(page.getByText("MUTATIONS ENABLED")).toBeVisible();
  await page.getByRole("button",{name:"Disable all mutations"}).click();
  await expect(page.getByText("MUTATIONS DISABLED")).toBeVisible();
  await page.getByRole("button",{name:"Re-enable test mutations"}).click();
  await expect(page.getByText("MUTATIONS ENABLED")).toBeVisible();
});

test("invalid login exposes a bounded error state",async({page})=>{
  await page.goto("/login");
  await page.getByLabel("Email").fill("missing@example.com");
  await page.getByLabel("Password").fill("not-the-password");
  await page.getByRole("button",{name:"Sign in with password"}).click();
  await expect(page.getByText("Invalid credentials")).toBeVisible();
});

test("sources and suites use project selectors without UUID entry",async({page})=>{
  await createAccount(page,"e2e-selectors");
  await page.goto("/projects");
  await page.getByPlaceholder("Project name").fill("Pilot selectors");
  await page.getByRole("button",{name:"Create project"}).click();
  await page.goto("/sources");
  await expect(page.getByLabel("Project")).toContainText("Pilot selectors");
  await expect(page.getByText("Project ID",{exact:true})).toHaveCount(0);
  await page.goto("/suites");
  await expect(page.getByLabel("Project")).toContainText("Pilot selectors");
  await expect(page.getByText("Project ID",{exact:true})).toHaveCount(0);
});
