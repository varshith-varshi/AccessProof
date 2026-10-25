import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  retries: 0,
  reporter: "line",
  use: { baseURL: "http://127.0.0.1:3011", trace: "retain-on-failure" },
  webServer: { command: "npm run build && cp -R .next/static .next/standalone/.next/static && cp -R public .next/standalone/public && cd .next/standalone && PORT=3011 HOSTNAME=127.0.0.1 node server.js", url: "http://127.0.0.1:3011", reuseExistingServer: false, timeout: 120_000 },
  projects: [
    { name: "desktop", use: { ...devices["Desktop Chrome"] } },
    { name: "mobile", use: { ...devices["Pixel 7"] } },
  ],
});
