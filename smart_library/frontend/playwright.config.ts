import { defineConfig, devices } from "@playwright/test";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// End-to-end tests run the real FastAPI backend on a throwaway database (port 8765),
// so they never touch your own smart_library.db.
const PORT = 8765;
const db = join(tmpdir(), `slms-e2e-${Date.now()}.db`);
// Use an already-installed Chromium if Playwright's pinned build is not downloaded.
const fallback = join(process.env.HOME ?? "", ".cache/ms-playwright/chromium-1193/chrome-linux/chrome");
const executablePath = process.env.PW_CHROMIUM_PATH ?? (existsSync(fallback) ? fallback : undefined);

export default defineConfig({
  testDir: "./e2e",
  timeout: 30_000,
  fullyParallel: false,
  workers: 1,
  reporter: [["list"]],
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    trace: "off",
    launchOptions: executablePath ? { executablePath } : {},
  },
  projects: [
    { name: "desktop", use: { ...devices["Desktop Chrome"], viewport: { width: 1366, height: 860 } }, testIgnore: /responsive\.spec\.ts/ },
    { name: "mobile", use: { ...devices["Pixel 7"] }, testMatch: /responsive\.spec\.ts/ },
  ],
  webServer: {
    command: `cd .. && SLMS_DB_PATH=${db} SLMS_SECRET_KEY=e2e-secret ./.venv/bin/uvicorn app.main:app --port ${PORT}`,
    url: `http://127.0.0.1:${PORT}/health`,
    reuseExistingServer: false,
    timeout: 60_000,
  },
});
