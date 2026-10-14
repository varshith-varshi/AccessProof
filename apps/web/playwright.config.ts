import {defineConfig,devices} from "@playwright/test";

const apiPort=process.env.ACCESSPROOF_E2E_API_PORT??"58080";
const webPort=process.env.ACCESSPROOF_E2E_WEB_PORT??"53030";
const apiURL=`http://127.0.0.1:${apiPort}`;
const webURL=`http://127.0.0.1:${webPort}`;

export default defineConfig({
  testDir:"./tests/e2e",
  timeout:45_000,
  expect:{timeout:8_000},
  fullyParallel:false,
  retries:0,
  use:{baseURL:webURL,trace:"retain-on-failure",screenshot:"only-on-failure"},
  projects:[{name:"chromium",use:{...devices["Desktop Chrome"]}}],
  webServer:[
    {command:`cd ../.. && TASK_DB=$(mktemp -u /tmp/accessproof-playwright-XXXXXX.db) && ACCESSPROOF_ENV=development DATABASE_URL=sqlite:///$TASK_DB uv run alembic upgrade head && ACCESSPROOF_ENV=development DATABASE_URL=sqlite:///$TASK_DB uv run python -m uvicorn apps.api.accessproof_api.app:app --host 127.0.0.1 --port ${apiPort}`,url:`${apiURL}/health/live`,reuseExistingServer:false,timeout:30_000},
    {command:`API_URL=${apiURL} npm run build && npm run start -- --hostname 127.0.0.1 --port ${webPort}`,url:`${webURL}/login`,reuseExistingServer:false,timeout:90_000},
  ],
});
