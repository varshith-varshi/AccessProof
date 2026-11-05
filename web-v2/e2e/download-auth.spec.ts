import { test, expect } from "@playwright/test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { NextRequest } from "next/server";
import { proxy } from "../proxy";

// Directly exercise the server-side proxy. Browser routing cannot intercept
// a Next.js server's own HTTP call to the internal API.
test.describe("Customer installer authorization", () => {
  test.describe.configure({ mode: "serial" });
  const url = "https://app.accessproof.in/downloads/accessproof-gateway-connector.zip?v=release";
  const cookie = "accessproof_session=synthetic-invalid; accessproof_organization=00000000-0000-0000-0000-000000000000";
  let originalFetch: typeof fetch;

  test.beforeEach(() => { originalFetch = globalThis.fetch; });
  test.afterEach(() => { globalThis.fetch = originalFetch; });

  test("the reviewed Python client wheel is bundled with a fixed checksum", () => {
    const wheel = readFileSync(join(process.cwd(), "public/downloads/accessproof_rag-0.1.0-py3-none-any.whl"));
    expect(createHash("sha256").update(wheel).digest("hex")).toBe(
      "ce72587503532202add008990e59fbf2a9c1c23e3740e1a4be3fac4b37235072",
    );
  });

  test("a missing cookie cannot download", async () => {
    globalThis.fetch = (async () => { throw new Error("No API check expected"); }) as typeof fetch;
    const result = await proxy(new NextRequest(url));
    expect(result.status).toBe(307);
    expect(result.headers.get("location")).toContain("/login?next=");
  });

  test("a fabricated session cookie is rejected by the real auth gate", async () => {
    let authCalls = 0;
    globalThis.fetch = (async (request, options) => {
      authCalls++;
      expect(String(request)).toMatch(/\/api\/v1\/auth\/me$/);
      expect((options as RequestInit)?.cache).toBe("no-store");
      expect(new Headers((options as RequestInit)?.headers).get("x-organization-id")).toBe("00000000-0000-0000-0000-000000000000");
      return Response.json({ detail: "Invalid or expired session" }, { status: 401 });
    }) as typeof fetch;
    const result = await proxy(new NextRequest(url, { headers: { cookie } }));
    expect(result.status).toBe(307);
    expect(authCalls).toBe(1);
  });

  test("a valid backend-authenticated organization session permits a private download", async () => {
    globalThis.fetch = (async () => Response.json({ active_organization_id: "org-1" }, { status: 200 })) as typeof fetch;
    const result = await proxy(new NextRequest(url, { headers: { cookie } }));
    expect(result.status).toBe(200);
    expect(result.headers.get("Cache-Control")).toContain("no-store");
  });

  test("API downtime refuses downloads instead of falling back to cookie presence", async () => {
    globalThis.fetch = (async () => { throw new Error("API unreachable"); }) as typeof fetch;
    const result = await proxy(new NextRequest(url, { headers: { cookie } }));
    expect(result.status).toBe(503);
    expect(result.headers.get("Cache-Control")).toBe("no-store");
  });

  for (const path of [
    "/downloads%2Faccessproof-gateway-connector.zip",
    "/downloads%252Faccessproof-gateway-connector.zip",
    "/%64ownloads/accessproof-gateway-connector.zip",
    "/downloads%5Caccessproof-gateway-connector.zip",
    "/DOWNLOADS%2Faccessproof-gateway-connector.zip",
    "/x/..%2Fdownloads/accessproof-gateway-connector.zip",
    "/downloads/%ZZ",
  ]) {
    test(`encoded path ${path} cannot skip the session check`, async () => {
      globalThis.fetch = (async () => Response.json({ detail: "Invalid or expired session" }, { status: 401 })) as typeof fetch;
      const result = await proxy(new NextRequest(`https://app.accessproof.in${path}`, { headers: { cookie } }));
      expect(result.status).toBe(307);
    });
  }

  test("other protected pages and public login have unchanged routing", async () => {
    globalThis.fetch = (async () => { throw new Error("No API check expected"); }) as typeof fetch;
    expect((await proxy(new NextRequest("https://app.accessproof.in/onboarding", { headers: { cookie } }))).status).toBe(200);
    expect((await proxy(new NextRequest("https://app.accessproof.in/login"))).status).toBe(200);
  });
});
