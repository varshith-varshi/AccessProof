import assert from "node:assert/strict";
import test from "node:test";
import { GuardClient, ProtectedRAG } from "../dist/index.js";

test("Protect never releases an observational would-allow decision", async () => {
  let generated = false;
  const fetchImpl = async url => url.endsWith("filter-resources")
    ? Response.json({ mode: "protect", decision_id: "d1", decision: "would_allow", allowed: [{ source_id: "s", resource_id: "r" }] })
    : Response.json({ decision: "would_allow", reason: "OBSERVER_ONLY" });
  const result = await new ProtectedRAG(new GuardClient({ baseUrl: "https://guard.test", fetchImpl }), 1_000_000, undefined, true).run({
    employeeToken: "verified", applicationId: "app", resources: [{ sourceId: "s", resourceId: "r" }],
    generate: () => { generated = true; return "NEVER_RELEASE"; },
    sourceTrace: () => [{ sourceId: "s", resourceId: "r" }],
  });
  assert.equal(result.decision, "block");
  assert.equal(result.response, null);
  assert.equal(generated, false);
});

test("Protect enforces a chunk-level allowlist before generation", async () => {
  const seen = [];
  const fetchImpl = async url => url.endsWith("filter-resources")
    ? Response.json({ mode: "protect", decision_id: "d1", decision: "allow", allowed: [{ source_id: "s", resource_id: "r", chunk_ids: ["allowed"] }] })
    : Response.json({ decision: "allow", reason: "OK" });
  const result = await new ProtectedRAG(new GuardClient({ baseUrl: "https://guard.test", fetchImpl }), 1_000_000, undefined, true).run({
    employeeToken: "verified", applicationId: "app", resources: [
      { sourceId: "s", resourceId: "r", chunkId: "allowed", content: "safe" },
      { sourceId: "s", resourceId: "r", chunkId: "denied", content: "FINANCE_CANARY" },
    ],
    generate: documents => { seen.push(...documents.map(doc => doc.content)); return "safe answer"; },
    sourceTrace: () => [{ sourceId: "s", resourceId: "r", chunkId: "allowed" }],
  });
  assert.deepEqual(seen, ["safe"]);
  assert.equal(result.decision, "allow");
  assert.equal(result.response, "safe answer");
});
