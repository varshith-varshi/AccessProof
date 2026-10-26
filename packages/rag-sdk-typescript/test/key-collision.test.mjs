import assert from "node:assert/strict";
import test from "node:test";
import { GuardClient, ProtectedRAG } from "../dist/index.js";

test("late source with delimiter collision receives independent Layer 1 check", async () => {
  const sep = String.fromCharCode(0);
  const first = {sourceId: "department" + sep + "team", resourceId: "file", content: "A"};
  const second = {sourceId: "department", resourceId: "team" + sep + "file", content: "B"};
  const calls = [];
  const client = new GuardClient({
    baseUrl: "http://localhost",
    maxRetries: 0,
    fetchImpl: async (url, init) => {
      calls.push(String(url));
      const body = JSON.parse(init.body);
      if (String(url).endsWith("/filter-resources")) {
        return new Response(JSON.stringify({
          decision_id: String(calls.length),
          mode:"protect", decision:"allow",
          allowed: body.resources.map(r => ({source_id:r.source_id, resource_id:r.resource_id, chunk_ids:[]})),
        }), {status:200});
      }
      return new Response(JSON.stringify({decision:"allow", reason:"SYNTHETIC"}), {status:200});
    },
  });
  const result = await new ProtectedRAG(client, 1_000_000, undefined, true).run({
    employeeToken:"synthetic", applicationId:"app", resources:[first],
    generate: () => "SAFE",
    sourceTrace: () => [first, second],
  });
  assert.equal(calls.filter(url => url.endsWith("/filter-resources")).length, 2);
  assert.equal(result.decision, "allow");
});
