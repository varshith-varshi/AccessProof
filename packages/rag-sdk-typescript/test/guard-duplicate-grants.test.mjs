import assert from "node:assert/strict";
import test from "node:test";
import { GuardClient, ProtectedRAG } from "../dist/index.js";

const resources = [
  {sourceId:"drive", resourceId:"file", chunkId:"public", content:"PUBLIC"},
  {sourceId:"drive", resourceId:"file", chunkId:"restricted", content:"RESTRICTED"},
];

function guardFor(grants) {
  return new GuardClient({
    baseUrl:"http://localhost", maxRetries:0,
    fetchImpl: async url => new Response(JSON.stringify(String(url).endsWith("/filter-resources") ?
      {decision_id:"d1", mode:"protect", decision:"allow", allowed:grants.map(chunk_ids => ({
        source_id:"drive", resource_id:"file", chunk_ids,
      }))} : {decision:"allow", reason:"SYNTHETIC"}), {status:200}),
  });
}

for (const grants of [
  [["public"], []],
  [[], ["public"]],
  [["public"], ["restricted"]],
]) {
  test("contradictory duplicate grants must block " + JSON.stringify(grants), async () => {
    let calls = 0;
    const output = await new ProtectedRAG(guardFor(grants), 1_000_000, undefined, true).run({
      employeeToken:"synthetic", applicationId:"app",
      resources, generate: () => { calls += 1; return "PUBLIC"; },
      sourceTrace: () => [resources[0]],
    });
    assert.equal(output.decision, "block");
    assert.equal(output.response, null);
    assert.equal(calls, 0);
  });
}

test("redundant identical grants do not block authorized input", async () => {
  const output = await new ProtectedRAG(guardFor([["public"], ["public"]]), 1_000_000, undefined, true).run({
    employeeToken:"synthetic", applicationId:"app",
    resources, generate: docs => docs.map(d => d.content).join(","),
    sourceTrace: () => [resources[0]],
  });
  assert.equal(output.decision, "allow");
  assert.equal(output.response, "PUBLIC");
});
