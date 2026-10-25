import assert from "node:assert/strict";
import test from "node:test";
import { GuardClient, ProtectedRAG } from "../dist/index.js";

const resource = { sourceId: "a", resourceId: "public", content: "safe" };
for (const responseBody of ["null", "[]", "{}", "true", '"allow"', '{"decision":"allow"}']) {
  test("unstructured output decision fails closed: " + responseBody, async () => {
    const client = new GuardClient({
      baseUrl: "http://localhost",
      maxRetries: 0,
      fetchImpl: async url => new Response(
        url.endsWith("/filter-resources") ?
          JSON.stringify({decision_id:"d1", mode:"protect", decision:"allow", allowed:[{source_id:"a",resource_id:"public",chunk_ids:[]}]}) :
          responseBody,
        {status: 200}
      ),
    });
    const result = await new ProtectedRAG(client, 1_000_000, undefined, true).run({
      employeeToken:"synthetic", applicationId:"app", resources:[resource],
      generate:()=> "OK", sourceTrace:()=> [resource],
    });
    assert.equal(result.decision, "block");
    assert.equal(result.response, null);
  });
}
