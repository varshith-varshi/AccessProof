import assert from "node:assert/strict";
import test from "node:test";
import { GuardClient, ProtectedRAG } from "../dist/index.js";

test("reauthorizes a trusted late source before releasing a buffered answer", async () => {
  const calls = [];
  let number = 0;
  const fetchImpl = async (url, init) => {
    const body = JSON.parse(init.body);
    calls.push({ path: new URL(url).pathname, body });
    if (url.endsWith("filter-resources")) {
      number += 1;
      const source = number === 1 ? "file-1" : "file-2";
      assert.deepEqual(body.resources.map(item => item.resource_id), [source]);
      return Response.json({ decision_id: "d" + number, decision: "allow", allowed: [{ source_id: "drive", resource_id: source }] });
    }
    assert.deepEqual(body.additional_decision_ids, ["d2"]);
    assert.deepEqual(body.used_resource_ids, ["file-1", "file-2"]);
    return Response.json({ decision: "allow", reason: "TRUSTED_PROVENANCE_VALID" });
  };
  const rag = new ProtectedRAG(new GuardClient({ baseUrl: "https://guard.test", fetchImpl }), 1_000_000, undefined, true);
  const result = await rag.run({
    employeeToken: "verified", applicationId: "rag", requestId: "r1",
    resources: [{ sourceId: "drive", resourceId: "file-1" }],
    generate: () => "Answer includes authorized cached fact",
    sourceTrace: () => [{ sourceId: "drive", resourceId: "file-1" }, { sourceId: "drive", resourceId: "file-2", derivedType: "cache" }],
  });
  assert.equal(result.decision, "allow");
  assert.equal(result.response, "Answer includes authorized cached fact");
  assert.deepEqual(calls.map(call => call.path), [
    "/guard/v1/filter-resources", "/guard/v1/filter-resources", "/guard/v1/check-output",
  ]);
});

test("denies extra source when second Layer 1 rejects it", async () => {
  let number = 0;
  const fetchImpl = async url => {
    if (!url.endsWith("filter-resources")) throw Error("Layer 2 must not be called");
    number += 1;
    return Response.json(number === 1
      ? { decision_id: "d1", decision: "allow", allowed: [{ source_id: "drive", resource_id: "file-1" }] }
      : { decision_id: "d2", decision: "block", allowed: [] });
  };
  const rag = new ProtectedRAG(new GuardClient({ baseUrl: "https://guard.test", fetchImpl }), 1_000_000, undefined, true);
  const result = await rag.run({
    employeeToken: "verified", applicationId: "rag",
    resources: [{ sourceId: "drive", resourceId: "file-1" }],
    generate: () => "must stay buffered",
    sourceTrace: () => [{ sourceId: "drive", resourceId: "file-1" }, { sourceId: "drive", resourceId: "denied", derivedType: "cache" }],
  });
  assert.equal(result.decision, "block");
  assert.equal(result.response, null);
  assert.equal(result.reason, "ADDITIONAL_SOURCE_NOT_AUTHORIZED");
  assert.equal(number, 2);
});
