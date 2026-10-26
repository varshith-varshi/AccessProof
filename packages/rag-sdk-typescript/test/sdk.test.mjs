import assert from "node:assert/strict";
import test from "node:test";
import { GuardClient, ProtectedRAG } from "../dist/index.js";

test("filters before generation and verifies before release", async () => {
  const paths = [];
  const fetchImpl = async (url, init) => {
    paths.push(new URL(url).pathname);
    const body = JSON.parse(init.body);
    if (url.endsWith("filter-resources")) return Response.json({ decision_id: "d1", decision: "allow", allowed: [{ source_id: "drive", resource_id: "allowed" }] });
    assert.deepEqual(body.used_resource_ids, ["allowed"]);
    return Response.json({ decision: "allow", reason: "TRUSTED_PROVENANCE_VALID" });
  };
  const protectedRag = new ProtectedRAG(new GuardClient({ baseUrl: "https://guard.test", fetchImpl }), 1_000_000, undefined, true);
  const response = await protectedRag.run({ employeeToken: "verified-token", applicationId: "app", requestId: "r1", resources: [{ sourceId: "drive", resourceId: "allowed", content: "ok" }, { sourceId: "drive", resourceId: "denied", content: "secret" }], generate: resources => { assert.deepEqual(resources.map(item => item.resourceId), ["allowed"]); return "safe"; }, sourceTrace: () => [{ sourceId: "drive", resourceId: "allowed" }] });
  assert.equal(response.response, "safe");
  assert.deepEqual(paths, ["/guard/v1/filter-resources", "/guard/v1/check-output"]);
});

test("does not release a blocked Layer 2 response", async () => {
  const fetchImpl = async url => url.endsWith("filter-resources") ? Response.json({ decision_id: "d1", decision: "allow", allowed: [{ source_id: "s", resource_id: "r" }] }) : Response.json({ decision: "block", reason: "PROVENANCE_ESCAPE" });
  const response = await new ProtectedRAG(new GuardClient({ baseUrl: "https://guard.test", fetchImpl }), 1_000_000, undefined, true).run({ employeeToken: "token", applicationId: "app", resources: [{ sourceId: "s", resourceId: "r" }], generate: () => "must remain buffered", sourceTrace: () => [{ sourceId: "s", resourceId: "r" }] });
  assert.equal(response.response, null);
  assert.equal(response.reason, "PROVENANCE_ESCAPE");
});


test("Protect fails closed when no ingestion verifier is pinned", async () => {
  let generated = false;
  const fetchImpl = async url => Response.json({ decision_id: "d1", mode: "protect", decision: "allow", allowed: [{ source_id: "s", resource_id: "r" }] });
  const response = await new ProtectedRAG(new GuardClient({ baseUrl: "https://guard.test", fetchImpl })).run({
    employeeToken: "token", applicationId: "app", resources: [{ sourceId: "s", resourceId: "r", content: "forged" }],
    generate: () => { generated = true; return "unattested"; },
    sourceTrace: () => [{ sourceId: "s", resourceId: "r", content: "forged" }],
  });
  assert.equal(response.decision, "block");
  assert.equal(response.response, null);
  assert.equal(response.reason, "SOURCE_CONTENT_ATTESTATION_REQUIRED");
  assert.equal(generated, false);
});


test("an explicit legacy metadata-only release is never certification eligible", async () => {
  const fetchImpl = async url => url.endsWith("filter-resources")
    ? Response.json({ decision_id: "d1", mode: "protect", decision: "allow", allowed: [{ source_id: "s", resource_id: "r" }] })
    : Response.json({ decision: "allow", reason: "TRUSTED_PROVENANCE_VALID" });
  const response = await new ProtectedRAG(new GuardClient({ baseUrl: "https://guard.test", fetchImpl }), 1_000_000, undefined, true).run({
    employeeToken: "token", applicationId: "app", resources: [{ sourceId: "s", resourceId: "r", content: "legacy" }],
    generate: () => "legacy answer",
    sourceTrace: () => [{ sourceId: "s", resourceId: "r", content: "legacy" }],
  });
  assert.equal(response.decision, "allow");
  assert.equal(response.provenanceLevel, "UNATTESTED_METADATA_ONLY");
  assert.equal(response.certificationEligible, false);
});


test("missing source trace blocks even an explicit legacy metadata-only release", async () => {
  let generated = false;
  const fetchImpl = async url => Response.json({ decision_id: "d1", mode: "protect", decision: "allow", allowed: [{ source_id: "s", resource_id: "r" }] });
  const response = await new ProtectedRAG(new GuardClient({ baseUrl: "https://guard.test", fetchImpl }), 1_000_000, undefined, true).run({
    employeeToken: "token", applicationId: "app", resources: [{ sourceId: "s", resourceId: "r" }],
    generate: () => { generated = true; return "untraced cache"; },
  });
  assert.equal(response.decision, "block");
  assert.equal(response.response, null);
  assert.equal(response.reason, "PROVENANCE_TRACE_REQUIRED");
  assert.equal(generated, false);
});
