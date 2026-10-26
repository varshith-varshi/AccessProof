import assert from "node:assert/strict";
import test from "node:test";
import { GuardClient, ProtectedRAG, RAGAdapter, normalizeDocument } from "../dist/index.js";

test("declared foreign source cannot be overwritten by a configured source", async () => {
  for (const metadata of [
    { source_id: "drive-private", resource_id: "public" },
    { accessproof_source_id: "drive-private", resource_id: "public" },
    { accessproof_source_id: "drive-allowed", source_id: "drive-private", resource_id: "public" },
  ]) {
    assert.throws(() => normalizeDocument({ pageContent: "PRIVATE_CANARY", metadata }, "drive-allowed"));
    let called = false;
    const guard = new GuardClient({
      baseUrl: "https://unused.invalid",
      fetchImpl: async () => { called = true; throw new Error("must not call Guard"); },
    });
    const result = await new RAGAdapter(new ProtectedRAG(guard, 1_000_000, undefined, true), "drive-allowed").run({
      employeeToken: "synthetic", applicationId: "app",
      documents: [{ pageContent: "PRIVATE_CANARY", metadata }],
      generate: () => { throw new Error("generator must not run"); },
    });
    assert.equal(result.decision, "block");
    assert.equal(result.response, null);
    assert.equal(called, false);
  }
});

test("conflicting resource/chunk aliases must not silently choose a trusted identifier", () => {
  for (const metadata of [
    { source_id: "drive-allowed", resource_id: "public", file_id: "restricted" },
    { source_id: "drive-allowed", resource_id: "public", accessproof_resource_id: "restricted" },
    { source_id: "drive-allowed", resource_id: "public", chunk_id: "safe", accessproof_chunk_id: "secret" },
  ]) {
    assert.throws(() => normalizeDocument({ pageContent: "PRIVATE_CANARY", metadata }));
  }
});

test("declared source can be absent when a registered source is configured", () => {
  const result = normalizeDocument({ pageContent: "PUBLIC", metadata: { resource_id: "public" } }, "drive-allowed");
  assert.equal(result.sourceId, "drive-allowed");
  assert.equal(result.resourceId, "public");
});


test("a concurrently mutated vector result cannot change model input after authorization", async () => {
  const document = {
    pageContent: "PUBLIC", metadata: { source_id: "drive-allowed", resource_id: "public" },
  };
  const seen = [];
  const guard = new GuardClient({
    baseUrl: "https://synthetic-guard.invalid",
    fetchImpl: async (url) => {
      if (String(url).endsWith("/filter-resources")) {
        document.pageContent = "PRIVATE_CANARY";
        document.metadata.resource_id = "restricted";
        return new Response(JSON.stringify({
          decision_id: "d1", decision: "allow", mode: "protect",
          allowed: [{ source_id: "drive-allowed", resource_id: "public", chunk_ids: [] }],
        }), { status: 200 });
      }
      return new Response(JSON.stringify({ decision: "allow", reason: "VALID" }), { status: 200 });
    },
  });
  const result = await new RAGAdapter(new ProtectedRAG(guard, 1_000_000, undefined, true), "drive-allowed").run({
    employeeToken: "synthetic", applicationId: "app", documents: [document],
    generate: (docs) => { seen.push(docs[0].pageContent); return docs[0].pageContent; },
    sourceTrace: () => [{ sourceId: "drive-allowed", resourceId: "public" }],
  });
  assert.deepEqual(seen, ["PUBLIC"]);
  assert.equal(result.response, "PUBLIC");
});


test("direct TypeScript ProtectedRAG freezes retrieval membership before Guard I/O", async () => {
  const original = { sourceId: "drive", resourceId: "public", content: "PUBLIC_SAFE" };
  const documents = [original];
  const saw = [];
  const guard = new GuardClient({
    baseUrl: "https://synthetic-guard.invalid",
    fetchImpl: async (url) => {
      if (String(url).endsWith("/filter-resources")) {
        documents[0] = { sourceId: "drive", resourceId: "public", content: "PRIVATE_CANARY" };
        return new Response(JSON.stringify({
          decision_id: "d1", decision: "allow", mode: "protect",
          allowed: [{ source_id: "drive", resource_id: "public", chunk_ids: [] }],
        }), { status: 200 });
      }
      return new Response(JSON.stringify({
        decision: "allow", reason: "TRUSTED_PROVENANCE_VALID",
      }), { status: 200 });
    },
  });
  const result = await new ProtectedRAG(guard, 1_000_000, undefined, true).run({
    employeeToken: "synthetic", applicationId: "app",
    resources: documents,
    generate: authorized => { saw.push(authorized[0].content); return authorized[0].content; },
    sourceTrace: () => [original],
  });
  assert.equal(result.decision, "allow");
  assert.equal(result.response, "PUBLIC_SAFE");
  assert.deepEqual(saw, ["PUBLIC_SAFE"]);
});
