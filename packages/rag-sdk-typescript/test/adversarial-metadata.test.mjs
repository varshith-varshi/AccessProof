import assert from "node:assert/strict";
import test from "node:test";
import { GuardClient, ProtectedRAG, RAGAdapter } from "../dist/index.js";

test("malformed retrieved document returns block instead of throwing past the enforcement boundary", async () => {
  let invoked = false;
  const guard = new GuardClient({
    baseUrl: "https://unused.invalid",
    fetchImpl: async () => { invoked = true; throw new Error("Guard must not be called"); },
  });
  const adapter = new RAGAdapter(new ProtectedRAG(guard, 1_000_000, undefined, true), "synthetic-drive");
  const result = await adapter.run({
    employeeToken: "synthetic", applicationId: "synthetic",
    documents: [{ pageContent: "CONFIDENTIAL", metadata: {} }],
    generate: () => { throw new Error("Generator must not execute"); },
  });
  assert.deepEqual(result, { decision: "block", response: null, reason: "RESOURCE_METADATA_REQUIRED" });
  assert.equal(invoked, false);
});
