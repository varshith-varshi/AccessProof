import assert from "node:assert/strict";
import test from "node:test";
import { GuardClient, ProtectedRAG, RAGAdapter } from "../dist/index.js";

class FrameworkNode {
  constructor(text) {
    this.node = { text };
    this.pageContent = text;
    this.metadata = { source_id: "allowed-source", resource_id: "public-file" };
  }
  getContent() {
    return this.node.text;
  }
}

function guardWithMutation(onLayer1) {
  return new GuardClient({
    baseUrl: "http://127.0.0.1:9999",
    fetchImpl: async (url) => {
      if (String(url).endsWith("/filter-resources")) {
        onLayer1();
        return new Response(JSON.stringify({
          mode: "protect", decision: "allow", decision_id: "synthetic-l1",
          allowed: [{ source_id: "allowed-source", resource_id: "public-file", chunk_ids: [] }],
        }), { status: 200 });
      }
      return new Response(JSON.stringify({ decision: "allow", reason: "TEST_LAYER2_ALLOW" }), { status: 200 });
    },
  });
}

test("nested vector-store node cannot mutate the generator content after Layer 1", async () => {
  const document = new FrameworkNode("PUBLIC_SAFE");
  const seen = [];
  const sdk = new RAGAdapter(
    new ProtectedRAG(guardWithMutation(() => { document.node.text = "PRIVATE_SECRET"; }), 1_000_000, undefined, true),
    "allowed-source",
  );
  const result = await sdk.run({
    employeeToken: "synthetic", applicationId: "customer-rag", documents: [document],
    generate: docs => { seen.push(docs[0].getContent()); return docs[0].getContent(); },
    sourceTrace: () => [{ sourceId: "allowed-source", resourceId: "public-file" }],
  });
  assert.deepEqual(seen, ["PUBLIC_SAFE"]);
  assert.equal(result.response, "PUBLIC_SAFE");
});

test("contradictory framework getContent and pageContent cannot silently reach generation", async () => {
  const document = new FrameworkNode("PUBLIC_SAFE");
  document.node.text = "PRIVATE_SECRET";
  let invoked = false;
  const sdk = new RAGAdapter(
    new ProtectedRAG(guardWithMutation(() => {}), 1_000_000, undefined, true), "allowed-source",
  );
  const result = await sdk.run({
    employeeToken: "synthetic", applicationId: "customer-rag", documents: [document],
    generate: docs => { invoked = true; return docs[0].getContent(); },
    sourceTrace: () => [{ sourceId: "allowed-source", resourceId: "public-file" }],
  });
  assert.equal(invoked, false);
  assert.equal(result.decision, "block");
  assert.equal(result.response, null);
});


test("LlamaIndex-style nested node getContent remains usable after isolated snapshot", async () => {
  class ContentNode {
    constructor(text) { this.text = text; }
    getContent() { return this.text; }
  }
  class NodeWithScore {
    constructor(node) {
      this.node = node;
      this.metadata = { source_id: "allowed-source", resource_id: "public-file" };
    }
    getContent() { return this.node.getContent(); }
  }
  const document = new NodeWithScore(new ContentNode("PUBLIC_SAFE"));
  const sdk = new RAGAdapter(new ProtectedRAG(guardWithMutation(() => {
    document.node.text = "PRIVATE_SECRET";
  }), 1_000_000, undefined, true), "allowed-source");
  const result = await sdk.run({
    employeeToken: "synthetic", applicationId: "customer-rag", documents: [document],
    generate: docs => docs[0].getContent(),
    sourceTrace: () => [{ sourceId: "allowed-source", resourceId: "public-file" }],
  });
  assert.equal(result.response, "PUBLIC_SAFE");
  assert.equal(result.decision, "allow");
});
