import assert from "node:assert/strict";
import test from "node:test";
import { GuardClient, ProtectedRAG, RAGAdapter, SourceAttestationVerifier } from "../dist/index.js";

async function signedSource() {
  const keys = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const exported = new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey));
  const verifier = new SourceAttestationVerifier("tenant-A", { "ingester-1": exported });
  const content = "PUBLIC_CONTENT_FROM_TRUSTED_INGESTION";
  const resource = {
    sourceId: "allowed-source", resourceId: "public-file",
    chunkId: "chunk-1", content, contentVersion: "rev-1",
  };
  const issue = async (res, opts = {}) => {
    const now = Math.floor(Date.now() / 1000);
    const data = {
      v: 1, kid: "ingester-1", tenant: opts.tenant ?? "tenant-A",
      app: opts.application ?? "rag-app", source: res.sourceId, resource: res.resourceId,
      chunk: res.chunkId ?? null, revision: res.contentVersion,
      sha256: Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(res.content))),
        value => value.toString(16).padStart(2, "0")).join(""),
      iat: opts.issued ?? now, exp: opts.expires ?? now + 120,
    };
    const payload = new TextEncoder().encode(JSON.stringify(
      Object.fromEntries(Object.entries(data).sort(([a], [b]) => a.localeCompare(b))),
    ));
    const signature = new Uint8Array(await crypto.subtle.sign("Ed25519", keys.privateKey, payload));
    return { ...res,
      contentAttestation: Buffer.from(payload).toString("base64url") + "." +
        Buffer.from(signature).toString("base64url"),
    };
  };
  return { resource: await issue(resource), issue, verifier };
}

function fakeGuard(mode = "protect") {
  let used = 0;
  const client = new GuardClient({
    baseUrl: "https://synthetic-guard.test",
    fetchImpl: async url => {
      if (String(url).endsWith("/filter-resources")) return new Response(JSON.stringify({
        mode, decision: mode === "protect" ? "allow" : "would_allow", decision_id: "test-context",
        allowed: [{ source_id: "allowed-source", resource_id: "public-file", chunk_ids: ["chunk-1"] }],
      }), { status: 200 });
      used++;
      return new Response(JSON.stringify({ decision: "allow", reason: "TEST_LAYER2_ALLOW" }), { status: 200 });
    },
  });
  return { client, outputCalls: () => used };
}

test("attested TypeScript route verifies real Ed25519 source and Layer 2 before release", async () => {
  const { resource, verifier } = await signedSource();
  const guard = fakeGuard();
  let seen;
  const result = await new ProtectedRAG(guard.client, 10000, verifier).run({
    employeeToken: "synthetic", applicationId: "rag-app", resources: [resource],
    generate: docs => { seen = docs[0].content; return docs[0].content; },
    sourceTrace: () => [resource],
  });
  assert.equal(result.response, resource.content);
  assert.equal(result.decision, "allow");
  assert.equal(result.provenanceLevel, "SOURCE_ATTESTED");
  assert.equal(result.certificationEligible, true);
  assert.equal(guard.outputCalls(), 1);
  assert.equal(seen, resource.content);
});


test("a revoked ingestion key cannot attest content into a Protect release", async () => {
  const { resource } = await signedSource();
  const replacement = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const replacementRaw = new Uint8Array(await crypto.subtle.exportKey("raw", replacement.publicKey));
  const verifier = new SourceAttestationVerifier(
    "tenant-A", { "ingester-2": replacementRaw }, 30, ["ingester-1"],
  );
  const guard = fakeGuard();
  let generated = false;
  const result = await new ProtectedRAG(guard.client, 10000, verifier).run({
    employeeToken: "synthetic", applicationId: "rag-app", resources: [resource],
    generate: () => { generated = true; return "LEAKED"; },
    sourceTrace: () => [resource],
  });
  assert.equal(result.decision, "block");
  assert.equal(result.reason, "SOURCE_CONTENT_ATTESTATION_FAILED");
  assert.equal(generated, false);
  assert.equal(guard.outputCalls(), 0);
});

test("signed-content bypass attempts fail closed before generation", async () => {
  const { resource, verifier, issue } = await signedSource();
  const wrongKey = await signedSource();
  const invalid = [
    { ...resource, content: "PRIVATE_PAYROLL_SECRET" },
    { ...resource, sourceId: "foreign-source" },
    { ...resource, resourceId: "restricted-payroll" },
    { ...resource, contentVersion: "rev-2" },
    { ...resource, contentAttestation: "" },
    { ...resource, contentAttestation: wrongKey.resource.contentAttestation },
    await issue(resource, { tenant: "another-tenant" }),
    await issue(resource, { application: "other-app" }),
    await issue(resource, { issued: 1, expires: 100 }),
  ];
  for (const forged of invalid) {
    const guard = fakeGuard();
    let generated = false;
    const result = await new ProtectedRAG(guard.client, 10000, verifier).run({
      employeeToken: "synthetic", applicationId: "rag-app", resources: [forged],
      generate: () => { generated = true; return "LEAKED"; },
      sourceTrace: () => [forged],
    });
    assert.equal(result.response, null);
    assert.equal(result.decision, "block");
    assert.equal(generated, false);
    assert.equal(guard.outputCalls(), 0);
  }
});

test("signed initial context and untrusted tool content cannot be laundered through Layer 2", async () => {
  const { resource, verifier } = await signedSource();
  const injected = { ...resource, content: "UNAUTHORIZED_CACHED_TOOL_TEXT" };
  const guard = fakeGuard();
  const result = await new ProtectedRAG(guard.client, 10000, verifier).run({
    employeeToken: "synthetic", applicationId: "rag-app", resources: [resource],
    generate: docs => docs[0].content,
    sourceTrace: () => [resource, injected],
  });
  assert.equal(result.decision, "block");
  assert.equal(result.response, null);
  assert.equal(result.reason, "SOURCE_TRACE_ATTESTATION_FAILED");
  assert.equal(guard.outputCalls(), 0);
});

test("attested RAG refuses Shadow downgrade", async () => {
  const { resource, verifier } = await signedSource();
  const result = await new ProtectedRAG(fakeGuard("shadow").client, 10000, verifier).run({
    employeeToken: "synthetic", applicationId: "rag-app", resources: [resource],
    generate: docs => docs[0].content, sourceTrace: () => [resource],
  });
  assert.equal(result.decision, "block");
  assert.equal(result.response, null);
});

test("framework adapter forwards attested bytes and rejects a swapped vector result", async () => {
  const { resource, verifier } = await signedSource();
  const frameworkDoc = {
    pageContent: resource.content,
    metadata: {
      source_id: resource.sourceId, resource_id: resource.resourceId,
      chunk_id: resource.chunkId, content_version: resource.contentVersion,
      content_attestation: resource.contentAttestation,
    },
  };
  const guard = fakeGuard();
  const app = new RAGAdapter(new ProtectedRAG(guard.client, 10000, verifier), "allowed-source");
  const good = await app.run({
    employeeToken: "synthetic", applicationId: "rag-app", documents: [frameworkDoc],
    generate: docs => docs[0].pageContent, sourceTrace: () => [resource],
  });
  assert.equal(good.response, resource.content);
  const bad = await app.run({
    employeeToken: "synthetic", applicationId: "rag-app",
    documents: [{ ...frameworkDoc, pageContent: "UNAUTHORIZED_VECTOR_PAYROLL" }],
    generate: docs => docs[0].pageContent, sourceTrace: () => [resource],
  });
  assert.equal(bad.response, null);
  assert.equal(bad.decision, "block");
});

test("cryptographic verification failure must return a safe block", async () => {
  const { resource } = await signedSource();
  const guard = fakeGuard();
  const verifier = { verify: async () => { throw new Error("verification unavailable"); } };
  const result = await new ProtectedRAG(guard.client, 10000, verifier).run({
    employeeToken: "synthetic", applicationId: "rag-app", resources: [resource],
    generate: () => "TEST_CONTENT",
    sourceTrace: () => [resource],
  });
  assert.equal(result.response, null);
  assert.equal(result.decision, "block");
});

test("TypeScript verifies actual Python-issued Ed25519 attestation", async () => {
  const { readFileSync } = await import("node:fs");
  const fixture = JSON.parse(readFileSync(new URL("./python-source-attestation-fixture.json", import.meta.url), "utf8"));
  const verifier = new SourceAttestationVerifier("tenant-cross", {
    [fixture.key_id]: new Uint8Array(Buffer.from(fixture.public_key_b64, "base64")),
  });
  const resource = fixture.resource;
  assert.equal(await verifier.verify(resource, "rag-app", fixture.now_seconds), true);
  assert.equal(await verifier.verify({ ...resource, content: "SWAPPED_SOURCE_BYTES" }, "rag-app", fixture.now_seconds), false);
  assert.equal(await verifier.verify(resource, "wrong-app", fixture.now_seconds), false);
});
