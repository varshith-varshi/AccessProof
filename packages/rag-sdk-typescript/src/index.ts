import { SourceAttestationVerifier } from "./attestation.js";
export { SourceAttestationVerifier, AttestationError } from "./attestation.js";

export const ADAPTER_CONTRACT_VERSION = "accessproof.rag/v1";

export type RetrievedResource = {
  sourceId: string;
  resourceId: string;
  chunkId?: string;
  content?: string;
  derivedId?: string;
  derivedType?: string;
  contentVersion?: string;
  contentAttestation?: string;
};

export type GuardDecision = "allow" | "block" | "unknown" | "would_allow" | "would_block";
export type ProtectedResponse = {
  decision: GuardDecision;
  response: string | null;
  reason: string;
  decisionId?: string;
  provenanceLevel?: "SOURCE_ATTESTED" | "UNATTESTED_METADATA_ONLY";
  certificationEligible?: boolean;
};

export class GuardError extends Error {
  constructor(public readonly code: string, public readonly status?: number) { super(code); this.name = "GuardError"; }
}

export type GuardClientOptions = {
  baseUrl: string;
  timeoutMs?: number;
  maxRetries?: number;
  fetchImpl?: typeof fetch;
};

export class GuardClient {
  readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly request: typeof fetch;

  constructor(options: GuardClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.timeoutMs = options.timeoutMs ?? 10_000;
    this.maxRetries = Math.max(0, Math.min(options.maxRetries ?? 1, 2));
    this.request = options.fetchImpl ?? fetch;
  }

  private async call<T>(path: string, init: RequestInit): Promise<T> {
    for (let attempt = 0; ; attempt++) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
      try {
        const response = await this.request(`${this.baseUrl}${path}`, { ...init, signal: controller.signal, redirect: "error" });
        if (!response.ok) {
          const retryable = response.status >= 500 && attempt < this.maxRetries;
          if (retryable) continue;
          throw new GuardError(`GUARD_HTTP_${response.status}`, response.status);
        }
        return await response.json() as T;
      } catch (error) {
        if (error instanceof GuardError) throw error;
        if (attempt >= this.maxRetries) throw new GuardError(error instanceof DOMException && error.name === "AbortError" ? "GUARD_TIMEOUT" : "GUARD_UNAVAILABLE");
      } finally { clearTimeout(timeout); }
    }
  }

  health(): Promise<Record<string, unknown>> {
    return this.call("/health", { method: "GET", headers: { Accept: "application/json" } });
  }

  filterResources(input: { employeeToken: string; applicationId: string; requestId: string; resources: RetrievedResource[] }): Promise<{ decisionId: string; decision: GuardDecision; mode?: "protect" | "shadow"; allowed: Array<{ source_id: string; resource_id: string; chunk_ids?: string[] }> }> {
    return this.call<{ decision_id: string; decision: GuardDecision; mode?: "protect" | "shadow"; allowed: Array<{ source_id: string; resource_id: string; chunk_ids?: string[] }> }>("/guard/v1/filter-resources", {
      method: "POST", headers: this.headers(input.employeeToken),
      body: JSON.stringify({ application_id: input.applicationId, request_id: input.requestId, resources: input.resources.map(resource => ({ source_id: resource.sourceId, resource_id: resource.resourceId, scope: "read", chunk_ids: resource.chunkId ? [resource.chunkId] : [] })) }),
    }).then(value => {
      if (!value || typeof value !== "object" || Array.isArray(value)) {
        throw new GuardError("GUARD_INVALID_LAYER1_RESPONSE");
      }
      if (typeof value.decision_id !== "string" || !value.decision_id.trim()
          || typeof value.decision !== "string" || !Array.isArray(value.allowed)) {
        throw new GuardError("GUARD_INVALID_LAYER1_RESPONSE");
      }
      return { ...value, decisionId: value.decision_id };
    });
  }

  checkOutput(input: { employeeToken: string; applicationId: string; requestId: string; decisionId: string; resources: RetrievedResource[]; additionalDecisionIds?: string[] }): Promise<{ decision: GuardDecision; reason: string }> {
    return this.call<{ decision: GuardDecision; reason: string }>("/guard/v1/check-output", {
      method: "POST", headers: this.headers(input.employeeToken),
      body: JSON.stringify({ decision_id: input.decisionId, application_id: input.applicationId, request_id: input.requestId, used_resource_ids: [...new Set(input.resources.map(item => item.resourceId))].sort(), provenance: input.resources.map(item => ({ derived_id: item.derivedId ?? item.chunkId ?? item.resourceId, derived_type: item.derivedType ?? "retrieval", source_resource_ids: [item.resourceId] })), additional_decision_ids: input.additionalDecisionIds ?? [] }),
    }).then(value => {
      if (!value || typeof value !== "object" || Array.isArray(value)
          || typeof value.decision !== "string"
          || typeof value.reason !== "string" || !value.reason.trim()) {
        throw new GuardError("GUARD_INVALID_LAYER2_RESPONSE");
      }
      return value;
    });
  }

  private headers(employeeToken: string): Record<string, string> {
    if (!employeeToken) throw new GuardError("EMPLOYEE_TOKEN_REQUIRED");
    return { Accept: "application/json", "Content-Type": "application/json", Authorization: `Bearer ${employeeToken}` };
  }
}

function allowedByGuard(resources: RetrievedResource[], grants: Array<{ source_id: string; resource_id: string; chunk_ids?: string[] }>): RetrievedResource[] {
  if (!Array.isArray(grants)) throw new GuardError("GUARD_INVALID_ALLOWLIST");
  const scopes = new Map<string, Set<string> | null>();
  for (const grant of grants) {
    if (!grant || typeof grant.source_id !== "string" || !grant.source_id
        || typeof grant.resource_id !== "string" || !grant.resource_id) {
      throw new GuardError("GUARD_INVALID_ALLOWLIST");
    }
    if (grant.chunk_ids !== undefined && (!Array.isArray(grant.chunk_ids)
        || !grant.chunk_ids.every(id => typeof id === "string" && id.length > 0))) {
      throw new GuardError("GUARD_INVALID_ALLOWLIST");
    }
    const key = JSON.stringify([grant.source_id, grant.resource_id]);
    const scope = grant.chunk_ids?.length ? new Set(grant.chunk_ids) : null;
    if (scopes.has(key)) {
      const previous = scopes.get(key);
      if ((previous === null) !== (scope === null)
          || (previous !== null && scope !== null
              && (previous?.size !== scope.size || [...scope].some(id => !previous?.has(id))))) {
        throw new GuardError("GUARD_CONFLICTING_GRANT_SCOPES");
      }
    }
    scopes.set(key, scope);
  }
  return resources.filter(resource => {
    const key = JSON.stringify([resource.sourceId, resource.resourceId]);
    if (!scopes.has(key)) return false;
    const scope = scopes.get(key);
    return scope === null || (scope !== undefined && !!resource.chunkId && scope.has(resource.chunkId));
  });
}

export class ProtectedRAG {
  constructor(
    private readonly guard: GuardClient,
    private readonly maxResponseBytes = 1_000_000,
    private readonly provenanceVerifier?: SourceAttestationVerifier,
    // Explicit, non-certified escape hatch for legacy metadata-only callers.
    private readonly allowUnattestedMetadata = false,
  ) {
    if (provenanceVerifier && allowUnattestedMetadata) {
      throw new Error("ATTESTATION_MODE_CONFLICT");
    }
  }

  async run(input: { employeeToken: string; applicationId: string; resources: RetrievedResource[]; generate: (authorized: RetrievedResource[]) => Promise<string> | string; requestId?: string; sourceTrace?: () => RetrievedResource[] | Promise<RetrievedResource[]> }): Promise<ProtectedResponse> {
    // The caller may reuse or replace its vector-store result array while
    // the Guard request is in flight. Capture only primitive, validated
    // resource fields once before authorization. Do not retain references to
    // mutable document objects or attacker-controlled getters.
    let resources: RetrievedResource[];
    try {
      if (!Array.isArray(input.resources)) throw new Error("INVALID_RETRIEVAL");
      resources = input.resources.map(item => {
        if (!item || typeof item !== "object") throw new Error("INVALID_RESOURCE");
        const copied: RetrievedResource = {
          sourceId: item.sourceId, resourceId: item.resourceId,
          chunkId: item.chunkId, content: item.content,
          derivedId: item.derivedId, derivedType: item.derivedType,
          contentVersion: item.contentVersion, contentAttestation: item.contentAttestation,
        };
        for (const value of Object.values(copied)) {
          if (value !== undefined && typeof value !== "string") throw new Error("INVALID_RESOURCE_FIELD");
        }
        return copied;
      });
    } catch { return { decision: "block", response: null, reason: "RESOURCE_SNAPSHOT_FAILED" }; }
    if (!resources.length) return { decision: "block", response: null, reason: "NO_RETRIEVED_RESOURCES" };
    if (resources.some(item => !item.sourceId || !item.resourceId)) return { decision: "block", response: null, reason: "RESOURCE_METADATA_REQUIRED" };
    const requestId = input.requestId ?? crypto.randomUUID();
    let layer1: Awaited<ReturnType<GuardClient["filterResources"]>>;
    try { layer1 = await this.guard.filterResources({ ...input, requestId, resources }); }
    catch (error) { return { decision: "block", response: null, reason: error instanceof GuardError ? error.code : "GUARD_UNAVAILABLE" }; }
    const mode = layer1.mode ?? "protect";
    if (this.provenanceVerifier && mode !== "protect") {
      return { decision: "block", response: null, reason: "ATTESTED_ROUTE_REQUIRES_PROTECT", decisionId: layer1.decisionId };
    }
    if (mode !== "protect" && mode !== "shadow") return { decision: "block", response: null, reason: "GUARD_MODE_MISMATCH", decisionId: layer1.decisionId };
    const expectedLayer1 = mode === "protect" ? ["allow", "block"] : ["would_allow", "would_block"];
    if (!expectedLayer1.includes(layer1.decision)) return { decision: "block", response: null, reason: "GUARD_MODE_MISMATCH", decisionId: layer1.decisionId };
    if (layer1.decision === "block") return { decision: "block", response: null, reason: "LAYER1_BLOCK", decisionId: layer1.decisionId };
    let authorized: RetrievedResource[];
    try { authorized = allowedByGuard(resources, layer1.allowed); }
    catch { return { decision: "block", response: null, reason: "GUARD_INVALID_ALLOWLIST", decisionId: layer1.decisionId }; }
    if (!authorized.length) return { decision: "block", response: null, reason: "NO_AUTHORIZED_RESOURCES", decisionId: layer1.decisionId };
    // A resource ID is not proof of the bytes the generator will receive.
    // Protect release must fail closed without a pinned ingestion verifier;
    // legacy metadata-only callers must opt in explicitly and never certify.
    if (!this.provenanceVerifier && mode === "protect" && !this.allowUnattestedMetadata) {
      return { decision: "block", response: null, reason: "SOURCE_CONTENT_ATTESTATION_REQUIRED", decisionId: layer1.decisionId };
    }
    if (this.provenanceVerifier) {
      let valid: boolean[];
      try {
        valid = await Promise.all(authorized.map(item => this.provenanceVerifier!.verify(item, input.applicationId)));
      } catch {
        return { decision: "block", response: null, reason: "SOURCE_CONTENT_ATTESTATION_FAILED", decisionId: layer1.decisionId };
      }
      if (valid.some(value => !value)) return { decision: "block", response: null, reason: "SOURCE_CONTENT_ATTESTATION_FAILED", decisionId: layer1.decisionId };
    }
    // A complete application-owned source trace is mandatory in Protect.
    // The initially retrieved list is not proof that tools/cache were unused.
    if (!input.sourceTrace) return { decision: "block", response: null, reason: "PROVENANCE_TRACE_REQUIRED", decisionId: layer1.decisionId };
    let buffered: string;
    try {
      buffered = await input.generate(authorized);
      if (typeof buffered !== "string") throw new TypeError("Model returned non-text output");
    } catch { return { decision: "block", response: null, reason: "MODEL_CALLBACK_FAILED", decisionId: layer1.decisionId }; }
    if (new TextEncoder().encode(buffered).byteLength > this.maxResponseBytes) return { decision: "block", response: null, reason: "RESPONSE_BUFFER_LIMIT", decisionId: layer1.decisionId };
    // Additional cache/tool provenance comes only from trusted application traces,
    // never from the model output or prompt. Gate it through another Layer 1 check.
    let traced: RetrievedResource[];
    try { traced = await input.sourceTrace(); }
    catch { return { decision: "block", response: null, reason: "PROVENANCE_MISSING", decisionId: layer1.decisionId }; }
    if (!Array.isArray(traced) || !traced.length || traced.some(item => !item?.sourceId || !item?.resourceId)) {
      return { decision: "block", response: null, reason: "PROVENANCE_MISSING", decisionId: layer1.decisionId };
    }
    if (this.provenanceVerifier) {
      let valid: boolean[];
      try {
        valid = await Promise.all(traced.map(item => this.provenanceVerifier!.verify(item, input.applicationId)));
      } catch {
        return { decision: "block", response: null, reason: "SOURCE_TRACE_ATTESTATION_FAILED", decisionId: layer1.decisionId };
      }
      if (valid.some(value => !value)) return { decision: "block", response: null, reason: "SOURCE_TRACE_ATTESTATION_FAILED", decisionId: layer1.decisionId };
      const signedKey = (item: RetrievedResource) => JSON.stringify([
        item.sourceId, item.resourceId, item.chunkId ?? null, item.content,
        item.contentVersion, item.contentAttestation,
      ]);
      const tracedKeys = new Set(traced.map(signedKey));
      if (authorized.some(item => !tracedKeys.has(signedKey(item)))) {
        return { decision: "block", response: null, reason: "INCOMPLETE_GENERATOR_SOURCE_TRACE", decisionId: layer1.decisionId };
      }
    }
    // Encode identity as a typed tuple: delimiter joining is ambiguous when
    // provider-controlled identifiers contain separator characters.
    const keyOf = (item: RetrievedResource) =>
      JSON.stringify([item.sourceId, item.resourceId, item.chunkId ?? null]);
    const originalKeys = new Set(authorized.map(keyOf));
    const late = traced.filter(item => !originalKeys.has(keyOf(item)));
    const additionalDecisionIds: string[] = [];
    let lateWouldBlock = false;
    if (late.length) {
      let extra: Awaited<ReturnType<GuardClient["filterResources"]>>;
      try { extra = await this.guard.filterResources({ employeeToken: input.employeeToken, applicationId: input.applicationId, requestId, resources: late }); }
      catch (error) { return { decision: "block", response: null, reason: error instanceof GuardError ? error.code : "GUARD_UNAVAILABLE", decisionId: layer1.decisionId }; }
      const expected = mode === "protect" ? ["allow"] : ["would_allow", "would_block"];
      let allLateAuthorized = false;
      try { allLateAuthorized = allowedByGuard(late, extra.allowed).length === late.length; }
      catch { allLateAuthorized = false; }
      if ((extra.mode ?? "protect") !== mode || !expected.includes(extra.decision) || !allLateAuthorized) {
        return { decision: "block", response: null, reason: "ADDITIONAL_SOURCE_NOT_AUTHORIZED", decisionId: layer1.decisionId };
      }
      lateWouldBlock = extra.decision === "would_block";
      additionalDecisionIds.push(extra.decisionId);
    }
    let layer2: Awaited<ReturnType<GuardClient["checkOutput"]>>;
    try { layer2 = await this.guard.checkOutput({ ...input, requestId, decisionId: layer1.decisionId, resources: traced, additionalDecisionIds }); }
    catch (error) { return { decision: "block", response: null, reason: error instanceof GuardError ? error.code : "GUARD_UNAVAILABLE", decisionId: layer1.decisionId }; }
    const validLayer2 = mode === "protect" ? ["allow"] : ["would_allow", "would_block"];
    if (!validLayer2.includes(layer2.decision)) return { decision: "block", response: null, reason: layer2.decision === "block" ? layer2.reason : "GUARD_MODE_MISMATCH", decisionId: layer1.decisionId };
    return {
      decision: mode === "shadow" && (layer1.decision === "would_block" || lateWouldBlock) ? "would_block" : layer2.decision,
      response: buffered, reason: layer2.reason, decisionId: layer1.decisionId,
      provenanceLevel: this.provenanceVerifier ? "SOURCE_ATTESTED" : "UNATTESTED_METADATA_ONLY",
      certificationEligible: this.provenanceVerifier !== undefined,
    };
  }
}

export type FrameworkDocument = { pageContent?: string; page_content?: string; content?: string; metadata?: Record<string, unknown> };

export class RAGAdapter<T extends FrameworkDocument> {
  constructor(private readonly protectedRag: ProtectedRAG, private readonly sourceId?: string) {}
  async run(input: { employeeToken: string; applicationId: string; documents: T[]; generate: (authorized: T[]) => Promise<string> | string; requestId?: string; sourceTrace?: () => RetrievedResource[] | Promise<RetrievedResource[]> }): Promise<ProtectedResponse> {
    let snapshotDocuments: T[];
    try {
      // The retriever or shared vector cache may mutate the original object
      // while the Guard HTTP request is in flight. The model must receive the
      // exact metadata/content snapshot submitted for authorization.
      snapshotDocuments = input.documents.map(document => {
        if (document === null || typeof document !== "object") throw new Error("INVALID_DOCUMENT");
        // A shallow Object.assign still aliases document.node and every
        // other nested vector-store field. A shared node can change after
        // Layer 1 authorizes metadata, letting getContent() return new bytes.
        // Clone *all* enumerable document state before preserving methods.
        const copiedState = structuredClone({ ...document }) as Record<string, unknown>;
        const snapshot = Object.assign(Object.create(Object.getPrototypeOf(document)), copiedState) as T;
        // Some LlamaIndex wrappers read node.getContent(). structuredClone
        // drops nested class prototypes; pin that accessor to the isolated
        // node's content instead of either losing support or retaining a
        // method bound to the original mutable node.
        const originalNode = (document as T & { node?: { getContent?: () => unknown } }).node;
        const copiedNode = (snapshot as T & { node?: Record<string, unknown> }).node;
        if (originalNode && copiedNode && typeof originalNode.getContent === "function") {
          const stableNodeContent = originalNode.getContent.call(copiedNode);
          if (typeof stableNodeContent !== "string") throw new Error("INVALID_NESTED_NODE_CONTENT");
          Object.defineProperty(copiedNode, "getContent", {
            value: () => stableNodeContent, writable: false, configurable: false, enumerable: false,
          });
        }
        for (const field of ["pageContent", "page_content", "content"] as const) {
          const value = document[field];
          if (value !== undefined) {
            if (typeof value !== "string") throw new Error("INVALID_DOCUMENT_CONTENT");
            Object.defineProperty(snapshot, field, {
              value, writable: true, configurable: true, enumerable: true,
            });
          }
        }
        // LlamaIndex-style APIs may consume getContent() rather than
        // pageContent. If the framework's effective text differs from the
        // authorized canonical input, do not call the model at all.
        const getter = (snapshot as T & { getContent?: () => unknown }).getContent;
        if (typeof getter === "function") {
          const effective = getter.call(snapshot);
          if (typeof effective !== "string") throw new Error("INVALID_FRAMEWORK_CONTENT");
          const canonical = snapshot.pageContent ?? snapshot.page_content ?? snapshot.content;
          if (canonical !== undefined && canonical !== effective) {
            throw new Error("CONFLICTING_FRAMEWORK_CONTENT");
          }
          if (canonical === undefined) {
            Object.defineProperty(snapshot, "content", {
              value: effective, writable: false, configurable: false, enumerable: true,
            });
          }
          // Subsequent framework method reads get the exact immutable text
          // inspected here, not a shared mutable source or external closure.
          Object.defineProperty(snapshot, "getContent", {
            value: () => effective, writable: false, configurable: false, enumerable: false,
          });
        }
        return snapshot;
      });
    } catch {
      return { decision: "block", response: null, reason: "RESOURCE_SNAPSHOT_FAILED" };
    }
    let pairs: Array<{ document: T; resource: RetrievedResource }>;
    try {
      pairs = snapshotDocuments.map(document => ({ document, resource: normalizeDocument(document, this.sourceId) }));
    } catch {
      // Never throw malformed retriever metadata to a customer fallback
      // handler that may accidentally bypass Protect and release raw output.
      return { decision: "block", response: null, reason: "RESOURCE_METADATA_REQUIRED" };
    }
    // Direct ProtectedRAG defensively snapshots caller resources, so object
    // reference equality is not a valid authorization-to-document mapping.
    // Match the *full* primitive content/source binding and preserve duplicate
    // ordinal positions, never merely a potentially colliding document ID.
    const keyOf = (resource: RetrievedResource) => JSON.stringify([
      resource.sourceId, resource.resourceId, resource.chunkId ?? null,
      resource.content ?? null, resource.contentVersion ?? null,
      resource.contentAttestation ?? null,
    ]);
    const byKey = new Map<string, T[]>();
    for (const { document, resource } of pairs) {
      const key = keyOf(resource);
      const documents = byKey.get(key) ?? [];
      documents.push(document);
      byKey.set(key, documents);
    }
    const selectDocuments = (authorized: RetrievedResource[]): T[] => {
      const offsets = new Map<string, number>();
      return authorized.map(resource => {
        const key = keyOf(resource);
        const offset = offsets.get(key) ?? 0;
        const document = byKey.get(key)?.[offset];
        if (document === undefined) throw new GuardError("AUTHORIZED_DOCUMENT_BINDING_MISSING");
        offsets.set(key, offset + 1);
        return document;
      });
    };
    return this.protectedRag.run({
      ...input, resources: pairs.map(pair => pair.resource),
      sourceTrace: input.sourceTrace,
      generate: resources => input.generate(selectDocuments(resources)),
    });
  }
}

export class LangChainAdapter<T extends FrameworkDocument> extends RAGAdapter<T> {}

export function normalizeDocument(document: FrameworkDocument, configuredSourceId?: string): RetrievedResource {
  const metadata = document.metadata ?? {};
  const declaredSource = consistentIdentifier(metadata, ["accessproof_source_id", "source_id"], "SOURCE");
  const configured = stringValue(configuredSourceId);
  if (configured && declaredSource && configured !== declaredSource) {
    throw new GuardError("SOURCE_ID_CONFLICT");
  }
  const sourceId = configured ?? declaredSource;
  const resourceId = consistentIdentifier(metadata,
    ["resource_id", "accessproof_resource_id", "source_resource_id", "document_id", "file_id"], "RESOURCE");
  const chunkId = consistentIdentifier(metadata,
    ["chunk_id", "accessproof_chunk_id", "node_id"], "CHUNK");
  if (!sourceId) throw new GuardError("SOURCE_ID_REQUIRED");
  if (!resourceId) throw new GuardError("RESOURCE_ID_REQUIRED");
  const contentVersion = consistentIdentifier(metadata,
    ["accessproof_content_version", "content_version"], "CONTENT_VERSION");
  const contentAttestation = consistentIdentifier(metadata,
    ["accessproof_content_attestation", "content_attestation"], "CONTENT_ATTESTATION");
  return { sourceId, resourceId, chunkId, content: document.pageContent ?? document.page_content ?? document.content ?? "",
    contentVersion, contentAttestation };
}

function stringValue(...values: unknown[]): string | undefined {
  const found = values.find(value => typeof value === "string" && value.trim());
  return typeof found === "string" ? found.trim() : undefined;
}

// An alias conflict is an authorization error, not a normal fallback: a
// retriever must never launder a document from another source through its
// registered application source or substitute a different provider file ID.
function consistentIdentifier(metadata: Record<string, unknown>, keys: string[], label: string): string | undefined {
  const candidates: string[] = [];
  for (const key of new Set(keys)) {
    const value = metadata[key];
    if (value === undefined || value === null || value === "") continue;
    if (typeof value !== "string" || !value.trim()) throw new GuardError(`${label}_ID_INVALID`);
    candidates.push(value.trim());
  }
  if (new Set(candidates).size > 1) throw new GuardError(`${label}_ID_CONFLICT`);
  return candidates[0];
}
