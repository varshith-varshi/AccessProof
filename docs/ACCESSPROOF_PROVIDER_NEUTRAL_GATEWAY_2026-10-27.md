> **Update (2026-10-27):** This earlier single-source limitation describes the pre-V2 Guard. See [MULTI_SOURCE_AUTHORIZATION.md](MULTI_SOURCE_AUTHORIZATION.md) for the newly implemented bounded, locally validated multi-source protocol. Live provider and customer-route certification are still required.

# AccessProof: Provider-Neutral Gateway V1 — implemented 2026-10-27

## Purpose

Reuse the **same Gateway code** for customer RAG applications whose data comes from Google Drive, SharePoint, and other independently attested document sources. This reduces source/framework-specific integration work. It is **not** a universal transparent interception proxy, and it does **not** certify arbitrary RAGs automatically.

## Verified code changes

- `apps/gateway/accessproof_gateway/app.py`
  - Existing strict `POST /v1/chat/completions`: employee-authenticated, independently signed retrieved resources, Layer 1 before model and Layer 2 before any response, buffered SSE.
  - **NEW** `POST /v1/snapshots/chat/completions`: accepts a tenant/application-verified employee JWT plus a source ID allowlisted in local operator configuration. Reads an independently signed provider-specific snapshot from a **customer-side, read-only volume**. Rejects symlinks, missing/stale/wrong-source/tampered snapshots via the existing `load_snapshot` validation. Selects no arbitrary filesystem path and never trusts a caller's raw source data. Reuses the exact same protected Gateway model/Guard path. Bounded to 50 signed chunks per request and source snapshots ≤240s old. This small-corpus route is appropriate for **reference demos**, not large-scale semantic search.
  - **NEW alias** `POST /v1/responses/authorize`: general signed dependent-answer release across cache/custom return paths, same implementation as the existing `/v1/cache/authorize`. Requires the customer's trusted cache/response signing key, signed answer/dependency manifest, current authenticated employee and reauthorization by Guard. This validates release; it cannot retroactively prevent unprotected earlier model exposure.
  - **NEW** explicit no-store/no-cache/Vary headers on all successful Gateway API paths, including cached answers and buffered streams.
  - **NEW** `ACCESSPROOF_GATEWAY_SOURCE_SNAPSHOTS_JSON` operator-only mapping of source ID to absolute file path. The API cannot choose a path or an unregistered source. Invalid configurations fail closed.
- `docker-compose.yml`: mounts the existing independently generated signed-ingestion snapshot volume **read only** into the Gateway, with the mapping env. Ingestion and signing private keys remain outside the Gateway.
- Tests: `tests/unit/test_gateway_multisource_snapshots.py`, `tests/integration/test_gateway_source_neutral_real_guard.py`, `tests/unit/test_gateway_universal_cache.py`.

## IMPORTANT: Guard is one source per application

The **real, current Guard** binds an `application_id` to a single `source_id` in its synchronized policy. An application request with two different sources is therefore rejected, not claimed supported. `source_ids` on the new route accepts **exactly one** source for now. Reuse the same Gateway implementation for `rag-google` and `rag-sharepoint` as separate registered applications (or separate scoped Gateway deployments). True multi-source *within one customer RAG answer* requires versioned Guard context, per-source verified identity mappings, cross-source revocation/revision checks and independent tests before eligibility for Protect. Do not turn on multi-source by trusting test mocks.

## Example configuration (reference, no secrets)

The independent Google Drive and Microsoft 365 ingesters write these files into the shared customer-owned read-only volume:

```
/run/accessproof/trusted/drive.snapshot.json
/run/accessproof/trusted/sharepoint.snapshot.json
```

Set the source alias mapping for the relevant application, using the **actual registered source ID** (the examples are placeholders):

```dotenv
ACCESSPROOF_GATEWAY_SOURCE_SNAPSHOTS_JSON={"customer-sharepoint-source":"/run/accessproof/trusted/sharepoint.snapshot.json"}
```

Use the normal Gateway `ACCESSPROOF_GATEWAY_APPLICATION_ID`, `TENANT_ID`, Guard URL, model URL, and `ATTESTATION_PUBLIC_KEYS_JSON` for this exact source, and a **separately provisioned** Guard whose application binding is in Protect only after live source/identity validation. A different Google app Gateway can use its own source alias and `drive.snapshot.json` with the same Gateway image.

### Signed-snapshot chat request

```http
POST /v1/snapshots/chat/completions
Authorization: Bearer <verified employee JWT>
Content-Type: application/json
```

```json
{
  "application_id": "rag-sharepoint",
  "employee_question": "What can I access?",
  "source_ids": ["customer-sharepoint-source"],
  "stream": false
}
```

No client can provide `document_text`, local file names or signer keys on this route. Invalid, stale or unknown source results in safe refusal. Guard Layer 1 filters the signed chunks *before model invocation*; Guard Layer 2 must approve the completed model result *before Gateway releases it*.

### Signed response release for existing answer caches or tool-result routes

The Gateway exposes the same previously tested signed answer contract at `POST /v1/responses/authorize`. This is **not** an unsigned `answer` passthrough. The caller must submit an independently signed answer manifest with source-attested dependencies (see `CachedAnswerAuthorizationInput` schema), current employee JWT, and authorization revision binding when Guard requires one. The customer's cache/response return path **must actually call this endpoint before emitting bytes**.

## Explicit unsupported / not validated

- Arbitrary third-party RAG with no trusted document IDs/attestations, whose LLM receives retrieved text before the Gateway, or whose cache/stream/tool return path bypasses the Gateway: **not protected**.
- Simultaneous SharePoint+Google docs in a **single app request**: rejected until Guard multi-source authorization is implemented and certified.
- WebSocket and true upstream token-by-token streaming: unsupported. The reference HTTP SSE is **buffered after authorization**.
- Uninstrumented browser/CDN/Redis/Memcached caches: not protected automatically. Route validation and customer network egress checks remain mandatory.
- Customer-specific RAG frameworks/vector retrieval need explicit route/cutover integration, not framework-specific SDK install by default.
- Real Microsoft employee sign-in, actual tenant delegated Graph access/denial, live revocation, real model providers and real customer network routing are **not** certified by synthetic local tests.

**Release verdict:** Gateway core reuse and provider-independent *reference* route work in local regression and real local Guard testing. Universal automatic compatibility and customer production Protect certification are **not established**.
