# AccessProof known limitations — review 2026-10-27

## Current readiness: LOCAL_REFERENCE_VALIDATED for source-qualified Gateway V2

- **External validation:** No successful real Microsoft Graph + Entra Alice/Bob + SharePoint ACL revoke + Google Drive mixed-source run was performed for this patch. Existing local signed snapshots and synthetic employee tokens do not count as enterprise integration evidence.
- **Customer bypass:** Cannot automatically protect any direct model egress, unobserved application cache, alternate response endpoint, WebSocket handler, custom tool return, or prompt contents produced before AccessProof. Customer-side network/cutover enforcement must be reviewed.
- **Connector sync:** Access decisions reflect the most recently installed authenticated source ACL/directory policy. Provider-side changes not yet observed can remain unknown; deny freshness failures but do not claim instantaneous revocation.
- **Retrieval provenance:** V2 needs source-verified attestations, immutable source IDs, content versions and bounded context. Arbitrary uninstrumented RAG prompts cannot supply trusted provenance.
- **Conversation history:** Existing Gateway employee-conversation content is not yet a certified authorization dependency ledger for previous answers; multi-turn reuse and tool-return history need a complete lineage contract. V2 now explicitly rejects nonempty employee conversation history until its dependencies can be safely reauthorized.
- **V2 scope:** Read-only source-qualified resources, bounded text response, buffered streaming; V2 now supports bounded source-qualified ANN authorization-scope allowlists. Customer vector-index integration and late V2 decision contexts are not yet validated or implemented, respectively.
- **Caches:** Existing signed cache manifest route can invoke V2 for mixed sources; real customer Redis/Postgres/Memcached/semantic cache hit interception and V2 failure injection are not comprehensively certified.
- **AuthN:** Local tests use signed synthetic HS256 employee tokens; real Entra OIDC/JWKS tenant validation and provider identity mappings still require controlled tenant credentials and an authorized validation run.
- **Protect activation:** Control-plane checklist explicitly blocks mixed-source Protect until route-specific evidence is available. Presence of binding rows, a healthy Guard, or a green local test does not certify the employee-facing route.
- **Onboarding:** Multi-source creation and UI binding selection exist. Automatic customer topology discovery, install/cutover of every customer framework, zero-code adaptation, arbitrary model feature support and all provider error paths are not fully implemented or tested.
- **Database:** Alembic `n7a2b4c6d801` supports forward upgrade and legacy binding backfill. Downgrade with any multi-source registration deliberately fails until data is migrated. PostgreSQL backup/restore and locked-row race testing remain outstanding.
- **Performance:** Source authorization fan-out, Graph throttle/backpressure behavior and production concurrency/load metrics have not been benchmarked for multi-source V2.
- **Audit:** V2 records decision/audit events; independent audit delivery durability and fully signed per-document lineage at customer endpoint require more testing.
- **Deployment:** No live-traffic cutover, production deployment, customer credentials changes or Git push were performed as part of this engineering patch.

Never represent local reference validation as provider-integrated or production-certified protection.
