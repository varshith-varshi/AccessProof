# AccessProof production readiness (2026-11-02)

## Determination

| Question | Answer |
|---|---|
| Overall product readiness | **NOT_READY** |
| Deployment protection state (SharePoint test workspace) | **Not protected.** Last reported state: `protect_pending`, Guard `DEGRADED` (source certificate missing). Not re-observed here. |
| Signed technical evidence issued | **None.** No certificate or signature was produced; nothing qualified. |
| Independent certification | **None.** This is an internal engineering assessment, not an accreditation. |

## Why NOT_READY

1. The primary end-to-end acceptance test (Alice/Bob ALLOW/DENY through the
   real protected RAG, then revoke and restore) has **never passed**. The live
   pipeline is blocked at SharePoint effective-permission certification (O-01).
2. Real employee OIDC identities are not mapped (O-02).
3. Revocation latency has not been measured (O-08).
4. The fixes in this change (D-01..D-04) are **not deployed** (O-07).
5. This session could not reach production, AWS or the tenant to verify anything live.

## Certification scope (if and when evidence exists)

```
Product:                       NeuralMatrix AccessProof
Git commit:                    see commit on branch claude/modest-bell-tazupa
Environment:                   NOT VERIFIED (production unreachable)
Supported source provider:     Microsoft SharePoint Online (list-item effective profile) — NOT CERTIFIED
                               Google Workspace Drive V1 — regression scope only
Supported RAG adapter:         accessproof.gateway/v1 (OpenAI-compatible chat completions, signed retrieval)
Supported architecture:        customer-hosted Guard + Gateway on Docker Compose, one selected chatbot
Certification timestamp:       none
Evidence expiry:               n/a
```

## Shortest path to READY_FOR_PRODUCTION_APPROVAL

1. Deploy this change: migrations `q1a2b3c4d5e6` and `r2b3c4d5e6f7`, then API,
   worker and web. Run `scripts/issue_source_certificate.py keygen` on a
   separate certifier host, set `ACCESSPROOF_SOURCE_CERTIFICATION_PUBLIC_KEYS_JSON`
   on the API, and remove any `…_HMAC_KEY`.
2. Re-pair the test Gateway with the new installer; confirm the dashboard shows
   `Connected` from heartbeats.
3. Have Alice and Bob each sign in through real Entra OIDC
   (`scripts/verify_delegated_actors.py`), and confirm the identity mappings sync to Guard.
4. With explicit owner authorization, run the synthetic revoke/restore trial and
   record provider-observed changes with timestamps.
5. Run mission §6 tests 1–12 through the customer route; save artifacts and
   their SHA-256 digests into the evidence JSON.
6. Issue the certificate on the certifier host only if all 14 checks are PASS,
   import it, and confirm Guard `ready` with Gateway `Connected · ready`.
7. Have an authorized reviewer approve the evidence package.
