# AccessProof: Live Provider and Gateway Route Validation
Date: 2026-10-27
Verdict: PARTIAL LIVE PROVIDER EVIDENCE + LOCAL GATEWAY MATRIX PASSED. NOT PRODUCTION-CERTIFIED.

## Microsoft SharePoint: real connected-provider verification
The authorized SharePoint connection listed current permissions for all three existing synthetic test documents in the NeuralMatrix093 tenant and successfully fetched all three document bodies with their expected synthetic markers.
- ap_sharepoint_shared_control_20261027.txt: Alice READ; Bob READ; owners intact.
- ap_sharepoint_alice_finance_20261027.txt: Alice READ; no direct Bob grant listed; owners intact.
- ap_sharepoint_bob_engineering_20261027.txt: Bob READ; no direct Alice grant listed; owners intact.

These are genuine current Graph-backed permission listings and content reads under the connected principal. They are NOT independently authenticated employee 200/403 probes, and no permissions were changed or revoked. Missing direct grants are not equivalent to effective 403.

## Google Drive: real inventory, not employee authorization proof
The connected Google Drive AccessProof-Demo folder contains mon/mon.txt and sai/sai.txt. File metadata shows the first document shared with one non-owner writer and the second with a different non-owner writer. This verifies live Drive sharing metadata only. These are personal Google account grants, NOT verified Workspace/Cloud Identity employee sign-in, RAG retrieval, or signed connector enforcement.

## Application prerequisites
The local API, Guard, and demo RAG services were not running. Required Entra web-app client credentials, Graph ingester credentials, and Google employee sign-in credentials were not configured in the local environment. Consequently no live Alice/Bob delegated Microsoft access-denial, real source revoke, or end-to-end live customer RAG run could be completed.

## Gateway response paths
Added tests/security/test_gateway_all_response_routes.py and ran the actual FastAPI Gateway and Guard V2 HTTP routes with locally signed synthetic document content and test JWT identities (model transport synthetic).
- Direct attested chat and signed-snapshot chat: non-stream and SSE deny unauthenticated or unauthorized users before model content; an in-flight revoke prevents output release.
- Signed cache authorization and response authorization: deny missing SharePoint permission and deny after revocation.
- All four answer-release routes: Guard outage leads to block without synthetic content.
- Unexpected model or tool routes do not exist in this Gateway, and customer identity is mandatory.
All 15 new route-matrix tests passed. This covers the tested Gateway, not arbitrary customer-owned extra endpoints.

## Deployment bypass finding and mitigation
Developer Docker Compose drive-rag, gateway and guard share a default non-internal network; a workstation override enables host networking. This configuration CANNOT prove Gateway-exclusive egress.
Added scripts/validate_gateway_route_isolation.py to fail closed on unsafe topology; the local configuration returned BLOCKED_UNVERIFIED_TOPOLOGY as expected.
Added docker-compose.gateway-isolated-reference.yml with distinct internal RAG/model/Guard networks, a separate Guard-only external network, and a Gateway-only host bridge. A static reference validation passed with synthetic placeholder images and configuration; no deployment was performed.
Added tests/security/test_gateway_deployment_isolation.py; new route and topology test group passed 83/83. The static template is not a production certificate.

## Remaining evidence
1. Actual Entra Alice/Bob web sign-in using approved real tenant app registration and authentic delegated provider requests.
2. Actual Google Workspace employee identities and source-specific Drive permission proofs.
3. Authorized synthetic source permission revoke followed by Graph/Drive effective denial and timestamped Guard, RAG, and cache probes.
4. A real customer pipeline with attested source ingestion, correct identity mapping, model/cache route interception, isolated egress and measured error/recovery behavior.
5. Separate customer security assessment of fallback, tools, long-lived conversations, WebSockets, background jobs and hidden egress paths.

No real employee permissions, production application data or connected provider files were changed. Do not label the product production-certified based solely on the passing local tests.
