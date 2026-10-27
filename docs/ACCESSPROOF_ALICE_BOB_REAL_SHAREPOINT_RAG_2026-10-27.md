# NeuralMatrix AccessProof — real Alice/Bob SharePoint RAG test environment

**27 October 2026** · **Status:** SharePoint documents and native grants LIVE; employee Entra login + AccessProof certificate NOT YET LIVE.

## Real Microsoft SharePoint evidence

Tenant: `6479e7ca-b256-4ebc-a408-871b9046547c`
Site: `neuralmatrix093.sharepoint.com,93ebc364-c7cc-44cc-b789-937791f4e220,20231c9b-3196-4a5e-9ed0-0404090d5930`
Library list ID: `8200ffae-ba10-42c5-bfa9-8f7ac155c5c4`
Drive ID: `b!ZMPrk8zHzES3iZN3kfTiIJscIyCWMV5KntAEBAkNWTCu_wCCELrFQr-pj3rBVcXE`
Approved test folder ID: `016KKBFAIWB6XJEP7J6FGIZFFGVLQEDZPB`
Folder URL: `https://neuralmatrix093.sharepoint.com/Shared%20Documents/AccessProof-RAG-Compatibility-Test-20261027`.

The signed-in SharePoint tenant resolved two real recipient principals:

- Alice: `alice@NeuralMatrix093.onmicrosoft.com` (actual SharePoint grant displayed `alice`)
- Bob: `bob@NeuralMatrix093.onmicrosoft.com` (actual SharePoint grant displayed `bob`)

### Three synthetic documents created and read back from Microsoft

| File | Drive item ID | Alice grant | Bob grant | Synthetic content marker |
|---|---|---|---|---|
| `ap_sharepoint_shared_control_20261027.txt` | `016KKBFAN536UXRFJZOZE3LSDMPGLWN6TC` | READ | READ | `AP_SHARED_20261027_M6K2` |
| `ap_sharepoint_alice_finance_20261027.txt` | `016KKBFAJYEMXFFYCSYRALYGIVKWFQ7C45` | READ | NONE | `AP_ALICE_20261027_J3R8` |
| `ap_sharepoint_bob_engineering_20261027.txt` | `016KKBFAPDOKLZSIPZM5AZ3SCS4H3DJ7UQ` | NONE | READ | `AP_BOB_20261027_V8T4` |

Each file was uploaded through authenticated SharePoint Graph and fetched back successfully. File-specific permissions were assigned with `retain_inherited_permissions=false` so the initial site Visitors/Members groups do not continue inheriting permissions into these three test files. All three permission listings were read back from Graph. Administrator/owner principal permissions remain intact.

**Critical distinction:** SharePoint Graph shows *grant inventory*, not a cryptographically verified employee-effective source denial. We have NOT logged in with either user's delegated Graph token to prove the 403/200 combinations, and site-level administrative privilege/group membership could still matter. These are the intended ACLs, not proof of complete native effective-ACL resolution.

## RAG implementation added

- `packages/auth/entra_demo_login.py`: tenant-pinned Microsoft OIDC authorization code + PKCE, nonce/state, signed ID token validation, immutable `oid` and `tid`, signed preferred_username matched against the selected test account, encrypted-in-transit server-side token exchange and HttpOnly sessions. Alice/Bob buttons are **login hints**, not spoofed identity switches. Does not accept plaintext employee passwords.
- `drive-rag-demo/app.py`: `GET /demo/entra` provides a two-button employee switcher plus question input, and existing `POST /v1/protected-chat` forwards the signed employee token to Guard (only when the operator explicitly selects `ACCESSPROOF_DEMO_SOURCE_PROVIDER=microsoft365`). A mismatched account is rejected, never implicitly given the other account's identity.
- `docker-compose.yml`: opt-in Entra RAG configuration without changing the Google default.
- Earlier integration: `connectors/microsoft365/snapshot_agent.py` publishes SharePoint source-signed metadata and document content into the existing RAG trusted-snapshot volume while retaining the signing key and Graph application token outside the RAG container.

### Local regression evidence

5 Entra-specific integration tests pass, including two independent signed RSA identities, same-browser account switching, failure on mismatched identity, Guard Layer 1/Layer 2 decisions, and local simulated revocation. The real local Guard engine independently verifies OIDC signatures in the tests (synthetic/mock Microsoft OIDC wire data). These tests **do not** prove a live Microsoft login or the actual SharePoint ACL revocation.

54 broader Entra/Google/Guard/Microsoft/SharePoint tests passed in the initial check; an additional Entra same-browser-to-Guard test enhancement passed in a subsequent 5-test run. Ruff, mypy and Compose validation passed.

## Remaining configuration to make sign-in live

The user accounts now exist and their SharePoint grants are configured, but no AccessProof RAG Entra **application registration/client ID and client secret** is available in the runtime. A ChatGPT SharePoint connection does not transfer its delegated Graph/OIDC credentials to AccessProof.

Register a **separate** Microsoft Entra web application in the same NeuralMatrix tenant for this test RAG; register exact redirect URI `http://localhost:8200/v1/auth/entra/callback` (or the real HTTPS site URL), use a **server-only** client credential, and enable `openid email profile` scopes. Do not configure broad Graph application permissions on the RAG browser login client. The existing separate SharePoint ingester app will use its own app-only, site-scoped Graph permission. Never store Alice/Bob passwords in the RAG.

For an isolated local test profile:

```dotenv
ACCESSPROOF_DEMO_SOURCE_PROVIDER=microsoft365
ACCESSPROOF_DEMO_ENTRA_TENANT_ID=6479e7ca-b256-4ebc-a408-871b9046547c
ACCESSPROOF_DEMO_ENTRA_DOMAIN=neuralmatrix093.onmicrosoft.com
ACCESSPROOF_DEMO_ENTRA_ALICE_EMAIL=alice@NeuralMatrix093.onmicrosoft.com
ACCESSPROOF_DEMO_ENTRA_BOB_EMAIL=bob@NeuralMatrix093.onmicrosoft.com
ACCESSPROOF_DEMO_ENTRA_REDIRECT_URI=http://localhost:8200/v1/auth/entra/callback
# ACCESSPROOF_DEMO_ENTRA_CLIENT_ID=<from tenant-specific app registration>
# ACCESSPROOF_DEMO_ENTRA_CLIENT_SECRET=<from private server secret store>
```

Configure the Guard with exact Microsoft issuer `https://login.microsoftonline.com/6479e7ca-b256-4ebc-a408-871b9046547c/v2.0`, audience equal to the Entra demo app's client ID, `subject_claim=oid`, expected tenant GUID, verified `oid`-to-source-principal mappings and **actual** SharePoint grants/sync. Configure `ACCESSPROOF_DEMO_SOURCE_ID`, `ACCESSPROOF_DEMO_APPLICATION_ID`, signing public key, tenant, strict trusted snapshot mode, and the separate SharePoint ingester app-only credentials.

Once the services and app registration are ready, visit `http://localhost:8200/demo/entra`, select Alice, sign into Microsoft, ask finance questions, switch to Bob and sign in again, then ask the identical questions. Verify the Microsoft delegated 200/403 source responses and the Guard's output decisions **independently**, including cache hit and post-revocation probes, before enabling Protect.

**Certification remains NOT CERTIFIED.** The local RAG generator is a deterministic demonstration generator, not evidence of a production LLM implementation. A signed SharePoint document by itself never proves employee authorization.

## Continuation audit: signed-only SharePoint fallback and regression suite

- Verified again with the real Microsoft SharePoint connector that the sandbox folder contains the original canary plus the three Alice/Bob test documents. Live Graph permission listings show Alice's direct READ on the finance file, Bob's direct READ on the engineering file, and two direct READ grants on the shared file. These are **grant inventories**, not delegated effective-access probes.
- Updated `drive-rag-demo/app.py`: when `ACCESSPROOF_DEMO_SOURCE_PROVIDER=microsoft365`, the protected chat route must have `ACCESSPROOF_DEMO_REQUIRE_ATTESTED_CONTENT=1` and a configured signed snapshot path. It fails closed with `SHAREPOINT_SIGNED_SOURCE_REQUIRED` rather than falling back to Google Drive's unsigned legacy fetcher. The same behavior applies to the buffered protected streaming route.
- Updated the local Entra Alice/Bob Guard integration test to consume real Ed25519-signed, tenant/source/application-bound synthetic documents instead of unsigned legacy cache data. This test still uses simulated Microsoft OIDC tokens, not real Microsoft employee accounts.
- New negative test confirms that even after a simulated Microsoft login, the RAG rejects unsigned SharePoint document content.
- **69 relevant tests passed** across Entra sign-in, Google sign-in, native SharePoint connector, signed snapshots, Guard and Gateway; Ruff, mypy, Docker Compose validation and `git diff --check` passed.
- Added `docs/entra_alice_bob_demo.env.example` with verified, non-secret tenant/SharePoint IDs, strict signed ingestion requirements and correct Guard OIDC `oid` mapping. No real employee passwords or client secrets are stored.

**Not yet completed:** production Entra web-app registration and secret, ingestion app registration/admin consent, actual Alice/Bob Microsoft OIDC sessions, live delegated `/me` authorization/denial probes, source permission mutation+revocation under their delegated identities, an online Guard enrollment/policy sync, and a full protected chat/answer-cache penetration test against live Microsoft. The current deployment contains no running RAG services and its local `.env` does not contain the necessary Microsoft client credentials. Do not claim live LLM certification or enable Protect.
