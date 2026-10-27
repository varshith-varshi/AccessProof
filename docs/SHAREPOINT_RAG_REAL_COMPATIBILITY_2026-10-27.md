# AccessProof — SharePoint → RAG compatibility, 27 October 2026

## Verified against live NeuralMatrix SharePoint

- Microsoft Graph site discovery succeeded: `https://neuralmatrix093.sharepoint.com`.
- Document library **Documents**: list ID `8200ffae-ba10-42c5-bfa9-8f7ac155c5c4`.
- Graph drive: `b!ZMPrk8zHzES3iZN3kfTiIJscIyCWMV5KntAEBAkNWTCu_wCCELrFQr-pj3rBVcXE`.
- In the otherwise empty library, created an isolated folder **AccessProof-RAG-Compatibility-Test-20261027** (folder ID `016KKBFAIWB6XJEP7J6FGIZFFGVLQEDZPB`).
- Uploaded an invented `text/plain` canary `accessproof_rag_sharepoint_canary_20261027.txt` (item ID `016KKBFAKU3ZELVFMBLBEYVY3PPHHPQPEQ`).
- Retrieved that exact canary through the connected SharePoint service and confirmed it contained `AP_CANARY_M365_20261027_RAG_SANDBOX`; Graph metadata returned expected library/drive/folder IDs and a source eTag.
- No unrelated SharePoint documents, employee identities, permissions or tenant policies were changed.

This is **real provider read/write/readback**, not a real AccessProof app-only-token or real employee-Gateway validation. The ChatGPT-connected Microsoft credential cannot be imported into AccessProof's own independent app.

## Fixed integration gap

Existing `drive-rag-demo` supported Google Drive trusted snapshots, but not a Microsoft 365 source snapshot publisher. Added:

- `connectors/microsoft365/snapshot_agent.py`: tenant + site + library + folder-pinned Graph app-token retrieval; verified complete boundary inventory; text-only fetch through `SharePointTrustedIngestion`; restricted Ed25519 signing key; atomic signed snapshot output. Empty, invalid, changed, unsupported, oversize or partially failed source refresh cannot publish a new complete snapshot. Source token and signing key remain in the ingester container, not the RAG/LLM.
- `docker-compose.yml`: opt-in `sharepoint-rag-ingester` profile, separate credentials and signing-key mount, shared signed-snapshot volume already consumed by RAG in strict mode.
- `tests/unit/test_sharepoint_rag_snapshot_agent.py`: signed snapshot verifies on RAG side, rejects source/application mismatch and tampered content, does not publish a partial snapshot after ingestion error.
- **59** focused SharePoint, Graph, RAG Guard and signed snapshot tests passed. Ruff, mypy, Docker Compose config validation passed.

## Running the isolated customer-side ingester

1. In Microsoft Entra, register a dedicated AccessProof test application with **minimal SharePoint site-scoped Graph application consent**; do not confuse delegated ChatGPT connector authentication with app-only credentials. Store `ACCESSPROOF_MICROSOFT_CLIENT_ID` and `ACCESSPROOF_MICROSOFT_CLIENT_SECRET` only in private process/Compose environment.
2. Configure these *verified* source values (not an unrelated production library):
   - `ACCESSPROOF_MICROSOFT_TENANT_ID=6479e7ca-b256-4ebc-a408-871b9046547c`
   - `ACCESSPROOF_SHAREPOINT_SITE_ID=neuralmatrix093.sharepoint.com,93ebc364-c7cc-44cc-b789-937791f4e220,20231c9b-3196-4a5e-9ed0-0404090d5930`
   - `ACCESSPROOF_SHAREPOINT_LIST_ID=8200ffae-ba10-42c5-bfa9-8f7ac155c5c4`
   - `ACCESSPROOF_SHAREPOINT_DRIVE_ID=b!ZMPrk8zHzES3iZN3kfTiIJscIyCWMV5KntAEBAkNWTCu_wCCELrFQr-pj3rBVcXE`
   - `ACCESSPROOF_SHAREPOINT_ROOT_ITEM_ID=016KKBFAIWB6XJEP7J6FGIZFFGVLQEDZPB`
3. Use a **customer-owned** raw 32-byte Ed25519 key in a private file with permissions `0600`; set `ACCESSPROOF_DEMO_SOURCE_SIGNING_KEY_PATH`, unique `ACCESSPROOF_DEMO_ATTESTATION_KEY_ID`, `ACCESSPROOF_DEMO_APPLICATION_ID`, and `ACCESSPROOF_DEMO_SOURCE_ID` to exact application/source registrations.
4. With the credentials securely available, launch only the ingester via `docker compose --profile sharepoint-rag-ingest up --build sharepoint-rag-ingester`. The signer publishes `/run/accessproof/trusted/sharepoint.snapshot.json` into the existing signed-snapshot volume. For the protected RAG, set `ACCESSPROOF_DEMO_TRUSTED_SNAPSHOT_PATH=/run/accessproof/trusted/sharepoint.snapshot.json`, `ACCESSPROOF_DEMO_REQUIRE_ATTESTED_CONTENT=1`, attestation tenant/key ID and corresponding **public key**. RAG has read-only volume access.
5. Set Gateway's source/application binding, real employee Entra OIDC configuration and independent live-permission certificate before Protect. A successful snapshot and a permitted Graph download alone never authorize an LLM response.

## Remaining gaps (not silently claimed fixed)

- **End-to-end RAG not yet connected to the live tenant:** app registration/admin consent and server-side Graph credentials for AccessProof have not been supplied. The new ingester's live Graph app-token path was not executed. No running RAG/Guard services or live authenticated Entra employee chat were tested.
- **No true revocation/cached-answer leak test yet:** Alice/Bob employee identities, delegated `/me`, native SharePoint inheritance/link semantics and post-revocation output checks require controlled enterprise authorization evidence.
- Only `text/plain` is supported by this verified SharePoint ingestion bridge. PDF/DOCX and general enterprise formats need dedicated independently verifiable extraction and tests.
- Signing a provider document proves content provenance, **not** whether a particular employee is currently authorized. Guard must enforce that separately; Microsoft/SharePoint Protect stays **SHADOW ONLY / NOT CERTIFIED**.
