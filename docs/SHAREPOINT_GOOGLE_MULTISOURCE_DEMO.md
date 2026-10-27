# SharePoint + Google Drive mixed-source demo — local validated path

## Local reproducible demonstration
Run `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -v tests/integration/test_gateway_multisource_real_guard.py` in the repository. This provisions a disposable SQLite Guard with a single application, synthetic Google/SharePoint source bindings, different source-specific Alice/Bob identities and two distinct Ed25519 ingestion signers.

It tests:
- Alice receives an LLM response generated with authorized synthetic Google and SharePoint chunks.
- Bob is authorized on Google but denied on SharePoint, and the synthetic model receives no denied SharePoint content.
- Alice's in-flight SharePoint ACL revocation causes the buffered answer to be blocked.
- The single-source selection within a multi-source application takes Guard V2 when explicitly enabled.
- Each provider has an identical resource ID to prove the source namespace is part of the authorization identity.

## Real cloud demo — NOT YET PERFORMED FOR V2
Using the authorized NeuralMatrix Microsoft 365 trial and a Google test tenant, perform actual OIDC employee sign-in, Graph and Drive retrieval with synthetic documents, independently verified permission snapshots, source-specific identity mapping and revocation timing. Then repeat using a signed cached response, group revoke, shared-link revoke, inherited ACL and an alternate response-route bypass attempt. Record actual timestamped observations and consent/connector errors. No fabricated screenshots or results.

Do not use real customer confidential documents for this validation. Do not publish employee passwords, OAuth refresh tokens, session cookies or private signing keys.
