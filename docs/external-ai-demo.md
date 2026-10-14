# External AI demo target

Run the isolated demo target with an external OpenAI-compatible model:

```bash
export DEMO_AI_MODEL_BASE_URL=https://api.groq.com/openai/v1
export DEMO_AI_MODEL_API_KEY=your-provider-key
export DEMO_AI_MODEL_NAME=your-model-name
export DEMO_AI_SERVICE_TOKEN=choose-a-long-random-token
docker compose --profile full --profile demo-ai up --build
```

The demo service listens inside Compose at `http://demo-ai:8100`. It creates
only synthetic documents, checks source access immediately, and can deliberately
retain retrieval access for `DEMO_AI_STALE_ACCESS_SECONDS` after revocation.

For an AccessProof source, create a `demo-ai` source with credentials:

```json
{"base_url":"http://demo-ai:8100","service_token":"your-token"}
```

For the target, use `http://demo-ai:8100/v1/chat` in private-runner mode with:

```json
{"request_body":{"message":"{{ probe }}","user_id":"{{ principal.external_id }}"},"answer_path":"answer","citations_path":"citations","retrieved_documents_path":"retrieved_documents"}
```

For a real Entra test, set `DEMO_AI_REQUIRE_OIDC=1`,
`DEMO_AI_OIDC_ISSUER=https://login.microsoftonline.com/<tenant-id>/v2.0`, and
`DEMO_AI_OIDC_AUDIENCE=<the API application ID URI>`. Configure the target
headers as `{"Authorization":"Bearer {{ principal.access_token }}"}` and put
the Alice and Bob test-user access tokens in encrypted **Test Identity**
credentials (never a run JSON payload). The bot discovers the provider's
`jwks_uri` through standard OIDC discovery, verifies signature, issuer,
audience, expiry and `nbf`, then derives the identity from the verified `oid` claim;
the request body's `user_id` is ignored in OIDC mode.

Set `DEMO_AI_OIDC_REQUIRED_SCOPES=access_as_user` to require a delegated user
token carrying that `scp` value. Application tokens, missing scopes, a wrong
tenant (`DEMO_AI_OIDC_TENANT_ID`), unknown signing keys, and invalid issuer or
audience are rejected with safe reason codes; tokens are never returned.

This service is a dedicated synthetic test harness. It is not a production
identity provider, document store, or authorization system.
