# Cloud Identity Free + Google Drive RAG: controlled validation

## Current evidence (2026-10-27)

- Live Google OIDC discovery and public JWKS endpoint: reachable; this checks
  Google's public login metadata, **not** an employee's sign-in.
- Browser employee sign-in flow: implemented under `drive-rag-demo` using
  server-side Google OAuth authorization code + PKCE + state/nonce and
  cryptographic ID token verification.
- Protected RAG browser route: `/demo`; authenticated employee Google ID
  tokens remain server-side, and the Guard independently verifies the token.
- Google identity-to-source mappings must use **immutable Google user IDs**
  (OIDC `sub`, corresponding to Directory API user `id`). Never use an
  email address as the ACL subject.
- Local integration tests use synthetic, RSA-signed Google-shaped identity
  tokens and a real AccessProof Guard/PolicyCache. **This is not certification
  against a live Cloud Identity Free organization.**
- Real Cloud Identity tenant and authorized OAuth client **not configured**.
  The previous manually supplied Drive owner access token returned HTTP 401
  on a read-only `files.get` probe; renew it via supported OAuth consent.

## Configure an authorized demo organization

1. Establish a Google Cloud Identity Free organization on a domain you
   control and create synthetic employees `alice@yourdomain` and
   `bob@yourdomain`. Use these accounts only with synthetic documents.
2. Create/obtain an accessible Google Drive owner account that can store
   the synthetic documents. Cloud Identity Free employees do not receive
   their own storage allocation.
3. In a Google Cloud project controlled by the test organization, create a
   **Web application** OAuth client for the demo RAG. Register the exact
   callback URL `http://localhost:8200/v1/auth/google/callback` for local
   testing (or an HTTPS callback for remotely hosted demos). Configure an
   appropriate OAuth consent audience and authorize employee test accounts.
   The employee login scopes are `openid email profile` only.
4. Set in the operator-controlled `.env`, without committing secrets:

   ```dotenv
   ACCESSPROOF_DEMO_GOOGLE_CLIENT_ID=<your Google OAuth web client ID>
   ACCESSPROOF_DEMO_GOOGLE_CLIENT_SECRET=<secret managed on the server>
   ACCESSPROOF_DEMO_GOOGLE_HOSTED_DOMAIN=yourdomain.example
   ACCESSPROOF_DEMO_GOOGLE_REDIRECT_URI=http://localhost:8200/v1/auth/google/callback
   ```

5. Separately configure AccessProof's Google Drive/Directory **source
   operator** OAuth connection via the control-plane Sources UI. It needs
   the Drive and Admin SDK scopes documented in
   `docs/google-drive-oauth-and-watch.md`. This is a different permission
   context from employee sign-in. OAuth credentials and authorization
   must be granted by the actual test tenant administrator.
6. Configure the Guard for Google's employee ID tokens:
   - identity mode: `oidc`
   - issuer: `https://accounts.google.com`
   - audience: exact demo Google OAuth Web client ID
   - subject claim: `sub`
   - identity mappings: Google ID token `sub` -> matched Google Drive
     source subject's stable Directory API ID
   - enrolled, healthy Guard and `protect` application/source bindings
7. Run the demo service, e.g.
   `docker compose --profile drive-rag up -d --build drive-rag`;
   open `http://localhost:8200/demo` from the same browser host as the
   OAuth callback. Sign in separately as Alice and Bob.
8. Run the source-side test matrix: allow Alice; deny Bob; revoke Alice at
   the Google Drive source; wait for authoritative source/ACL sync; ask again;
   verify stale content is not exposed. Measure time from actual Google
   revocation to Guard denial. Do not silently pass when source sync fails.

## Demo limitations

This reference login uses bounded, **single-process in-memory sessions**.
A process restart ends all sessions; it does not implement durable,
multi-instance enterprise identity sessions or employee lifecycle
management. Its auth flow is for demonstrating *sign-in* and Guard
authorization, not for authenticating AccessProof's control plane.

Cloud Identity Free has no included Drive storage, and internal Shared
Drive roles are restricted. A real live tenant, configured OAuth consent,
managed employee sign-ins, Admin SDK sync and Drive permission changes
are required before claiming live validation.

Do not use customer data, collect employee passwords, or paste OAuth
refresh tokens into the web UI. All tests should use organization-authorized
synthetic data and dedicated test identities.
