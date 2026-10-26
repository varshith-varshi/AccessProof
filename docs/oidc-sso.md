# OIDC SSO

AccessProof supports organization-level OpenID Connect SSO.

## Security properties

- OIDC discovery is fetched from a validated public HTTPS issuer.
- Authorization Code flow uses PKCE.
- Login state and nonce are one-time and expire.
- ID tokens are validated against the provider JWKS, issuer, audience, time claims and nonce.
- Identities are keyed by stable `(issuer, subject)` rather than email alone.
- Organizations may restrict allowed email domains and configure a default role / role-claim mapping.
- Enforced SSO prevents password-authenticated member sessions from being used for that organization.
- OWNER retains break-glass password access.
- The OIDC client secret is encrypted through the configured secret backend and is never returned by read APIs.

## Configuration

An OWNER/ADMIN configures issuer, client ID, client secret, allowed domains, default role, optional role claim mapping and whether SSO is enforced from Settings or `/api/v1/auth/oidc/config`.

The browser callback defaults to `${ACCESSPROOF_PUBLIC_APP_URL}/api/v1/auth/oidc/callback` unless `ACCESSPROOF_OIDC_REDIRECT_URI` is explicitly configured. Production URLs must use HTTPS.

## Current validation state

Cryptographic token/JWKS validation, PKCE/state replay protection, auto-provisioning, role mapping, enforced login behavior and browser callback handling are automated locally. No real third-party IdP tenant was supplied in this environment, so external IdP validation remains pending.
