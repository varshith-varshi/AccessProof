# Google Drive customer-side validation configuration (V3 reference flow)

**Status:** Local implementation and synthetic validation. Live Google Workspace
consent, effective permissions, change notification delivery, directory/group
revocations and provider-side token rotation are **not** certified.

## Guided Google OAuth (control-plane API)

1. In an administrator-controlled Google Cloud project, enable Drive API and
   Google Workspace Admin SDK, configure the OAuth consent screen and choose an
   appropriate internal/test audience. The product requests `drive.readonly`,
   `admin.directory.user.readonly`, `admin.directory.group.readonly` and
   `admin.directory.group.member.readonly`; an administrator may need to
   approve restricted/sensitive scopes and their organization policies.
2. Register this exact **Web application** redirect URI:
   `https://api.accessproof.in/api/v1/current/sources/google-oauth/callback`
   (replace the hostname only when deploying an independent staging API).
3. Configure `ACCESSPROOF_GOOGLE_OAUTH_CLIENT_ID` and
   `ACCESSPROOF_GOOGLE_OAUTH_CLIENT_SECRET` **only in the backend API environment**.
   Configure `API_PUBLIC_URL` to the same externally reachable HTTPS API base
   and `ACCESSPROOF_PUBLIC_APP_URL` to the HTTPS frontend base.
4. On Sources, create a `google-drive` source using its administrator-approved
   root folder ID and leave the manual access token empty. The browser goes to
   Google's consent page, then returns to the Sources page.
5. A one-time hashed state bound to the original source/organization/initiating
   administrator and short-lived encrypted PKCE verifier guards the redirect.
   The backend exchanges the authorization code directly with Google, requires
   the requested scopes and an offline refresh token, validates root-folder
   access, and encrypts credentials. It never sends tokens to the browser.
6. Wait for a successful **directory and ACL sync**, verify mapped employee
   identities, then run customer-side positive, negative, revocation, and
   application-route proof before allowing Protect. OAuth consent by itself
   does not certify permissions or customer deployment coverage.

If backend Google OAuth config is missing, the admin can still create a source
for a controlled pilot and supply manually approved credentials. Do not represent
an unconfigured OAuth draft as an active protected source.

## Google `changes.watch` subscription lifecycle (worker)

1. Set `ACCESSPROOF_GOOGLE_WATCH_CALLBACK_URL` in the **worker** environment
   to `https://api.accessproof.in/api/v1/provider-events/google-drive`.
   Configure actual DNS, TLS, routing, and inbound body/connection rate limits.
   Google must be able to reach it; never forward real notifications from an
   unrelated customer tenant into a shared development service.
2. Existing initial Google ACL sync must reach `connected` and hold a durable
   changes cursor before a channel is registered. Worker checks every 900
   seconds by default (`ACCESSPROOF_GOOGLE_WATCH_CHECK_SECONDS`).
3. Worker registers 3-day `changes.watch` subscriptions with a unique channel
   ID and random secret. It stores the returned resource binding, token
   encrypted at rest, and provider expiry; replacement begins six hours before
   expiry. Superseded channels are stopped only after the new channel commits.
4. Webhook checks channel, secret, provider resource ID, expiry, allowed resource
   state and message number, then records a bounded, durable hint. Worker uses
   authoritative `changes.list` to update ACL state. It does **not** treat the
   notification itself as a permission change.
5. Google may send an initial `sync` notification before the watch response is
   persisted. Ignore such unrecognized early events; **periodic ACL and
   directory reconciliation must stay enabled** to cover missed notifications,
   channel gaps, group changes and provider failures.
6. A shared-drive change with `driveId` but no `fileId` triggers bounded known
   source-resource revalidation. If the provider cannot authoritatively return
   required data, mark ACL sync degraded and fail closed; do not silently keep
   the previous ALLOW. Large (>20,000 known items) membership rescans are not
   certified in this reference implementation.

**Remaining:** In an authorized synthetic Workspace tenant, test shared-drive
membership removal, group nesting, inherited permissions, shortcuts, folder
moves, repeated notification delivery, channel renewal, provider 403/429/5xx,
OAuth token expiry, negative controls, Guard wake-up and measured source-change
to employee denial. The current worker still reconciles directory state
periodically; no Google Workspace group-membership push guarantee is claimed.
