# Google operator OAuth setup

1. Create a dedicated Google Cloud OAuth client for the AccessProof deployment.
2. Register the exact HTTPS callback URL shown by the AccessProof deployment configuration.
3. Grant only the Google Workspace/Drive scopes documented in the deployment environment; review the consent screen with the customer administrator.
4. Store the OAuth client secret only in the server/worker deployment secret store. Both API and background worker need `ACCESSPROOF_GOOGLE_OAUTH_CLIENT_ID` and `ACCESSPROOF_GOOGLE_OAUTH_CLIENT_SECRET`. Do not store NeuralMatrix's OAuth client secret in individual source records; Google source records contain encrypted provider access/refresh tokens, a public client ID, and `oauth_credential_mode=server_managed`. Refresh fails closed if the operator settings are missing or the client ID changes. Existing records are scrubbed on their next successful credential-refresh path.
5. In web-v2, add a Google Drive permission source and choose **Connect Google Workspace**. Complete consent as the approved operator.
6. Validate the source, inspect the resulting capability/health state, then run the staging checklist.

Do not paste an operator access token, refresh token, client secret, or end-user token into the browser UI.
