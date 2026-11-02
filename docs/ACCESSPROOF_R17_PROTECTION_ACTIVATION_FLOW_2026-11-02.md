# AccessProof r17: Guard → Gateway → Enable Protect → customer tests own RAG

The r16 website-based Alice/Bob worksheet was the wrong workflow. Removed it.
The customer can now go to AI Applications, click Check & Enable Protection,
review Guard connection/readiness and Gateway pairing/route status, and request
actual backend protection activation. The product displays Protected ONLY
when the Guard acknowledges activation and the real backend confirms it.
RAG questions and manual testing happen outside AccessProof, after activation.

Guard connection and security readiness are distinct signals; Gateway pairing
is not proof of real-time liveness or certified output enforcement. When
unready the Enable Protection button stays disabled. Once Guard is ready and
Gateway reported its installation, the request uses the existing guarded
backend endpoint; source and route certification still apply.

Host findings: SharePoint Gateway /health/live = 200;
SharePoint Gateway /health/ready = 503 GUARD_NOT_READY.
Guard policy cache contains the SharePoint application in Protect mode,
but its source_acl_healthy flag is FALSE. The Guard is correctly fail-closed.
This release cannot by itself resolve SharePoint provider, employee OIDC,
Layer1/2, provenance, buffered output, cache or customer route cutover gates.

Quality: ESLint, TypeScript and production Next build passed; complete desktop
and mobile Playwright suite 55 passed, 5 skipped. No backend or Guard policy
has been changed. Corrected UI does not claim that protection was activated.
