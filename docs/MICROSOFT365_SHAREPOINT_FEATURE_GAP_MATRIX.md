# Microsoft 365 / SharePoint feature-gap matrix

Date: 2026-10-27  
Scope: current `f15` working tree, before this implementation pass. This is a
code-backed planning matrix, not a production certification.

| Product area | Current evidence | Status before this pass | Safe implementation direction |
|---|---|---|---|
| Google Drive source onboarding | Server-side PKCE, consent callback, encrypted source tokens and durable Google bootstrap jobs exist in `app.py`; active Sources UI supports Google only. | Implemented | Preserve unchanged. |
| Microsoft source profiles | `sharepoint` and `onedrive` are accepted by source validation; Graph site/list and OneDrive owner profile checks are in `adapter.py`. | Partially implemented | Surface the existing profiles in the UI and keep profile identifiers immutable on reauthorization. |
| Microsoft admin consent | Tenant-bound, one-time hashed state and a fixed Microsoft authority/token endpoint exist in `microsoft_consent.py` and `app.py`. Credentials are encrypted at rest. | Partially implemented | Queue fresh ACL and directory work only after connection validation; never expose tokens or secrets to the browser. |
| Token renewal | Worker reacquires Microsoft client-credential Graph tokens and restricts token endpoints. | Partially implemented | Add focused regression coverage for renewal state/error behavior; retain server-managed credentials where configured. |
| Entra directory sync | Stable Entra user/group object IDs, active/disabled state, Graph paging and transitive members are implemented. | Implemented locally | Keep incomplete directory pages fail-closed; report health in UI. |
| Graph document inventory/delta | Approved-root traversal, continuation URL validation, delta processing and moved-out/delete handling exist in Microsoft adapter and ACL sync. | Implemented locally | Present operational controls/history; no claim that delta proves effective ACLs. |
| DriveItem permission ingestion | Direct, stable user/group permissions with role and expiry filtering are ingested; link/unknown principals fail closed. | Implemented with limitations | Keep Shadow-only where Graph records cannot prove native SharePoint effective rights. |
| SharePoint native effective access | `SharePointEffectiveAccessProbe` is diagnostic-only and requires a separately verified SharePoint identity and audience token. Site groups, inheritance, unique scopes, guests and links are not authoritative. | Blocked for Protect | Do not publish ALLOW from the probe or relax certification. Require real-tenant evidence and a provider validator. |
| OneDrive effective access | Owner/business drive/root profile validation exists; full sharing/ownership effective-access proof does not. | Blocked for Protect | Keep distinct OneDrive profile and Shadow-only certification gate. |
| Gateway/Guard source isolation | Single-source application binding and Microsoft certificate checks are present; Microsoft protect readiness fails absent signed provider-live evidence. | Implemented locally / Shadow only | Preserve source/tenant isolation and no mixed-source behavior. |
| Sources UI | `web-v2/app/sources/page.tsx` offers Google Workspace only. | Missing | Add provider selection plus Google/Microsoft-specific configuration, consent, validation and sync controls using existing API boundaries. |
| Applications UI | Permission-source selector filters to `google-drive` only. | Missing | Include SharePoint/OneDrive with truthful Shadow/Protect eligibility labeling. |
| Microsoft employee OIDC/RAG demo | No controlled Microsoft employee-login SharePoint demo was located. | Not implemented | Requires a configured tenant, app registration, and a separately scoped implementation; must not be simulated as production evidence. |
| Webhooks/subscriptions | No Microsoft Graph webhook subscription implementation located. | Not implemented | Use periodic sync/reconciliation only until a securely bound subscription workflow is built and live-tested. |
| Live tenant validation | Existing runbook explicitly says NOT RUN; no tenant credentials are available in this task. | Blocked externally | Maintain NO-GO for Protect and document a reproducible authorized sandbox validation plan. |

## Guardrails for this pass

- Do not overwrite existing uncommitted changes.
- Do not replace Google OAuth or authorization behavior.
- No browser token, refresh-token, client-secret, or raw Graph credential handling.
- A successful Microsoft login, Graph request, or mocked test cannot mark a Microsoft source Protected.
- Unsupported/incomplete Microsoft authorization semantics remain fail-closed and Shadow-only.
