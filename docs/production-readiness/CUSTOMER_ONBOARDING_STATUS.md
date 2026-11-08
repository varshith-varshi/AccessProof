# Customer onboarding status

Last updated 2026-11-08T08:35Z. Nothing in this journey was re-executed this session; doing so creates production resources and needs customer identities. Status comes from the latest dated evidence.

| Step | Status | Evidence / gap |
|---|---|---|
| Organization registration | VERIFIED_LIVE (synthetic pilot org `0fb98b25…`, 2026-11-04/05) | `docs/CUSTOMER_ONBOARDING_CURRENT_2026-11-05.md` |
| Email verification | VERIFIED_LIVE (pilot) | same |
| Microsoft tenant admin consent (new tenant) | **NOT_VERIFIED**: no successful consent by a real customer tenant | memory/handoff "not yet proven" |
| Selected-site authorization | VERIFIED_LIVE for the single owner tenant only | — |
| SharePoint connection + permission sync | VERIFIED_LIVE (pilot + reference sources) | source certs valid to 2026-12-04 |
| Guard installation | VERIFIED_LIVE on Linux Docker; Docker Desktop setup page NOT_VERIFIED | — |
| Gateway pairing | VERIFIED_LIVE (pilot); R44 challenge CLI fix live but not exercised on a fresh install | `docs/CUSTOMER_ONBOARDING_SMOKE_R44.md` |
| RAG discovery and selection | TESTED_LOCAL / VERIFIED_LIVE (pilot) | — |
| Signed route verification | CERTIFIED (pilot-langchain); operator-assisted with live employee identities by design | CERTIFICATION_STATUS.md |
| Source certification | CERTIFIED (pilot + reference) | — |
| Owner approval (`APPROVE PROTECT`) | VERIFIED_LIVE for 2 apps (2026-11-05, explicit owner approval); a new-app human approval is not proven | `docs/evidence/protect-activation-2026-11-05/` |
| Protect activation | DEPLOYED for sharepoint-rag-staging and pilot-hr-rag; `PROTECTED_VERIFIED` is not visible to the certifier identity, so the **Owner must confirm** | — |
| Employee questions + revocation | VERIFIED_LIVE through route certification | — |

**Verdict:** the pilot journey works with operator assistance. A fresh real customer is NOT_VERIFIED for Microsoft consent and new-app owner approval, and route certification is not yet self-service.
