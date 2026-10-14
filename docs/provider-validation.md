# Provider validation status

Status date: 2026-10-02

A provider is never labeled validated merely because a simulator or mocked HTTP transport passed.

The capability rows below describe connector primitives. The current propagation
engine exercises loss-of-access transitions; grant and member-add primitives are
used to establish controls but grant/add propagation scenarios are not implemented.

| Provider / capability | Implemented | Contract tested | Real sandbox/tenant tested | Production API tested | Known limitation |
|---|---:|---:|---:|---:|---|
| Mock source + mock RAG lifecycle | YES | YES | N/A | N/A | Simulator only; never evidence for a real provider |
| SharePoint/OneDrive connection + synthetic file | YES | YES | NO | NO | No Microsoft credentials available |
| SharePoint direct user grant/revoke | YES | YES | NO | NO | Real effective-access behavior needs tenant validation |
| SharePoint pre-provisioned group add/remove | YES | YES | NO | NO | Requires explicitly configured dedicated test group |
| SharePoint share-link create/revoke | EXPERIMENTAL | YES | NO | NO | Explicit opt-in; link/identity semantics vary |
| SharePoint move/recalculation | EXPERIMENTAL | YES | NO | NO | Requires explicit move target |
| SharePoint inherited/parent ACL mutation on authorized test root | YES opt-in | YES | NO | NO | Real inheritance behavior requires dedicated Microsoft tenant validation |
| Google Drive direct user grant/revoke | YES | YES | NO | NO | No Workspace credentials available |
| Google Drive parent ACL + move | YES opt-in | YES | NO | NO | Group/delegation/Shared Drive semantics require tenant validation |
| Confluence page lifecycle safe subset | YES | YES | NO | NO | Full effective access across space+restriction composition not claimed |
| Slack private-channel membership | YES | YES | NO | NO | Admin/plan/token differences require real workspace validation |
| Salesforce record lifecycle/effective read safe subset | YES | YES | NO | NO | Direct share mutation depends on customer-selected share model |

## How to perform real validation later

Use dedicated non-production provider resources and opt-in provider tests. Supply least-privileged credentials/scopes, configure the explicit AccessProof test boundary and execute provider-specific direct/group/link/inheritance scenarios. Record the test date, API version/scopes, provider request IDs and observed limitations here.

Real-provider tests remain outside ordinary CI and must never use arbitrary customer production resources.
