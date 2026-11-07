# AccessProof customer claims register — 7 November 2026

| Claim | Supporting implementation | Evidence | Approved wording | Status |
|---|---|---|---|---|
| Authorization before generation | Gateway Layer 1 and Guard policy evaluation | Automated security regressions and tested Alice/Bob validation environment | “Layer 1 checks retrieved resources against synchronized, source-bound authorization state before the model receives context.” | Approved for supported routes |
| Provenance verification before release | Buffered Gateway Layer 2 and signed retrieval manifest checks | Gateway regression suite and tested validation environment | “Layer 2 verifies the complete source set and authorization revision before a protected answer is released.” | Approved for certified routes |
| SharePoint support | Microsoft 365 connector, ACL/directory sync, certification workflow | Tested documents and validation environment; not universal provider certification | “Microsoft SharePoint and Entra guided pilot.” | Approved with pilot qualifier |
| Revocation enforcement | Permission-event/sync pipeline, policy revision, Guard enforcement | Implemented and tested in controlled cases; provider/sync latency remains variable | “Once a permission change is synchronized into current Guard policy, the protected route enforces it.” | Approved with timing qualifier |
| Fail closed | Gateway and Guard denial paths for missing/stale required evidence | Automated negative-path tests | “If AccessProof cannot verify required authorization state, the protected route withholds the answer.” | Approved for protected routes |
| Customer-side enforcement | Customer-hosted Guard and Gateway deployment | Installer and deployment implementation | “Guard and Gateway run in the customer environment for the supported deployment.” | Approved with deployment qualifier |
| Control plane does not require document content | Control-plane models and Guard/Gateway architecture use permission metadata and evidence | Code and data-flow inspection | “The control plane receives permission metadata, health state and decision evidence; pilot data flow is reviewed before installation.” | Approved |
| Existing RAG compatibility | Supported Gateway HTTP contract and reviewed installer workflow | Contract and integration tests | “AccessProof integrates with a reviewed customer RAG route that implements the supported Gateway contract.” | Approved; universal compatibility rejected |
| Google Drive generally available | Google connector and local validation exist | No current first-customer GA evidence | None | Rejected |
| Free plan | Registration exists | No defined entitlement or commercial free plan | “Create workspace” | Rejected as pricing claim |
| Unlimited applications / SCIM / enterprise SLA | No approved public entitlement or verified launch evidence | None | None | Rejected |
| Independent security certification | No completed third-party certification identified | Security page explicitly discloses this | “AccessProof has not yet completed a third-party security audit such as SOC 2.” | Disclosure approved |
