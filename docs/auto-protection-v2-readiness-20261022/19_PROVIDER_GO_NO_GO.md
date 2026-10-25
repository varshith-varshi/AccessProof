# Provider-by-provider release verdict

| Provider/source profile | Locally exercised | Real effective ACL coverage | Real RAG challenge | Pilot / Protect verdict |
|---|---|---|---|---|
| Google Drive | Existing mock adapter/worker/Guard/SDK integration and revocation tests | Real Workspace tenant/group/share-link authorization NOT RUN | Actual private customer route/evidence agent absent | **Synthetic DEMO only; NO-GO customer Protect** |
| SharePoint document libraries | Synthetic Graph permission/delta/groups + read-only REST mask probe; signed-scope verification contract | Native site/library groups, inheritance, guests, link possession not integrated/proved | Absent | **Shadow/diagnostic preview; NO-GO Protect** |
| OneDrive personal drive | Synthetic shared Graph adapter and source-boundary tests | Owner/inheritance/remoteItem/guest/link semantics not proved | Absent | **Shadow/diagnostic preview; NO-GO Protect** |

The product-wide API's source-specific certificate gate does NOT grant a Microsoft exception based on provider name. No valid certificate is minted or externally validated. Admin cannot flip a UI switch to bypass missing evidence. Guard still denies when source ACL/directory freshness is insufficient.

**Production, staging deployment, controlled actual tenant pilot: NOT RUN.** Owner must explicitly authorize a disposable test tenant before real-provider validation and a production change separately.
