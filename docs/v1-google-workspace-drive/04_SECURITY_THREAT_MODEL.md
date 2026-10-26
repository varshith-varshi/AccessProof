# Security threat model

* **Browser credential exfiltration:** blocked by rejecting browser credential payloads in production; secrets are never returned by source APIs.
* **Unsupported-provider bypass:** blocked at the API, not only hidden in the UI.
* **Cross-tenant policy disclosure:** source, Guard and policy paths are organization-scoped and protected by the existing actor/tenant checks.
* **Stale authorization:** Guard decisions carry policy revisions and receive policy notifications. Customer policy selects the stale-cache deny behavior; it must be tested in the target tenant.
* **Forged Guard updates:** Guard endpoints require enrolled bearer credentials; credentials are hashed server-side.
* **Untrusted RAG provenance:** a RAG integration must send stable identity and canonical document/resource identifiers to the Guard. Missing or unverifiable provenance must fail closed when enforcement is enabled.

Residual risk: Google’s effective-access semantics and customer RAG identity/provenance mappings cannot be proved without a real tenant and RAG deployment.
