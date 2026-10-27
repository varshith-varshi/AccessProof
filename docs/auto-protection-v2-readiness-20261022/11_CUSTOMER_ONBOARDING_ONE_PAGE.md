# AccessProof customer onboarding — current pilot instructions

1. Register the company and configure a **single** approved permission source. Use a non-sensitive test-only folder, site/library or OneDrive root; obtain consent through an authorized administrator. Never paste production secrets in chat.
2. Install and enroll a Guard beside the existing **server-side RAG** backend, restrict its listener to a private network, and ensure a healthy machine heartbeat and current ACL/directory policy.
3. Register the RAG application, select the appropriate Python/TypeScript adapter, its stable application ID, Guard and one source. Ensure employee OIDC tokens, source identity mapping and stable source resource IDs are provided from the trusted backend.
4. Integrate both before-generation document filtering and complete post-generation provenance buffering into **every** RAG generation/retrieval/tool route. Do not return raw SSE/HTTP bytes before Layer2 approval.
5. Click **Enable Protection**. The current build runs safe preflight checks and shows **Action required** for missing real RAG test agent. There is no manual ID form; do not interpret the button as protection activation.
6. For a controlled future pilot, connect the approved test agent and provider-specific certification once they have been implemented/tested, then re-run checks; activation must remain pending until the Guard acknowledges policy application. Monitor health and revoke the integration if tests fail.

The current build is **not yet customer Protect-ready**. Contact engineering for controlled validation; never rely on the preview alone for confidential data access policy.
