# Customer journeys executed locally

**Synthetic Google Drive customer:** Existing API/Guard/RAG over HTTP lifecycle and revocation integration tests were executed in the full Python suite. They exercise a local TestClient/Guard with synthetic OIDC identity and policies, not Google Workspace. Existing controlled-protect fixture passes before new V2 preflight end-to-end activation agent exists.

**New V2 one-button UI:** `web-v2/e2e/web-v2.spec.ts` click test on desktop and mobile: registered application → Enable Protection → POST preflight → Action required, required agent reason and Retry; manual audit ID form absent. The browser test verifies no client PASS fabrication. This is **not a successful activation**.

**Microsoft synthetic preview:** the `test_microsoft_shadow_release_gate.py` API test creates source/application and demonstrates missing certification blocks Protect; the signed certification unit test verifies scope/signature/expiry/tenant tampering. Real Microsoft Entra/SharePoint/OneDrive API requests were **NOT RUN**.

**Anti-fraud:** A basic Guard health response does not prove a private RAG route or zero bytes released. No synthetic 'Protection active' click-to-end-to-end journey has been claimed.
