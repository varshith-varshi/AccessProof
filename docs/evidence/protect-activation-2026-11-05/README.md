# Protect activation (2026-11-05)

* The owner gave explicit approval for **both** applications, `sharepoint-rag-staging` (reference org) and `pilot-hr-rag` (pilot org), in reply to a direct question.
* It was submitted through the D-28 owner-only endpoint: an OWNER session, `APPROVE PROTECT <app>` confirmation text, and a reviewer name. Production re-checked the valid route certificate and every activation check.
* **Gates A–J PASS** for both applications, and each Guard acknowledged `protect`. The verdict `TECHNICAL_GATES_PASSED_PENDING_REVIEWER_APPROVAL` is the maximum the code emits; the human approval is the owner's decision above.
* Live enforcement after activation: E2E-01..04 PASS on both routes. Unauthorized documents never reached the model.
