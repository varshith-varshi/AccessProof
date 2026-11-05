# AccessProof customer onboarding — current verified workflow

**Revision:** 2026-11-05. This document supersedes older r12/r13 onboarding notes and the corrections listed below. It is intended for pilot review, not proof that a fresh independent customer tenant has been certified. UI patches in `claude/universal-rag` must be deployed before instructing customers to use the new Owner approval panel.

## Before the call

Have an AccessProof organization Owner, a Microsoft 365 admin authorized to grant access to a named SharePoint site, a RAG/IT owner with access to the private Docker host, and two consenting test employees with distinct SharePoint access. The customer decides which site, document library and folder boundary is in scope. No public RAG URL, Microsoft password, or AWS access key is requested by AccessProof.

### Phase 1 — Workspace

The Owner registers at `https://app.accessproof.in/register`, verifies their work email, and signs in. The Owner role—not just Admin—is required to approve production Protect. The Owner should enable MFA before a production pilot.

### Phase 2 — SharePoint

In **Permission sources → Connect source**, choose Microsoft 365 + SharePoint. Enter the verified Entra tenant ID, SharePoint site ID, document library ID, Graph drive ID and approved folder/root ID. AccessProof has no automatic site picker. Microsoft consent is tenant-specific and initiated from the customer's session. The customer should approve only the described Graph application roles.

Microsoft onboarding has two independent authorization steps:

1. **Admin consent** establishes a service principal but gives no site access by itself when using `Sites.Selected`.
2. **Selected-site grant** is created by a separately privileged Microsoft/SharePoint administrator, for the named site only. If the callback reports `MICROSOFT_SITE_ACCESS_GRANT_REQUIRED`, consent has been recorded and the source intentionally stays unconfigured. The admin adds the approved site grant; the customer then clicks **Validate** on the same source. Re-consent is not needed merely to add a site grant. A successful Validate triggers fresh directory and ACL synchronization. Never force Protect on stale source state.

**Elevated-permission warning:** Production-equivalent effective-permission certification in our November 2026 lab required a site-scoped `fullcontrol` grant to the AccessProof enterprise service principal. This is powerful access, although confined to an explicitly selected site. It is not tenant-wide `Sites.FullControl.All`. Neither the frontend nor the backend automatically applies it. The tenant security owner must review the intended operations and expressly authorize the role; do not pretend a `read` grant was certified for the complete path. A narrower-read-only certification method is not yet demonstrated and must be proven independently before claiming it.

### Phase 3 — Guard

Enroll a Guard in the dashboard and download the **official Guard installer**. On the customer-owned host, run the installer, provide its one-time enrollment token and the trusted Microsoft Entra OIDC issuer/audience for the RAG. Confirm live Guard connectivity and a fresh policy; heartbeat alone is not certification. Keep the Guard and RAG inside private networks.

### Phase 4 — AI application

Register exactly one application ID and bind its approved source and enrolled Guard. Select the supported Gateway contract. Do not claim universal conversion of arbitrary RAG code or protection of other unregistered chatbots.

### Phase 5 — Customer-side Gateway and RAG

**Docker Compose path:** On the private Linux host, obtain the reviewed Gateway connector ZIP through the authenticated dashboard download, obtain a one-time pairing file, then run `python3 ~/Downloads/accessproof-gateway-connector.zip`. The installer discovers the local eligible chatbot. Select exactly one in **Get Started**. Preserve private RAG routing; install and verify the signed Gateway only for the selected application. Verify that the ZIP actually downloads and passes internal checksum review for this release before sharing the instruction.

**Remote Python/LangChain/LlamaIndex path:** The `accessproof-rag` client exists at `integrations/rag-clients/python`, but **is not on PyPI**. We now include the source-built v0.1.0 wheel in this branch at `web-v2/public/downloads/accessproof_rag-0.1.0-py3-none-any.whl` so, **after this branch is deployed**, the customer can sign into AccessProof and download it from `https://app.accessproof.in/downloads/accessproof_rag-0.1.0-py3-none-any.whl`. SHA-256: `ce72587503532202add008990e59fbf2a9c1c23e3740e1a4be3fac4b37235072`. Verify that checksum before `python3 -m pip install ./accessproof_rag-0.1.0-py3-none-any.whl`; install framework extras separately when needed. A technical operator can alternatively build a wheel from the reviewed source checkout using `python3 -m pip wheel --no-deps --no-build-isolation -w dist ./integrations/rag-clients/python`. This path still needs Gateway TLS configuration, per-request signed identity forwarding, trusted-ingestion provenance, and a customer-side route certification plan. Do not embed customer secrets in code or the PDF.

### Phase 6 — Independent certification

The customer-authorized technical operator verifies the **real RAG route** using the signed route manifest, Gateway/Guard challenges, valid source certification, live employee allow/deny, content-forgery refusal, and in-flight revocation / cache controls. Temporary access to the customer's RAG host is agreed explicitly and restricted to the validation window. There is no safe unattended cloud-side scan of arbitrary customer hosts, and successful installation alone cannot certify Protect.

### Phase 7 — Human approval and activation

After every other backend gate is green and the live route is certified, the signed-in organization **Owner** opens **AI Applications → Check & Enable Protection** and enters the exact phrase `APPROVE PROTECT <application_id>` in the new **Owner approval required** panel. The backend verifies the interactive OWNER session, current route certificate and all other gates, then audits the approval. **Approval alone does not activate Protect**. The Owner requests **Enable Protection**, and the product waits for Guard acknowledgment. An admin or API key cannot approve on the Owner's behalf. If route certification changes after approval, reapproval is required.

### Phase 8 — Live tenant tests

Confirm `PROTECTED_VERIFIED` in the server-authoritative dashboard. In the customer's chatbot, sign in as allowed and denied Microsoft employees and verify accessible information is available while denied content never reaches the model or answer. Exercise a controlled revocation and cache reuse if permitted. Share only sanitized hashes and test outcomes, never access tokens, private documents or employee passwords.

## Release and evidence limitations

- UI adjustments and the Owner approval panel in `claude/universal-rag` are not production facts until built, deployed and reviewed on the actual server.
- Installer download authorization is hardened in the branch: a backend-validated session is required for `/downloads`; the old production cookie-presence gate needs a reviewed deployment before this is a production claim.
- The guide's screenshots use **synthetic Example Corp data**, not customer production credentials.
- The current site-grant requirement, client packaging, Entra production client ID and support inbox must be checked as part of each customer change review.
- The consent callback and selected-site-retry path are already covered by backend tests; do not remove the fail-closed status in order to make first-time consent appear successful.
- Real customer onboarding cannot be certified by mocked Playwright tests. Customer approval, Microsoft site grant and live route cutover remain external dependencies.

## Contact details

The website currently displays `admin@accessproof.in`. Confirm the mailbox is receiving external customer requests before distributing this guide. Verify the deployed Entra application ID against the actual production registration; do not copy a synthetic ID from a screenshot.

## Release operator note

A web-only deployment must preserve the currently published customer Gateway ZIP with the reviewed SHA-256; the release script now copies it from the active web image after integrity verification and fails closed if missing or modified. The new wheel is committed under the website `public/downloads` path, but **neither download endpoint is authorized until the new web image is deployed and confirmed live**. The Guard setup copy/Entra subject-claim improvement also requires a reviewed separate customer-side Guard image or installer update. Use a dedicated least-privilege release identity, not the `accessproof-certifier` role or an AWS root session.

## Fresh-install validation, 2026-11-05

The Guard 0.1.6 bundle and Gateway installer `32942af5…` completed a clean synthetic install against production: Guard enrolled through its setup page, the installer imported its verified runtime, pairing succeeded, and the Gateway reported `CONNECTED` with live heartbeats.

A new application stays in Shadow, and its Gateway reports `GUARD_NOT_READY`, until certification and Owner approval finish. That is correct fail-closed behaviour. Route certification remains an operator-assisted step using live employee identities.

Linux Docker hosts are validated. Docker Desktop on macOS and Windows is not.
