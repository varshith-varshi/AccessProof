# AccessProof R44 — human-only steps remaining after technical validation

**Current released version:** `web-r44-challenge-0788ca3a1bc0` (verified); published Gateway ZIP SHA-256 `bab5f15f62c5186235677e489d7020654e72600d1f999a83554fa160a5dd91d9`.

## Owner's dashboard checks (not checked via the certifier's read-only identity)

1. Sign in as the organization **Owner** to `https://app.accessproof.in`.
2. Open **AI applications**. For `pilot-hr-rag` verify that the displayed, server-authoritative status is `PROTECTED_VERIFIED`; for the other authorized organization, check `sharepoint-rag-staging` separately. Record a timestamped screenshot or sanitized status (no tokens, cookies, private documents). A valid route certificate alone does not prove Protect is active.
3. If either status is not verified, inspect the failed gates and stop; do not force protection on.

## First real SharePoint customer pilot (distinct customer authorization required)

1. **Customer Microsoft admin**: consent to the registered AccessProof Entra app and approve only the named SharePoint site's `Sites.Selected` grant. The documented effective-permission path may require a site-scoped `fullcontrol` grant; review this explicitly. Consent alone does not grant site access. The vendor must not silently elevate permissions.
2. **Customer IT/RAG owner**: use an authorized private Linux Docker RAG host, enroll the official Guard 0.1.6, download the current authenticated R44 Gateway ZIP, compare its full SHA-256 with the value above, and pair it with the provided one-time pairing material. Confirm dashboard `Gateway Connected`. Preserve private network boundaries.
3. **Operator + consenting employees**: perform the independent route challenge and route certification with actual Entra sign-ins; verify allowed and denied users, Layer 1/2, provenance, buffering, cache replay, revocation/in-flight denial, fail-closed behavior, and audit evidence. The CLI accepts the server-issued challenge in R44, but its local synthetic probe is not a Protect certificate. Do not create forged certification evidence.
4. **Actual organization Owner**: when all backend gates are green, personally enter `APPROVE PROTECT <application_id>` in **AI applications → Check & Enable Protection**, then request **Enable Protection**. Wait for verified Guard acknowledgement. An assistant/admin/API key cannot do this on behalf of the Owner.
5. Recheck `PROTECTED_VERIFIED`, allowed user access, denied user refusal and both layers' audit evidence before declaring the real customer pilot complete.

## Current certificate renewal and operational ownership

- Route certificates due ~Nov 11, 2026. Current local route scheduler and tunnel are active; full re-certification runs when <=2 days remain. Keep laptop **powered on** through the Nov 9 renewal window with authorized employee sessions active. The laptop being off is still a real risk.
- Source certificates verified until Dec 4, 2026. Local source renewal starts at <=10 days, approximately Nov 24.
- New installed local monitors: `accessproof-renewal-watchdog.timer` (every 2h, file/attestation/prerequisites) and `accessproof-source-expiry-monitor.timer` (daily, authorized production read-only source expiry). Inspect `systemctl --user list-timers --all` and `journalctl --user -u <unit>` for warnings/failures. These are **not off-device alarms**.
- An always-on signer migration is **not complete** and must not be represented as complete: requires a separately approved certifier host, signing-key custody and trust review, customer-approved employee auth/session handling and restricted private RAG access. Never copy the private signer or Alice/Bob tokens to an existing public server.
- Deployer identity certificate reportedly expires Feb 3, 2027; verify authoritative certificate metadata before renewal.

**Evidence boundary:** Previous R43 synthetic pairing passed. R44 ZIP checksum/runtime/integration regressions passed. A real fresh customer certificate/Owner activation after R44 has not been demonstrated and cannot be claimed without the above authorized people.
