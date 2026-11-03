# Live evidence — 2026-11-03

Collected from the operator laptop using:
* AWS SSM against production `i-0c11427d4d9c1b438`;
* the Azure CLI, delegated and read-only, against tenant `6479e7ca-b256-4ebc-a408-871b9046547c`;
* the local customer test stacks.

No tokens, secrets, presigned URLs or document contents are stored here.
Each record carries the sha256 of its raw observation file.

| File | Mission step | Summary |
|---|---|---|
| `tenant-validation.json` | 5 | SRC-01 PASS_WITH_FINDINGS (T-02), SRC-02 PASS_WITH_FINDINGS (T-01), SRC-03 PASS |
| `guard-gateway-identity.json` | 6, 7, 8(2a) | GRD-01 BLOCKED (correct fail-closed), GW-01 BLOCKED (not paired), GW-02 PASS, ID-01/02 BLOCKED (no mappings), AccessProof stored ACL matches the expected matrix |

## New findings
* **T-01 (P2, tenant):** AccessProof holds `fullcontrol` on the lab site. A
  stale `fullcontrol` grant also exists for first-party app `c94a1c36`
  ("Microsoft Graph"). Confirm the minimum role that still allows
  role-assignment enumeration before lowering it. Needs owner approval.
* **T-02 (P3):** production gets app-only tokens with the client secret
  (`appidacr=1`) although two certificates are registered.

## Not done (needs the operator)
* Step 4: least-privilege DB switch (approval).
* Step 6: Gateway pairing file from the dashboard.
* Step 7: identity mappings and interactive Alice/Bob sign-in.
* Steps 8–9: direct SharePoint checks as each employee, live RAG answers,
  and revocation trials A–G (the trials need approval to modify the test site).
* Step 10: off-host certifier key, then the certificate.
* Steps 11–12: gates and reviewer approval.
