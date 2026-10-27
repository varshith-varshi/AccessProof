# AccessProof — SharePoint security hardening audit (2026-10-27)

Repository: `/home/white-devil/Downloads/accessproof/f15`

## Outcome

**SHAREPOINT PROTECT: NOT CERTIFIED**

This audit repaired specific locally reproducible bugs and made source-denial evidence more trustworthy. It **does not** establish live Microsoft 365 effective-permission support or certify a protected enterprise RAG deployment. The Microsoft source remains Shadow-only until independently observed live-provider evidence and all release gates pass.

## Confirmed issues and fixes

1. **False SharePoint ALLOW through a redirected permission probe.** Reproduced with a caller-injected HTTP client configured to follow 302 redirects to an unrelated host, which returned a forged `Low=1` mask. Fixed `SharePointEffectiveAccessProbe.can_view_item` to force `follow_redirects=False`, regardless of client defaults. Added negative regression.
2. **Attesting content downloaded through an untrusted redirect.** Fixed the SharePoint preauthenticated download request to force `follow_redirects=False` for any injected HTTP client. Added an adversarial redirect test.
3. **Potential credential forwarding to a preauthenticated download URL.** Reject injected SharePoint download clients with client-level Authorization or authentication handlers. Added negative tests.
4. **Microsoft 401 falsely counted as evidence of permission revocation.** A revoked or expired delegated token cannot prove loss of document access. Changed Microsoft delegated source verification to raise `AuthenticationError` on 401, yielding an inconclusive security test instead of a false source denial.
5. **Graph DriveItem permission listings mistaken for employee-effective access.** Removed the fallback that inferred user access from administrator-visible permission entries, emails, or display names when no delegated employee token was present. It now raises `UnsupportedCapabilityError`. The adapter still exposes `permissions_snapshot` for diagnostics and inventory only.
6. **Delegated token substitution could falsify Alice's revocation evidence.** The delegated checker now calls authenticated Graph `/me?$select=id` and compares the returned immutable employee object ID to the tested principal before the content access request. Missing, malformed, mismatched or unauthorized identities are inconclusive, not denial. Added a Bob-for-Alice substitution regression.
7. **Malformed SharePoint port fields leaked unhandled `ValueError`.** Guarded `.port` parsing, mapping invalid URL ports to explicit domain-specific errors. Added both download and site URL regressions.
8. **Ambiguous Graph item IDs entering trusted ingestion.** Reject URI delimiter characters, percent escapes and non-ASCII item ID strings before boundary queries or attestation. Added negative tests for `../outside`, `item/other`, `item%2Fother`, and query injection.

## Validation

- **Full repository test suite (before last targeted patches):** completed with exit code 0. 1,041 pytest pass markers in the terminal output. Uses `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 -p pytest_asyncio.plugin` because the ROS Jazzy global pytest extension otherwise breaks collection. The full suite began before the latest source modifications, so do **not** claim it is a post-patch full-suite run.
- **Post-patch focused regression suite:** 137 tests across Microsoft security/SharePoint, connector contracts, relevant gateway security and Microsoft integrations: exit code 0.
- **Ruff (modified Python modules and relevant tests):** clean.
- **Python bytecode compile (Microsoft connector modules):** clean.
- **Microsoft Graph/SharePoint real-provider integration:** NOT RUN. No test tenant credentials or admin consent were used for this audit.
- **Gateway full customer cutover and production replay:** NOT RUN.
- No production database was reset, no credential was changed, no repository push was performed and no public deployment was made.

## Critical remaining limitations

- **Native SharePoint effective permissions** including site/library/folder inheritance, SharePoint-native groups, custom roles, unique scopes, guest and link semantics are not authoritatively resolved/certified. DriveItem permission inventory is insufficient.
- **Microsoft Entra employee sign-in and live SharePoint RAG demo** not proven end to end; no verified real tenant with Alice/Bob tests here.
- **SharePoint ingestion currently supports only UTF-8 `text/plain`** under approved roots, not DOCX/PDF or general library formats.
- **Source-bound tenant OIDC/token issuer verification** beyond Graph `/me` identity matching requires controlled tenant integration and credential/certification setup; a 403/404 result must be interpreted within a successful positive-control test of the same verified principal and token.
- **Permission revocation, source sync races, answer-cache enforcement, Layer 1/2 coverage, and bypass-path inventory** must be tested through the actual target RAG/Gateway in an authorized, separate Microsoft 365 test tenant before Protect activation.
- **Live supported-scope certification, signed external evidence, and administrator approvals** are absent, so status remains SHADOW / NOT CERTIFIED.

## Modified/added during this audit

- `connectors/microsoft365/adapter.py`
- `connectors/microsoft365/sharepoint_effective.py`
- `connectors/microsoft365/trusted_ingestion.py` (existing untracked working-tree module, amended)
- `tests/contract/test_connectors.py`
- `tests/unit/test_microsoft_delegated_access.py`
- `tests/security/test_sharepoint_no_redirects.py` (new)

All preexisting unrelated uncommitted changes were left intact. This report is not a claim of a third-party security audit.
