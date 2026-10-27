# AccessProof gateway / Guard adversarial verification — 26 October 2026

## Scope
Worktree: `/home/white-devil/Downloads/accessproof/f15`.
Baseline commit: `b3e35a6` plus numerous pre-existing uncommitted gateway-only migration edits.
**Existing changes were preserved; no reset, rebase, Git push, deployment, customer secrets or live customer endpoints were used.**
All exploit reproductions used synthetic Guard responses, employee identities and Ed25519 test keys.

## Confirmed vulnerability: incomplete Guard authorization-revision handshake

**Pre-fix reproduction:** when a Guard returned `authorization_revision=1` / its hash
at Layer 1 but responded with `decision=allow` at Layer 2 **without any revision
evidence**, the signed-cache path returned an authorized cached answer anyway.
The legacy metadata-only generation route also returned its buffered output.
A `decision=allow` flag is insufficient evidence that the authorization state
at final release equals the Layer 1 snapshot. This could turn Guard protocol
degradation or a malformed authorization response into a bypass of revision
consistency, though a correct current production Guard normally supplies
the fields.

**Fix** in `packages/rag_core/protection.py`:
- Reject revision presence mismatch between Layer 1 and Layer 2 in Protect mode.
- Reject revision value/hash differences as already required.
- Apply presence consistency to signed cached-answer authorization as well.
- Keep failures fail-closed, with `response=None` and stable reason
  `AUTHORIZATION_REVISION_MISSING`; never release buffered model/cache content.

**Regression coverage** in `tests/security/test_authorization_revision_binding.py`:
- Source-attested generation: signed input plus missing Layer 2 revision -> block.
- Signed cached answer: valid signed manifest plus missing Layer 2 revision -> block.
- Layer 1 unversioned / Layer 2 versioned -> block.
- Update the synthetic `RevisionGuard` success fixture to return the same revision
  from both layers by default, matching the actual production Guard contract.

## Local verification performed

| Check | Result |
|---|---|
| Focused gateway/Guard/Drive authorization baseline | 71 passed (before patch) |
| Broad security suite baseline | 374 passed (started before patch) |
| Post-fix focused authorization, gateway and guard tests | 32 passed |
| Post-fix unit directory | 462 passed |
| Ruff targeted files | PASS |
| mypy `packages/rag_core` | PASS (11 modules) |
| Python source compilation | PASS |
| Full post-fix security suite | 377 cases reached 100%, no failure markers; isolated temp SQLite |
| Full post-fix integration suite | 130 cases reached 100%, no failure markers; isolated temp SQLite |
| Combined distinct unit + security + integration cases | 969 collected/executed across the three separate suites |

Post-fix security and integration suite logs:
`/tmp/ap-redteam-security-suite.log` and
`/tmp/ap-redteam-integration-suite.log`. Those runs used an additional `-q`
(which suppresses their numeric PASS summary), so their counts were independently
confirmed with `pytest --collect-only`: **507** security + integration cases.
Both logs reached 100% and ended with warnings only; their wrapper processes
finished. The exact wrapper exit markers were not captured into the files,
so the remaining absence of a recorded exit status is called out rather than
fabricating one.

The ROS `launch_testing_ros_pytest_entrypoint` auto-plugin on this Ubuntu
installation interferes with ordinary pytest discovery. Use:
```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest \
  -p pytest_asyncio.plugin -p anyio.pytest_plugin tests/security
```
Set `ACCESSPROOF_CURRENT_DATABASE_URL` to a disposable SQLite URL for
repository-wide database-mutating tests. The existing developer SQLite file
timestamp was checked and had not changed during these tests.

## Remaining release gates / limits
- Not a runtime penetration test of a customer's real RAG + model path.
- A customer can bypass a Gateway entirely if their model access, tool flows,
  alternate endpoints or network egress are not cut over and isolated.
- No real Google Workspace admin OAuth / Drive permission change validation,
  independent nested/shared-drive group effectiveness test, measured revoke-to-deny
  latency, or OAuth expiry under live quota/throttle has been done in this session.
- No production Postgres migration/rollback, high availability, restore drill,
  full load/soak or independent external review was completed.
- Therefore **NO-GO for unrestricted production Protect with sensitive customer data**;
  local synthetic Shadow/staging validation is a separate and narrower claim.

## Operator next checks
Run post-fix full security and integration suites on isolated test storage;
prove revocation timing and strict consent/permission behavior against a test
Google Workspace tenant, then test customer RAG egress isolation with an
independently monitored model endpoint and exercise safe rollback.
