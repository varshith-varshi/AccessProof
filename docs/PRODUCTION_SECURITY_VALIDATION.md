# AccessProof multi-source security validation (2026-10-27)

## Reproducible local commands
From `/home/white-devil/Downloads/accessproof/f15`:

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -q \
  tests/security/test_multisource_guard_v2.py \
  tests/integration/test_gateway_multisource_real_guard.py \
  tests/unit/test_gateway_multisource_snapshots.py
cd web-v2 && npm run typecheck
```

The ROS Jazzy pytest auto-loaded plugin declares an unknown pytest hook; disabling plugin auto-load removes that collection error. For async tests, selectively enable the installed `pytest_asyncio` plugin (`-p pytest_asyncio`); disabling *all* plugins causes unrelated async tests to fail with "async def functions are not natively supported".

### Verified local scenarios
- Independent Google/SharePoint source bindings under one application, exact source/identity mapping.
- Same resource ID in two sources without identity/ACL collision.
- Signed source snapshots passed to Gateway; only allowed chunks reached the synthetic model.
- Bob Google allow + SharePoint deny; denied SharePoint content excluded from model context.
- Atomic Layer-2 source ACL recheck blocks a revocation during generation.
- Invalid tenant, cross-user decision replay, wrong request ID, mapping changes, authorization revision changes, unapproved source and source-health outages fail closed.
- Legacy V1 endpoints refuse multi-source application requests.
- Gateway full response remains buffered until V2 release decision.

## External acceptance criteria not executed
Microsoft Entra sign-in, real Microsoft Graph inherited/direct/group/share-link permission cases, external Google Workspace identity, mixed Microsoft+Google employee principal mapping, Redis/Postgres cached answer after real revoke, production network bypass scan, performance thresholds and customer cutover evidence are NOT_TESTED or BLOCKED.

## Evidence interpretation
Mock model transport and synthetic provider data remain local reference tests. One cannot infer security guarantees across arbitrary RAG architectures or announce production certification from green pytest alone.
