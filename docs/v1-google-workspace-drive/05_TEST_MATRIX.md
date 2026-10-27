# Test matrix

| Layer | Evidence | Result |
|---|---|---|
| Configuration | `tests/unit/test_config.py` | Passed locally |
| Source lifecycle and tenant isolation | `tests/integration/test_source_lifecycle.py` | Passed locally |
| Google OAuth source flow | `tests/integration/test_google_source_oauth.py` | Passed locally |
| Protected source health | `tests/security/test_google_source_protect_health.py` | Passed locally |
| Google Drive security semantics | `tests/unit/test_google_drive_v1_security.py` | Run separately in the release check |
| API syntax | `python3 -m compileall` | Passed locally |
| web-v2 production build | `npm run build` | Passed locally |
| Real Google Workspace | Checklist 09 | Required before customer production |
