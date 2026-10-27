# Implementation log

The API now has `ACCESSPROOF_V1_PROVIDER`, defaulting to `google-workspace-drive`. In production it accepts creation of only `google-drive` sources. It rejects credential dictionaries posted from the browser with `V1_BROWSER_CREDENTIALS_NOT_ALLOWED`.

`web-v2/app/sources/page.tsx` now presents Google Drive as the V1 connection path and sends an empty credential payload before starting server-owned OAuth. Legacy source records are retained for audit/history but cannot be newly created through V1 onboarding.

Regression coverage was added in `tests/unit/test_config.py` and `tests/integration/test_source_lifecycle.py`.
