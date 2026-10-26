# Fix log

SIM-001 | P1 | Revoked user saw a misleading adapter error | RAG release | `tests/integration/test_customer_lifecycle_over_http.py` | valid Guard Protect `block` produced `GUARD_MODE_MISMATCH` | SDK accepted only `allow` for Protect Layer 1 | `packages/rag_sdk/protection.py` | `tests/unit/test_rag_sdk.py` | PASS: denial returns `NO_AUTHORIZED_RESOURCES` and model is not called.
