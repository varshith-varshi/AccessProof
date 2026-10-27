# Release and rollback runbook

Before release, run the focused test commands in `05_TEST_MATRIX.md`, run `docker compose config`, and execute the read-only staging validator. Capture source validation, Guard heartbeat, policy version and audit evidence.

Rollback the application image/configuration through the normal deployment tool. Do not delete database volumes or source records. If authorization correctness is uncertain, put the affected RAG integration into its documented fail-closed mode, investigate policy revision/Guard health, and restore service only after validation.
