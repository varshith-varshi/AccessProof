# GitHub Actions

`integrations/github/action.yml` creates a release-qualified run, waits for a terminal result and exits:

- `0` PASS
- `1` FAIL
- `2` INCONCLUSIVE/PRECONDITION_FAILURE when configured to block
- `3` AccessProof/API execution error

Use a revocable AccessProof API key created through `/api/v1/api-keys` and store it as a GitHub secret. Do not put interactive session tokens in CI.
