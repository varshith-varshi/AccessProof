# GitLab CI

AccessProof does not implement a second GitLab-specific test engine. GitLab uses the same versioned API and `accessproof` CLI as GitHub and local CI.

Create a scoped AccessProof API key with `runs:create` and `runs:read`, then store these as masked/protected GitLab CI variables:

- `ACCESSPROOF_API_URL`
- `ACCESSPROOF_API_TOKEN`
- `ACCESSPROOF_ORG_ID`
- `ACCESSPROOF_PROJECT_ID`
- `ACCESSPROOF_SUITE_ID`
- `ACCESSPROOF_CLI_VERSION`

The CLI reads the first three directly from the environment, so CI does not need an interactive login or a credential file. Copy `integrations/gitlab/.gitlab-ci.accessproof.yml` into your pipeline and pin the AccessProof CLI package/version used by your deployment.

The actual CLI contract is positional for project and suite IDs:

```bash
accessproof run "$ACCESSPROOF_PROJECT_ID" "$ACCESSPROOF_SUITE_ID" \
  --release "${CI_COMMIT_TAG:-$CI_COMMIT_SHORT_SHA}" \
  --git-sha "$CI_COMMIT_SHA" \
  --wait \
  --block-on-inconclusive
```

Exit behavior is consistent across CI systems:

- PASS: `0`
- FAIL: `1`
- INCONCLUSIVE / PRECONDITION_FAILURE: `2` by default
- internal/other error: `3`

Use `--warn-on-inconclusive` when your release policy should allow an inconclusive test to warn rather than block.
