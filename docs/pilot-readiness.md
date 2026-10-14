# Pilot-ready local validation

AccessProof waits for the synthetic document to become visible to the AI before it revokes access. Configure this in a suite's `positive_control` policy:

```json
{"timeout_seconds":120,"poll_interval_seconds":5,"required_observations":2}
```

If visibility never becomes stable, the run ends as `PRECONDITION_FAILURE` with `AI_INGESTION_NOT_CONFIRMED`; it is never reported as a pass or a failed propagation SLO.

For conversational targets choose `STATELESS`, `NEW_SESSION_PER_PROBE`, `ONE_SESSION_PER_RUN`, or `CUSTOM_SESSION`. The generic HTTP adapter supports a session-creation URL and `session.id` extraction path. If a required session cannot be created, the target observation is unavailable rather than treated as a clean authorization result.

Create Alice and Bob under **Test identities**. Their bearer credentials are encrypted at rest, excluded from normal API responses and run records, and resolved only in a runner lease. Use the AI target header template `Bearer {{ principal.access_token }}` for authenticated probes.

The local demo validates the product mechanics. A customer pilot still requires real Entra/OIDC accounts, the source of truth, and the enterprise AI target.
