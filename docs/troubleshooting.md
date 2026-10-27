# Troubleshooting

## Positive control fails
The AI never retrieved the synthetic canary. Verify source permission, ingestion/indexing and identity mapping. The run should be PRECONDITION_FAILURE/INCONCLUSIVE, not PASS.

## Source denial confirmed but AI leaks
This is the core measured regression. Inspect probe timestamps and available evidence level. Do not assign a cache/vector-db root cause unless instrumentation proves it.

## INCONCLUSIVE after target outage
Check target availability and runner network path. Outages are intentionally not converted to PASS.

## Runner offline
Verify `ACCESSPROOF_API_URL`, runner ID/secret, outbound HTTPS and control-plane health. Registration tokens are one-time; do not reuse them.

## Cloud target rejected
Internal/private/link-local targets must use private runner mode due to SSRF protections.
