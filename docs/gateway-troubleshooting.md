# Gateway troubleshooting

`IDENTITY_TOKEN_REQUIRED` means the employee bearer token is missing. `SOURCE_CONTENT_ATTESTATION_FAILED` means the content or its binding differs from trusted ingestion output. `NO_AUTHORIZED_RESOURCES` means Guard Layer 1 denied all retrieval candidates. `GUARD_REQUEST_FAILED` or `GUARD_NOT_READY` are fail-closed conditions. `STREAMING_UNSUPPORTED_ON_PROTECTED_ROUTE` requires a buffered route.
