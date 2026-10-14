# Private runner

The runner is designed for outbound-only deployment inside the customer test environment.

1. An admin creates a one-time registration token in the web/API.
2. The runner exchanges it at `/api/v1/runners/exchange`.
3. The control plane stores only the hash of the resulting runner secret.
4. The runner heartbeats and leases typed jobs using an Authorization bearer header.
5. Provider credentials are decrypted only into the authenticated runner job envelope.
6. The runner calls the source and private AI endpoint locally and posts derived evidence back to the control plane.

Docker runs as UID 10001. The compose runner profile uses a read-only root filesystem and a dedicated state volume. No inbound port is needed.

Required environment variables:

```text
ACCESSPROOF_API_URL=https://accessproof.example
ACCESSPROOF_RUNNER_ID=...
ACCESSPROOF_RUNNER_SECRET=...
```

The runner checkpoints leased job envelopes. Credentials are removed before any local
checkpoint is written. Lease expiry and mutation-journal recovery prevent a second
runner from blindly replaying an acknowledged source mutation.

See [runner security](runner-security.md) for the credential, network, and response
model, and [customer onboarding](customer-onboarding.md) for the supported pilot flow.
