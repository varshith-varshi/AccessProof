# Private runner security

AccessProof separates the hosted control plane from the customer-operated private runner.
The control plane schedules typed permission-regression jobs; it does not open an
inbound connection, execute arbitrary commands, or receive an interactive shell on a
runner.

## Enrollment and credentials

An administrator creates a project-scoped enrollment code. It is high entropy,
short-lived, single use, revocable before use, and stored only as a hash. The runner
exchanges the code over TLS for a separate long-lived runner credential. That
credential is returned once, stored in a `0600` file in the runner state directory,
and is never returned by a normal control-plane API.

All runner runtime requests use `Authorization: Bearer <runner credential>`. Runner
credentials are never accepted in query parameters or JSON bodies. The runner secret
is redacted from checkpoints, logs, events, reports, and browser responses.

## Network and execution boundary

The runner makes outbound HTTPS requests to the control plane. It pulls a lease,
contacts configured source and RAG endpoints from its own network, and posts derived
events, checkpoints, hashes, timestamps, and outcome data. A runner only receives
jobs for its project, and a lease expires for recovery if the runner stops reporting.

The runner is deliberately limited to source validation, synthetic resource lifecycle,
authorization verification, RAG probing, evidence collection, and cleanup. It does
not accept arbitrary scripts or remote shell commands.

## Operational response

Use **Runners** to disable a runner temporarily, revoke a compromised runner, or
rotate its credential. Rotation requires updating the credential on that runner;
revocation immediately prevents further heartbeat/lease calls and releases unfinished
work for a compatible runner. Re-enroll a revoked runner instead of reusing its old
credential.

## Pilot limitations

Runner binaries are built from the repository/Docker image in this pilot. Signed
installers, hardware-backed credential storage, and automatic runner update channels
are future distribution work. Customer production data should only be tested after the
specific source and RAG integration has been validated in that tenant.
