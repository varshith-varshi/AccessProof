# Runner enrollment

AccessProof private runners make outbound HTTPS requests to the control plane. The control plane never opens an inbound connection to a customer machine.

An administrator creates a project-scoped enrollment code in **Runners**. The code is shown once, expires after 5–60 minutes, can be revoked before use, and is stored only as a hash. The installed runner exchanges it once for a runner credential, stores that credential in a mode-`0600` file owned by the dedicated `accessproof` service account, and immediately begins authenticated heartbeats.

The normal Ubuntu flow is:

1. Download `accessproof-runner_<version>_amd64.deb` from the approved AccessProof release channel.
2. Open the package installer.
3. Open **AccessProof Runner** from the desktop launcher.
4. Paste the one-time code generated in the AccessProof website and select **Connect Runner**.

The package installs `accessproof-runner.service`. The service is enabled only after successful enrollment, starts at boot, restarts after unexpected failures, and runs as the low-privilege `accessproof` user.

For controlled technical deployments, `accessproof-runner enroll --server … --code … --name …` remains available. The legacy `POST /api/v1/runners/exchange` contract remains for backward compatibility but is not the primary customer workflow.

Runner credentials are never shown in the website after enrollment. Revoking a runner disables its credential and releases unfinished leases back to the queue.
