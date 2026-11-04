# AccessProof 24/7 unattended operation (certifier / lab host)

| Unit (systemd --user, linger on) | Purpose | Restart | Boot |
|---|---|---|---|
| `accessproof-ingestion-refresher-reference` | Signed evidence, reference org | always (30 s) | `default.target` |
| `accessproof-ingestion-refresher-pilot` | Signed evidence, pilot org (own key) | always (30 s) | `default.target` |
| `accessproof-remote-rag-tunnel` | SSH over SSM to the staging RAG host (loopback-only forwards) | always (20 s) | `default.target` |
| `accessproof-route-attestation.timer` | Remote route attestation, twice daily | n/a | `timers.target` (persistent) |
| `accessproof-cert-renewal.timer`, `-pilot.timer` | Source certificate renewal, daily | n/a | `timers.target` (persistent) |

* **Single instance:** each refresher runs under `flock --nonblock` on `<ingestion home>/.refresher.lock`, so a second instance exits 75. Publishing also takes the publisher's own lock and enforces a monotonic sequence.
* **Containers:** every lab and pilot container uses `--restart unless-stopped`, and Docker is enabled at boot.
* **Logs:** journald (`journalctl --user -u <unit>`). The refresher logs event names, sequence numbers, expiry and error types only, never credentials.

## Unattended AWS authentication (IAM Roles Anywhere; owner runs the setup once)

* **No IAM user and no access keys.** The certifier host authenticates with an X.509 certificate.
  Claude generated `~/.ap-id/rolesanywhere/{ca.pem,host.pem}` and `host.key` (0600) on this host; the keys are never printed.
* AWS returns **1-hour** credentials, refreshed automatically by `aws_signing_helper` (v1.4.0, in `~/.local/bin`)
  through `credential_process` in the `accessproof-certifier` CLI profile.
* **Role `accessproof-certifier`:**
  * Assumable only through Roles Anywhere, only from trust anchor `accessproof-certifier-host-ca`, and only with certificate subject `CN=accessproof-certifier-host, OU=certifier`.
  * Inline policy `certifier-unattended-iam-policy.json` grants exactly the calls the services make, all in `eu-north-1`:
    * Instance Connect key push to the staging host (`ubuntu` user only);
    * an SSH session over SSM to the staging host;
    * terminating or resuming only its own `accessproof-certifier-*` sessions;
    * `AWS-RunShellScript` on the production and staging instances only;
    * reading command results.
  * There are no IAM, EC2, S3 or deploy permissions.
* **Remaining privilege:** `AWS-RunShellScript` on production is root-equivalent there. A later hardening step is to replace it with dedicated SSM documents for status, import, attest and read-only SQL.

Run once, while signed in with `aws login`:

```
bash deploy/certifier/setup_unattended_aws_identity.sh
```

It:
1. creates (or reuses) the trust anchor, role, inline policy and profile;
2. writes the CLI profile and checks that `sts get-caller-identity` returns the role;
3. adds `AWS_PROFILE=accessproof-certifier` drop-ins to the tunnel, route-attestation and both renewal services;
4. restarts the tunnel.

Certificate lifetimes:
* The host certificate expires **2027-11-04**; re-issue it from the local CA before then.
* The CA expires **2028-11-03**.
* Revoke access at any time by disabling the trust anchor or profile in IAM Roles Anywhere.
