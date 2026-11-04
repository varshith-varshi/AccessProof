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

## Required manual action: a non-interactive AWS identity

The tunnel, the route attestation (production import via SSM) and the certificate renewals call AWS.
The current credentials are a console `aws login` session for the **root** account. They expire, and they must not be used unattended.

Create a dedicated IAM identity with `certifier-unattended-iam-policy.json` and give it to the certifier host. That policy allows:
* staging SSH-over-SSM and the Instance Connect key push;
* `AWS-RunShellScript` on the production and staging instances;
* reading command results.

Then point the CLI at it, for example:

```
aws configure --profile accessproof-certifier          # access key of the dedicated IAM user
# then add to each unit:  Environment=AWS_PROFILE=accessproof-certifier
systemctl --user daemon-reload
```

(Better still is IAM Roles Anywhere with a host certificate, which avoids static keys.) `AWS-RunShellScript` on production is powerful; a later hardening step is to replace it with dedicated SSM documents for the gates, import and attest operations.
