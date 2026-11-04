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

## Unattended AWS authentication (hardened)

### Identities: IAM Roles Anywhere, 1-hour credentials, no access keys

Each identity authenticates with an X.509 host certificate. AWS issues 1-hour credentials, refreshed automatically by `aws_signing_helper` through `credential_process`.

| CLI profile / role | Certificate (key 0600, user-only directory) | May do | Explicitly denied |
|---|---|---|---|
| `accessproof-staging-tunnel` | `~/.ap-id/rolesanywhere/tunnel/` (`OU=staging-tunnel`) | Instance Connect key push and SSH over SSM to the **staging** instance; close its own sessions | Every `SendCommand`, anything on the production instance, IAM, documents, infrastructure |
| `accessproof-certifier` | `~/.ap-id/rolesanywhere/certifier/` (`OU=certifier`) | `SendCommand` with **only** the 3 AccessProof documents; read command results (`eu-north-1`) | AWS-managed documents (including `AWS-RunShellScript`), interactive sessions, SSH key push, IAM, document changes, infrastructure |

Trust policy of each role:
* `rolesanywhere.amazonaws.com`;
* `aws:SourceArn` = the trust anchor;
* certificate subject CN, OU and O, and issuer CN.

Both the policies and the trust policies validated with **0 Access Analyzer findings**.

### Purpose-built SSM documents (`deploy/certifier/ssm`, rendered by `build_ssm_documents.py`, hashes in `MANIFEST.json`)

* `ProductionReadOnly`: certificate_status, identity_bindings, sync_cursors, effective_access_allows, guard_revisions, first_notification, source_scope, route_status. SQL runs with `default_transaction_read_only = on`; a write attempt was proven to fail.
* `ProductionImport`, the only write path: source certificate import, route certificate import, route attestation. Production still verifies the pinned certifier signature, binding and freshness.
* `RagHostProbe`: the two fixed re-certification probes, on staging only.

Every parameter is constrained by `allowedPattern` or `allowedValues`, and each document checks its instance id with IMDSv2 and refuses to run elsewhere.

**Remaining privilege:**
* SSM runs documents as root on the instance, but only this fixed, reviewed content.
* Anyone able to change documents could change that content, which is why document changes are denied to both roles.

### Certificates and keys

* **Host keys:** user-only (0700 directory, 0600 key). The services run as this user.
* **CA key:** encrypted with an owner passphrase (`~/.ap-id/rolesanywhere-ca/ca.key.enc`); the setup script removes the plaintext copy. It is used only to issue or revoke certificates. Prefer moving it offline.
* **Never in Git, images or logs:** keys live outside every repository and Docker build context. Checked: Git tree and full history contain no private key; service logs contain none; customer Gateway and Guard images contain no AWS CLI and no boto.
* **Renewal of a host certificate** (before 2027-11-04), for `<name>` = `tunnel` or `certifier`:
  ```
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes       -keyout ~/.ap-id/rolesanywhere/<name>/host.key.new -out /tmp/<name>.csr       -subj "/O=NeuralMatrix AccessProof/OU=<staging-tunnel|certifier>/CN=<accessproof-tunnel-host|accessproof-certifier-host>"
  openssl x509 -req -in /tmp/<name>.csr -CA ~/.ap-id/rolesanywhere/ca.pem       -CAkey ~/.ap-id/rolesanywhere-ca/ca.key.enc -CAcreateserial -days 365       -extfile ~/.ap-id/rolesanywhere/host.ext -out ~/.ap-id/rolesanywhere/<name>/host.pem.new
  ```
  Then move both `.new` files into place (`chmod 600` the key) and restart the service.
* **Revocation:** `bash deploy/certifier/rolesanywhere_revoke_host_cert.sh <host.pem>` imports a CRL; revoked or expired certificates cannot obtain credentials. For an emergency stop of everything, disable the trust anchor or the profiles.

### Owner steps

```
cd ~/Projects/AccessProof-universal
aws login                                                  # once, as an administrator (not used by services)
bash deploy/certifier/setup_unattended_aws_identity.sh     # creates, validates, switches; asks for the CA passphrase
bash deploy/certifier/verify_unattended_aws.sh             # proves operation with the login session hidden
# if anything is wrong:
bash deploy/certifier/setup_unattended_aws_identity.sh --rollback
```
