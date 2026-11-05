# Unattended AWS access: hardening status (2026-11-05, final)

**24/7 AWS authentication is COMPLETE and verified with the interactive login session hidden** (`verify_unattended_aws.sh`: 16/16 PASS).

| Component | Implemented | Installed | Live-verified |
|---|---|---|---|
| SSM documents ReadOnly / Import / RagHostProbe (no `AWS-RunShellScript`) | yes | **yes** (created in eu-north-1 from the committed, hash-checked content) | yes: route attestation and renewal reads run through them |
| Role `accessproof-staging-tunnel` (Roles Anywhere, 1-hour credentials) | yes | **yes** | authenticates; reconnects the tunnel after SIGKILL; **denied** on production and IAM |
| Role `accessproof-certifier` (3 documents only) | yes | **yes** | authenticates; route verification and both renewal services run on it; **denied** `AWS-RunShellScript`, interactive sessions, SSH key push, document changes, IAM |
| Services switched (systemd drop-ins; backup `~/.ap-id/aws-setup-backup-20261105T013747Z`) | yes | **yes** | tunnel, `accessproof-route-attestation`, `accessproof-cert-renewal` and `accessproof-cert-renewal-pilot` all succeeded with no login session |
| Short-lived credentials | yes | yes | 1-hour expiry observed; `credential_process` obtains fresh credentials whenever they are needed |
| Production fix (invalidation reason length) | yes | **deployed r38f** | regressions 1667/0 (SQLite and PG) |
| Customer components need no NeuralMatrix AWS; no private keys in Git, images or logs | n/a | n/a | verified |
| Production | n/a | r38f | **gates A–J PASS for both applications**, Protect **ACTIVE**, 2 + 1 remote routes VALID |

## Owner step still open

* Encrypt the CA private key with a passphrase only you know (it needs a terminal):
  `bash deploy/certifier/setup_unattended_aws_identity.sh --encrypt-ca-key`
  Until then `~/.ap-id/rolesanywhere/ca.key` is plaintext (0600, user-only).

## Not yet tested

* Recovery after a full machine reboot (configured: linger, enabled units, container restart policies).
* A credential refresh across an actual 1-hour expiry inside a long-running process. The CLI obtains fresh credentials per call through `credential_process`, and the tunnel re-authenticates on every reconnect.
* Live allow/deny re-check on r38f: the synthetic Alice and Bob sessions had expired.

## Remaining limitation (owner decision)

Source-certificate renewal and route re-certification need fresh synthetic Alice and Bob sign-ins (tokens in memory only, by design). Without them those runs fail closed, and the 10-day and 2-day leads leave time to react. Route attestation and the evidence refreshers do not need the sessions.
