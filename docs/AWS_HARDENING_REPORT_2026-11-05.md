# Unattended AWS access: hardening status (2026-11-05)

**24/7 AWS authentication is NOT yet complete.** The owner must run the setup; the services then have to be proven working with the interactive login hidden.

| Component | Implemented | Installed in AWS | Live-verified |
|---|---|---|---|
| SSM documents (ReadOnly / Import / RagHostProbe) replacing `AWS-RunShellScript` | yes (`deploy/certifier/ssm`, hashes in `MANIFEST.json`) | **no**: owner setup | **content yes**: every operation ran against production and staging with the exact rendered document. A DB write in the read-only session was rejected; an injection attempt was refused by the pattern. |
| Services moved onto the documents (renewal, route attestation, revocation polls, challenge status, staging probes) | yes | n/a | **yes, content-mode**: route attestation (3 routes VALID), renewal NOT_DUE path, probe through the adapter; arbitrary probe code refused |
| Role `accessproof-staging-tunnel` (staging SSH only; commands and production denied) | yes | **no** | Access Analyzer: 0 findings (policy and trust) |
| Role `accessproof-certifier` (3 documents only; IAM, documents, AWS shell, sessions and infrastructure denied) | yes | **no** | Access Analyzer: 0 findings |
| Roles Anywhere: separate tunnel and certifier host certificates; trust anchor = local CA | certificates created (0600, user-only) | **no** | certificates verify (`x509_strict`) |
| CA key encrypted with owner passphrase | in setup | **no** | n/a |
| CRL revocation procedure | yes (`rolesanywhere_revoke_host_cert.sh`) | **no** | syntax only |
| Production fix: invalidation reason exceeded its column (PostgreSQL rolled the invalidation back) | yes | **deployed r38f** (`b1dcf70`), regressions SQLite/PG 1667/0 | unit-tested; gates A–J PASS after deploy |
| Customer Gateway and Guard need no NeuralMatrix AWS | n/a | n/a | **verified**: no AWS code in apps/gateway, apps/guard, packaging or integrations; images contain no AWS CLI and no boto |
| No private keys in Git, images or logs | n/a | n/a | **verified** (Git tree and full history, build contexts, service logs) |

Production on r38f: **gates A–J PASS for both applications**, Protect **ACTIVE**, both Guards ready.

## Owner commands

```
cd ~/Projects/AccessProof-universal
aws login                                              # administrator, once; not used by the services afterwards
bash deploy/certifier/setup_unattended_aws_identity.sh # creates documents/roles/profiles, validates allowed+denied, switches, encrypts CA key
bash deploy/certifier/verify_unattended_aws.sh         # hides ~/.aws/login and proves all three services work
# rollback if needed:
bash deploy/certifier/setup_unattended_aws_identity.sh --rollback
```

## Not yet tested

* Everything that needs the owner setup: the real documents and roles in AWS, unattended tunnel reconnect, route verification and renewal with the login session hidden, and automatic credential refresh.
* **Live enforcement re-check on r38f:** the synthetic Alice and Bob sessions had expired (tokens are in memory only, 12-hour maximum). Gates A–J pass on recorded evidence.
* Recovery after a full machine reboot.

## Remaining limitation (owner decision)

**Source-certificate renewal** (about every 20 days) and **route re-certification** (about every 5 days) require fresh synthetic Alice and Bob sign-ins, because tokens are in memory only by design. Without them those runs fail closed, and the 10-day and 2-day leads leave time to react. Route attestation and the evidence refreshers do not need the sessions. Unattended renewal would require at-rest, encrypted refresh tokens for the synthetic identities, which changes the current rule.
