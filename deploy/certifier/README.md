# Automatic source-certificate renewal (certifier host)

Install (owner, on the offline certifier host; not done automatically):

```
mkdir -p ~/.config/systemd/user
cp deploy/certifier/accessproof-cert-renewal.{service,timer} ~/.config/systemd/user/
systemctl --user daemon-reload && systemctl --user enable --now accessproof-cert-renewal.timer
loginctl enable-linger "$USER"     # run while logged out
```

Every day it checks the active certificate. If 10 days or fewer remain, it renews:

* It collects new live evidence in that same run (effective matrix, Layer 1, RAG E2E, live
  revocation plus route trial, buffered release). Evidence is never reused, and the importer rejects evidence older than 72 hours.
* It checks the source scope, signing-key integrity (0600, pinned public key) and that the Guard is ready.
* It issues and imports the certificate, then verifies it through production.

If anything fails, the current certificate stays in place. The run exits non-zero and records a
`FAILED` line in `~/.ap-id/certificate-renewal.log`. The 10-day lead leaves time to fix the problem by hand.

Validity: production r35 accepts up to **14 days**. r36 (commit 71e34cf, not yet deployed)
raises the maximum to **30 days**. The service pins `--days 14` for r35. After r36 is deployed, change it to `--days 30`.

Prerequisites while it runs: the employee test sessions (`scripts/live/start_employee_sessions.sh`)
must be up, AWS SSM access must work, and the certifier key must exist. If any of these is missing, renewal fails closed.
