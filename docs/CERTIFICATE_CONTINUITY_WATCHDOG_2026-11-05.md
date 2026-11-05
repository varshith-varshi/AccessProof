# Certificate continuity watchdog — Ubuntu certifier laptop

This is a **read-only warning system**, not an alternative certificate issuer, and not a substitute for the separate always-on certifier migration proposed in `RENEWAL_HOST_MIGRATION_PLAN_2026-11-05.md`.

## Installed systemd user services

- `accessproof-renewal-watchdog.timer`: runs approximately every two hours, including catch-up runs after laptop startup (Persistent=true).
- `accessproof-renewal-watchdog.service`: checks all locally stored route certificates, the latest attestation for each route, active renewal timers, credential-file permissions, available Alice/Bob Unix sockets, and the route tunnel status. It never opens or exports the key or employee tokens. It performs **no certificate renewal** and **no production writes**.
- `accessproof-renewal-watchdog-alert.service`: attempts a desktop notification when the watchdog exits with a warning or critical result. A desktop notification requires a running graphical session. Regardless, failures and structured status are preserved in the per-user journal.

## Expected behavior and checks

- `OK`: route certificates remain certified, last signed-attestation run is recorded as successful in local metadata, local prerequisites are present, and route certificates have more than 4 days remaining.
- `WARNING`: a route certificate has 4 or fewer days remaining (automatic re-certification runs within 2 days of expiry), or an attestation is failing or stale.
- `WARNING` (nonzero exit): the most recent attestation failed or is stale, a route certificate is not signed/CERTIFIED, is near expiry, invalid or expired, or local certifier prerequisites are missing. Inspect the structured JSON in journald for the specific reason.

Inspect current status without changing any production resource:

```bash
cd /home/white-devil/Projects/AccessProof-universal
python3 -m scripts.certifier.renewal_watchdog
systemctl --user list-timers accessproof-renewal-watchdog.timer
journalctl --user -u accessproof-renewal-watchdog.service -n 20 --no-pager
```

Local certificate metadata checks do not cryptographically validate a signature; the independent production certifier remains authoritative. A warning does not by itself imply Protect is off; consult server-authoritative certificate and Gate E state. The watchdog only observes local routes and services and cannot read the customer dashboard's authenticated `PROTECTED_VERIFIED` status.

**Important limitations:** When the laptop is off, no local watchdog or signing job runs. Systemd lingering and timer catch-up cannot change that. Local Unix socket existence does not prove that Microsoft employee login sessions are valid. Source certificate validity must still be checked through the existing authorized read-only production operation, and Owner Approval still requires the real Owner. Independent ChatGPT reminders are scheduled for **November 9** (route certification) and **November 24** (SharePoint source renewal), but they don't check or renew certificates automatically.

## Source certificate and renewal failure alerts

`accessproof-source-expiry-monitor.timer` checks the live pilot and reference source certificates daily via the approved read-only AWS role. A failure in the route-attestation, source-renewal, or monitoring oneshot service starts `accessproof-renewal-watchdog-alert.service`, which attempts a desktop notification and leaves a journal event. This alert is **local-only**: when this laptop is off, no notification can be delivered. It is not an independent, always-on monitor.
