# Certificate renewal: migrate laptop-run independent certification safely

**Status:** Migration **NOT PERFORMED**. The current validated production renewal runs on the owner's Ubuntu laptop. This document defines prerequisites and a safe cutover; it does not authorize transferring keys or Microsoft tokens.

## Verified current dependencies

- `accessproof-route-attestation.timer` twice daily; route certificates expire around **2026-11-11**. Remote certification needs live customer RAG access, SSH/SSM tunnel, employee verification evidence and the independent signing identity. Missed attestation causes fail-closed `ATTESTATION_STALE`.
- `accessproof-cert-renewal.timer` and `accessproof-cert-renewal-pilot.timer` daily; source certificates expire around **2026-12-04**, renewal becomes due about **2026-11-24**. Both require Alice and Bob's active delegated sessions (`~/.ap-id/{alice,bob}.sock`), a local Guard, a signer key mode 0600, and access to the production read-only/import SSM documents.
- The current signing key is an **offline Ed25519 identity** intentionally isolated from production; copying it onto the public app/API host would compromise the trust separation.
- The read-only local health helper `python3 scripts/certifier/check_renewal_dependencies.py` checks prerequisites without printing secrets. A PASS **does not verify actual session validity or certificate renewal**.

## Non-negotiable operator decisions before migration

1. Select a **separate, always-on, hardened Linux certifier** host (not the public API host), under a dedicated least-privilege identity and access policy. Approve cost, OS update strategy, monitoring, network egress, and backups.
2. Review signing-key custody. Prefer a new, hardware-backed or otherwise isolated cryptographic signer **if it can meet the existing Ed25519 pinned trust model**. Otherwise select an explicitly authorized encrypted secure-key provision scheme; no private key transfer by automated assistant. Rotate/import signing trust only through the existing verified certificate trust-change procedure.
3. Decide the customer-approved identity flow for **live employee authorization**. Synthetic unattended tokens are insufficient; delegated employee refresh/session handling needs valid Entra consent, custody controls, revocation and a human reauthentication path. Never export Alice/Bob session sockets or raw refresh tokens from the laptop without explicit consent and a security review.
4. Replace the laptop-opened SSH/SSM RAG tunnel with a customer-authorized private network path, pinned TLS identity and explicit route scope. Ensure access is limited to the certification route, not general customer infrastructure.
5. Assign production permissions only for required **named certifier SSM documents** and read-only status. Do not grant generic shell, EC2 mutation, unrestricted AWS roles or console Owner privileges.

## Staged migration and rollback

1. Provision isolated certifier host and deployment identity with no customer data or key material. Confirm its clock synchronization, logging, encrypted disk, outbound network policy and service supervision.
2. Dry-run source and route certificate **read-only** checks on new host. Validate connectivity and failure alarms without issuing or importing certificates.
3. Conduct authorized key and employee-session design review. Obtain explicit customer/Owner approval before installing any private signing key, credential or persistent employee session.
4. Test certificate issuance and rejection (bad identity, permission revocation, stale evidence, disconnected RAG, expired certificate) using a synthetic tenant and disposable keys.
5. Only after signed evidence and approved credentials are available, run the old and new schedulers with the **new host in observer-only mode** to compare outcomes. Never allow concurrent writers/importers for the same certificate.
6. Activate the new certifier alone, verify an actual route attestation and one complete renewal against approved test evidence, and observe a full cycle before disabling laptop timers.
7. Preserve bounded rollback: reenable previous supervised laptop timers only if key rotation/trust state permits. Alert on missed run, <72h to route expiry, <10d to source expiry, or failed signed evidence import.

**Blocker:** Today there is no authorized replacement for the laptop's offline signer, live Microsoft employee sessions and owner-managed tunnel. Keeping existing renewal timers active until a reviewed migration completes is safer than pretending a server-side cron job solves the dependency.
