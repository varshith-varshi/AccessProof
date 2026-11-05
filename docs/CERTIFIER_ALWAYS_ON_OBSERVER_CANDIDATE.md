# Always-on AccessProof certifier: isolated observer-host blueprint

**State: TEMPLATE PREPARED — NO NEW AWS SERVER PROVISIONED.** This deliberately does **not** migrate the production certificate signer or employee sessions. The running certifier remains on the owner's Ubuntu laptop until a reviewed cutover is approved. This file is for the infrastructure operator and must not be used to imply 24/7 certificate signing is live.

## What is ready

`deploy/certifier/always_on_observer.template.json` is a CloudFormation blueprint for a *separate*, private SSM-managed EC2 candidate. The template creates no public IP or inbound security-group access, pins IMDSv2, encrypts the 30 GiB root volume with EBS, and limits its instance role to AWS-managed **AmazonSSMManagedInstanceCore**. It deliberately grants **no** certificate import, IAM administration, employee-token access, route execution, customer RAG access or signing permission. Cloud-init creates only a locked-down service user/directory, never any credential. All these invariants have offline regression tests. Using an instance adds AWS charges, so it has **not** been deployed.

### Operator-provided prerequisites before deployment

An authorized AWS infrastructure owner must pick and approve: VPC, **private** subnet, approved current Linux AMI with SSM agent, that AMI's actual root device mapping, instance capacity/cost, SSM VPC endpoints (or restricted NAT HTTPS egress), backup/log retention and approved monitoring. This template is an *observer host skeleton*, not an authorization to copy the laptop signer into a public production server. Never deploy it into the production RAG host or reuse the public API's role.

For an approved account and explicit infrastructure change, the operator can review the template and deploy it via an approved CloudFormation execution role with `CAPABILITY_IAM` and supplied parameters. Do not use the restricted `accessproof-certifier` or `accessproof-production-deployer` roles for provisioning; they intentionally lack infrastructure-creation privileges.

### Separate security cutover required to make it an issuer

The template must **not** automatically run source or route renewal. Before activation, the organization must independently approve:

1. Signing-key custody and trust rotation/registration (prefer key isolation/HSM or suitable KMS signing support if the pinned Ed25519 protocol is compatible). **No automated copy of `~/.config/accessproof/certifier/*.pem`**.
2. A tenant-approved human employee authentication and bounded refresh policy; no socket or token copying from the old laptop. Employees must be able to revoke consent and reauthenticate.
3. A customer-authorized private RAG route with pinned transport identity and scoped network permission. Do not create arbitrary tunnels into customer infrastructure.
4. Least-privilege certifier-only named SSM import/read permissions, independently reviewed and bound to the correct application/source; no generic shell or document mutation access.
5. End-to-end synthetic certification tests with disposable keys, revocation, denied identities, stale evidence and rollback. Only one host may issue/import for each certificate at a time. Verify an authorized live renewal on the new host before disabling laptop timers.

## Immediate no-new-server operation

Current local systemd timers remain active. Two monitoring timers check local route signatures/expiry/attestation and live source expiry. Five renewal and monitoring jobs now have a local desktop OnFailure notification wired (graphical-session dependent), and journald records failures. This is **not** an off-host paging channel and cannot operate while the laptop is off.

Keep the laptop on for the **November 9** route recertification window. Source renewal starts around **November 24**. Review `docs/FINAL_CUSTOMER_HUMAN_STEPS_2026-11-05.md` for the actual customer consent/Owner steps, and `docs/RENEWAL_HOST_MIGRATION_PLAN_2026-11-05.md` for the rollback sequence.
