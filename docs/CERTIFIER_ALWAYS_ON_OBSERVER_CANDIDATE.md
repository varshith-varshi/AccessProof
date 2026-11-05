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

## Optional KMS-backed Ed25519 signing — implementation available, NOT ACTIVATED

AWS KMS supports `ECC_NIST_EDWARDS25519` (standard Ed25519), using `Sign` with `SigningAlgorithm=ED25519_SHA_512` and `MessageType=RAW`. This allows a *new* independent signer without copying the existing Ed25519 private key from the laptop. AWS KMS's prehash `ED25519_PH_SHA_512` is **not** interchangeable with AccessProof's current pure Ed25519 signatures. KMS RAW payloads must be <=4,096 bytes; the current three route-certificate canonical payloads were 2,393–2,405 bytes as checked on the existing certifier host.

Added `packages/crypto/aws_kms_signer.py`. It implements `sign()` / `public_key()` for the unchanged certificate wire format, verifies the returned signature with KMS's public key, and refuses misconfigured key type/usage/ARN/region, wrong algorithm, missing profile, static AWS environment credentials, and oversized messages. It does not create keys or access KMS in default/local mode; AWS SDK `boto3` is an opt-in existing `aws-kms` dependency. The source and remote-route certifier CLIs have **opt-in** KMS support, but local signer defaults remain unchanged.

**DO NOT enable KMS mode on the current laptop timers or existing production certifier without an approved new key and trust rotation.** This is a staged capability, not a complete infrastructure migration.

Required secure cutover steps (explicitly authorized operator only):

1. Provision the **separate private host** with an approved provisioning role, not the account root AWS CLI identity. Review the private subnet, networking, OS image, budget, alarms and DNS/SSM access. The CloudFormation observer-only template is not itself a signer.
2. Create a new **nonexportable** KMS key with key spec `ECC_NIST_EDWARDS25519`, usage `SIGN_VERIFY` in `eu-north-1`, and key policy granting `kms:Sign` and `kms:GetPublicKey` **only** to the independent certifier role. The role policy can be based on `deploy/certifier/iam-policy-kms-signer.template.json` after filling its single pinned key ARN placeholder. Deny other signing algorithms and avoid aliases to eliminate key-switching ambiguity. Do not grant API, worker, Gateway, customer app or RAG host roles KMS signing.
3. Retrieve the key's **public** DER `SubjectPublicKeyInfo` via `GetPublicKey`, validate `KeySpec`/`KeyUsage`, convert to the raw 32-byte Ed25519 public key and base64url encode. Obtain review and append a **distinct** key ID to the API's existing `ACCESSPROOF_SOURCE_CERTIFICATION_PUBLIC_KEYS_JSON` map without dropping the current key while its source/route certificates are valid. This trusted key pin is a production change and must follow the approved release process; signed evidence remains mandatory.
4. Configure the *independent host* with `AWS_PROFILE=accessproof-certifier` (dedicated role/instance metadata, not root or static env credentials) and the optional `aws-kms` Python extra; set `AP_CERTIFIER_KMS_KEY_ARN` to the approved immutable key ARN and `AP_CERTIFIER_KMS_KEY_ID` to the registered distinct identifier. Both variables must be configured for the same signer. Route and source certifier CLIs will then use the new KMS key; default remains the existing local key in the absence of the opt-in variables.
5. Complete the **separate** Microsoft employee authentication and private customer RAG connectivity review. Live employee sessions and approval cannot be replaced with synthetic credentials; never copy Alice/Bob sockets or refresh tokens from the laptop without a separately authorized secure process.
6. Using real approved employee sessions and disposable test sources, demonstrate source evidence collection, route revocation/restoration, signature verification, certificate import/rejection, and full fail-closed safeguards. Stage a parallel **read-only** observer first, ensure no concurrent certificate issuers, then perform an authorized cutover and decommission the laptop signer only after new issuance and renewal evidence succeeds.

The local source CLI supports `scripts/issue_source_certificate.py issue --kms-key-arn <approved-arn> --key-id <new-id> ...` and the route CLI uses the same environment variable pair; both enforce existing 14-check evidence gates. Existing source-certification functions and production route-verification code do not need a new signature format. No KMS key, role policy, trusted public-key pin or customer session was deployed by this change.

Official AWS docs: https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose-key-spec.html and https://docs.aws.amazon.com/botocore/latest/reference/services/kms/client/sign.html

### Public-key export helper (reviewable, no secrets)

On the **new approved independent certifier host**, after `KMS:GetPublicKey` is granted and the reviewed role is configured, run from the repo root:

```bash
AWS_PROFILE=accessproof-certifier uv run --extra aws-kms python -m scripts.certifier.kms_public_key_export \
  --kms-key-arn '<full-approved-KMS-key-ARN>' --key-id '<distinct-registered-key-ID>'
```

This returns only a JSON mapping from the new key identifier to its raw Ed25519 public key (base64url). It does **not** mutate production or sign a certificate. The organization Owner/security operator must approve merging this public key into the existing production trust pin. Do not use the laptop's AWS default root profile for key creation or trust updates.

**Existing source-renewal timers currently execute from the separate `AccessProof-realtime` working tree**, not this universal checkout. The KMS opt-in code in this checkout will not reach those live timers until the independent-host migration is explicitly executed and verified. Keep current source renewal on the existing local signer in the interim; do not silently change its working directory or port customer evidence paths.
