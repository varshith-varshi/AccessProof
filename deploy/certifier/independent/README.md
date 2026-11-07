# AccessProof isolated certifier: administrator provisioning and cutover

STATUS: NEW HOST NOT PROVISIONED. PRODUCTION SIGNING NOT ACTIVATED.

This package prepares a NEW EC2 host and AWS KMS Ed25519 key. It does not
reuse the production API server or the staging RAG host under certification.
The cloud stack has no permission to sign or import certificates initially,
no Microsoft sessions, no private key exports, and no automatic Protect changes.

## Administrator infrastructure deployment (not executed by assistant)

The current accessproof-certifier delegated identity explicitly denies
CloudFormation, IAM, infrastructure and key creation. Do not bypass that
role with AWS root or unrestricted SSM documents. The organization must
review the billable EC2/KMS costs and select an approved private VPC subnet
with outbound HTTPS access (NAT or AWS endpoints).

Only an authorized infrastructure administrator executes:

    aws cloudformation validate-template --region eu-north-1 --template-body file://deploy/certifier/independent/isolated-certifier-stack.json

    aws cloudformation deploy --region eu-north-1 --stack-name accessproof-independent-certifier-2026 --template-file deploy/certifier/independent/isolated-certifier-stack.json --capabilities CAPABILITY_IAM --parameter-overrides VpcId=vpc-REPLACE PrivateSubnetId=subnet-REPLACE

    aws cloudformation describe-stacks --region eu-north-1 --stack-name accessproof-independent-certifier-2026 --query 'Stacks[0].Outputs'

The stack sets: no public IP or ingress security-group rules, IMDSv2-only,
encrypted gp3 volume, AWS SSM instance management, outbound HTTPS only,
new distinct Ed25519 KMS key retained on stack deletion, and a restricted
assumable execution role with GetPublicKey but NO KMS Sign, NO certificate
import permissions and no static AWS keys.

## Separate host bootstrap (read-only)

On the NEW host ONLY, after reviewing the stack outputs and staging the
reviewed source files through a separate approved administrator workflow:

    cd /opt/reviewed-AccessProof-source
    sudo bash deploy/certifier/independent/bootstrap_readonly_host.sh INSTANCE_ID_FROM_STACK EXECUTION_ROLE_ARN_FROM_STACK KMS_KEY_ARN_FROM_STACK
    sudo systemctl status accessproof-independent-certifier-preflight.timer
    sudo journalctl -u accessproof-independent-certifier-preflight.service -n 25 --no-pager

The bootstrap establishes a non-secret IAM role-assumption profile named
accessproof-certifier; IMDS provides rotating, ephemeral base credentials.
It installs only a read-only systemd preflight timer. It never enables a
signer, certificate import or employee session. Even PASS here is just
host-identity readiness, not an independent certificate renewal.

## Additional authorization and technical dependencies

1. Trust-key rotation: Export only the new KMS Ed25519 PUBLIC key with the
   reviewed exporter. Register its distinct key ID alongside the current
   signer in the production API's
   ACCESSPROOF_SOURCE_CERTIFICATION_PUBLIC_KEYS_JSON. Verify old certificates
   and route attestations continue to validate and unknown signatures fail.
   Never replace current trust before an approved dual-key transition.

2. Grant limited signing rights ONLY after trust registration: kms:Sign on
   the exact reviewed key and SigningAlgorithm=ED25519_SHA_512, together with
   scoped ProductionReadOnly, ProductionImport and RagHostProbe SSM document
   actions. Existing generic shell, unrelated instance and IAM mutations
   remain denied. This separate authorization is deliberately absent from
   the initial infrastructure stack.

3. Real Microsoft identity: Source renewal currently requires genuine Alice
   and Bob delegated Entra sessions. Set up approved user consent, secure
   custody, token expiry and human reauthentication on the dedicated host.
   Do not copy employee .sock files or refresh tokens off the laptop.
   App-only Graph permission is not a valid substitute for per-user tests.

4. Genuine independent Guard/RAG route: The existing two remote RAG routes
   depend on an SSH tunnel from the laptop (localhost ports 28187 and 28188)
   to a laptop-hosted Gateway and Guard. Moving a timer to EC2 does not
   make those routes available when the laptop shuts down. Independently
   deploy and certify a proper customer-approved Gateway/Guard path, then
   adapt the source renewer's local Docker evidence checks to that path.

5. Before turning on the new writer: run fresh synthetic certificate
   issuance/import, revocation/recovery, source and route tampering, stale
   evidence rejection, key-trust rotation tests and a complete laptop-off
   test. Enable one production certificate writer and disable the old laptop
   timers only after witnessed independent renewal and rollback approval.

The always-on staging observer (commit 6fbdfe5) currently detects outages
but cannot generate a signature, establish employee auth, or certify a route.

## Local tests (safe, no infrastructure mutations)

    PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -q tests/unit/test_isolated_certifier_infrastructure.py tests/unit/test_independent_host_preflight.py tests/unit/test_certifier_kms_ed25519_signer.py

    python3 -m json.tool deploy/certifier/independent/isolated-certifier-stack.json
    bash -n deploy/certifier/independent/bootstrap_readonly_host.sh

Completion is established only when a real independently held signer issues
and imports fresh certified evidence with independently authorized employee
sessions and a customer-approved route, while the laptop is OFF.
