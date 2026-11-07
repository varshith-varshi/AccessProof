# Customer SharePoint certification: independent automated source jobs

The SaaS **cannot** mint a SharePoint certificate. Source-specific live evidence
must be collected with two consenting Microsoft Entra employee sessions and an
authorized, isolated synthetic canary site. All **14** checks in
`packages/crypto/source_certificate.py` must pass. This includes temporary
revoke/restore of synthetic canary permissions and real Layer-1/Layer-2 route
tests. The job runs with `AWS_PROFILE=accessproof-certifier` on the independent
certifier host. There is no certificate without fresh evidence.

## Registration prerequisites

The customer's tenant administrator grants appropriate *selected-site* access
to an isolated, customer-approved test site (or selected test folder) and
identifies two consenting employees with different effective document rights.
No privileged access to the customer's other sites is required. The certifier
operator creates one private `0600` registration and one `0600` module profile
for each **exact** organization/source/application. The profile contains
source-specific tenant ID, site, synthetic file IDs/names, Guard, RAG, Gateway
route, and evidence/identity-socket paths. Never use another customer's
profile, test site, user tokens, model witness or source IDs.

Example registration (values are placeholders, **not** live customer data):

```json
{
  "schema": "accessproof.source_certification_registration/v1",
  "organization_id": "<organization UUID>",
  "source_id": "<source UUID>",
  "tenant_id": "<Microsoft Entra tenant UUID>",
  "application_id": "customer-rag",
  "scope_digest": "<current 64-character SHA-256 from restricted source_scope>",
  "profile_file": "/home/certifier/private/customer-profile.json",
  "gateway_service": "accessproof-gateway",
  "canary": {
    "site_url": "https://example.sharepoint.com/sites/AccessProof-Canaries",
    "mutation_authorized": true,
    "employee_object_ids": {"alice": "<immutable OID>", "bob": "<distinct immutable OID>"}
  }
}
```

The `mutation_authorized` flag is **not** an AccessProof Protect approval:
it records the test-site owner's permission to temporarily change only
synthetic permissions and restore them during certification.

## Independent job

From the independent certifier host with enrolled, short-lived AWS role
credentials (never with root credentials):

```bash
export AWS_PROFILE=accessproof-certifier
python scripts/certifier/customer_certification.py \
  --registrations ~/.config/accessproof/certifier/registrations
```

This checks the current production scope and identity bindings without signing.
After the exact customer canary site and test route are operational, the
`--execute` flag runs the existing real-tenant 14-check evidence collection,
independent Ed25519 signing, restricted production import, and revalidation.
The API still independently rejects invalid signatures, changed source scope,
revoked/expired certificates or stale authorization.

**Critical limitations as of 7 Nov 2026:** This is a *registered-source
automation worker*, not yet zero-configuration certification for arbitrary
customers. Initial registration, customer canary provisioning, employee Entra
sign-in, and secure always-on certifier-host provisioning still require an
approved onboarding workflow. The developer laptop can run this worker but is
not a production-independent 24/7 certifier host. The worker does not silently
grant Microsoft privileges or create users. Nothing should label Protect active
until the source certificate and all live activation checks pass.
