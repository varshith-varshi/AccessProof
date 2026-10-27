# OIDC identity-to-source authorization mapping

## Implemented boundary

AccessProof now treats dashboard SSO and RAG employee authorization as
separate systems. The Guard validates an employee JWT locally, then resolves
the exact `(source, issuer, subject, tenant)` tuple through a tenant-scoped,
verified mapping before it evaluates source ACL policy.

- The issuer is preserved exactly. A trailing slash is not normalized.
- A source mapping points to a synchronized immutable Google Workspace source
  subject, never to an email address.
- Only `VERIFIED` mappings are sent on the authenticated Guard policy channel.
- `SUSPENDED`, `REVOKED`, missing, conflicting, cross-tenant and stale mappings
  fail closed. The Guard performs this resolution again at output release.
- Mapping snapshots are replaced on every successful Guard poll, independently
  of ACL-policy version. Revoking a mapping therefore takes effect without a
  fabricated ACL change.

## Operator workflow

1. Connect and synchronize the Google Drive permission source and directory.
2. Configure the customer-side Guard with its employee OIDC issuer, audience,
   immutable subject claim and tenant constraint.
3. In **web-v2 → Identity mappings**, select the source identity and enter the
   exact issuer, immutable subject and optional tenant. Verify the mapping.
4. Register the AI application with its Guard and source. Start in Shadow;
   move to Protect only after the existing application verification evidence is
   complete.

The mapping UI intentionally does not accept or infer an identity from an
email address. A customer must use a provider-/directory-verified process to
establish the mapping.

## Local validation completed

- OIDC verifier accepts a valid RSA token whose issuer ends in `/` and rejects
  discovery that returns the otherwise-similar issuer without `/`.
- Mapping API is tenant-scoped and rejects a source subject from another tenant.
- Guard policy sync transports only verified mappings, and a mapping revocation
  removes it from the next snapshot.
- The local customer lifecycle uses real loopback HTTP for control plane,
  Guard and RAG SDK. It covers mapping, allowed access, denied access,
  provenance escape, ACL revocation and stale-source failure.
- Existing adversarial Guard, two-layer provenance and revocation-race suites
  pass with the new boundary.

## Real-provider validation still required

No real Microsoft Entra, Okta, Auth0 or Google Identity tenant was contacted.
Before a customer Protect rollout, validate that provider's discovery/JWKS
behavior, issuer spelling (including trailing slash), audience and tenant
claims, key rotation, group/directory synchronization, source identity
mapping approval process, and revocation latency in that tenant. These are
provider and customer configuration facts that a synthetic local environment
cannot prove.
