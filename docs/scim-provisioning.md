# SCIM 2.0 provisioning

AccessProof exposes an organization-scoped SCIM 2.0 endpoint at `/scim/v2` after an OWNER/ADMIN enables SCIM in **Settings**. The bearer token is shown once and stored only as a hash.

## Supported resources

- `Users`: create, list/filter by `userName`, read, activate/deactivate, and deprovision.
- `Groups`: create, list/filter by `displayName` or `externalId`, read, patch membership, rename, and deactivate.
- Discovery: `ServiceProviderConfig`, `ResourceTypes`, and `Schemas`.

SCIM operations are tenant-scoped and protected by the same PostgreSQL RLS context used by the application when PostgreSQL is enabled.

## Group-to-role mapping

The standard SCIM Group resource is extended with:

`urn:accessproof:params:scim:schemas:extension:role:2.0:Group`

Example:

```json
{
  "schemas": [
    "urn:ietf:params:scim:schemas:core:2.0:Group",
    "urn:accessproof:params:scim:schemas:extension:role:2.0:Group"
  ],
  "displayName": "Engineering",
  "urn:accessproof:params:scim:schemas:extension:role:2.0:Group": {
    "role": "ENGINEER"
  }
}
```

Allowed mapped roles are `ADMIN`, `ENGINEER`, `VIEWER`, and `AUDITOR`. SCIM can never assign `OWNER`.

AccessProof deliberately rejects conflicting role-group assignments. If one user is already in a role-mapped group and an IdP attempts to add that user to a second group mapped to a different AccessProof role, the request returns `409` instead of silently choosing the more privileged role.

When a user leaves their only role-mapped group, their organization membership falls back to the SCIM configuration's default role. Deactivate/reactivate cycles preserve group membership and recompute the mapped role on reactivation.

## Typical IdP configuration

1. Enable SCIM in AccessProof Settings and copy the one-time bearer token.
2. Configure the IdP base URL as `https://<accessproof-host>/scim/v2`.
3. Configure bearer-token authentication.
4. Provision users first, then groups/memberships.
5. For role mapping, send the AccessProof Group Role extension shown above.
6. Verify provisioning in the organization member list and audit log.

## Safety properties

- SCIM cannot provision OWNER.
- Tokens are stored hashed and can be rotated by re-saving SCIM configuration.
- Cross-organization SCIM resource access returns not found.
- Group role conflicts fail closed.
- Deprovisioning removes active organization access without deleting the global user account.
