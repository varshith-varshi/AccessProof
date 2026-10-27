# Live Workspace validation checklist

This checklist is a **NO-GO** until every item is witnessed in a customer-controlled non-production Google Workspace tenant.

- [ ] Dedicated operator OAuth client, least privilege scopes and HTTPS callback verified.
- [ ] My Drive direct user allow/revoke verified.
- [ ] Folder inheritance and child-file overrides verified.
- [ ] Google Group and nested-group membership grant/revoke verified.
- [ ] Shared Drive membership and item restrictions verified.
- [ ] Link sharing, domain sharing and external principals have an explicit documented policy.
- [ ] Rate limits, pagination, changes/watch recovery and token revocation tested.
- [ ] Guard offline, revision lag and stale-cache outcomes fail as configured.
- [ ] Customer RAG sends authenticated identity plus canonical retrieved-document IDs; a deny blocks output.
- [ ] Audit trail is complete and no OAuth/Guard secret appears in logs or browser responses.
