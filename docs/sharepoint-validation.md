# SharePoint validation

AccessProof's Microsoft 365 connector is for a dedicated test boundary. It creates
synthetic files, changes only permissions that it created, and deletes the files at
the end of a run.

## Recommended setup

Create two dedicated Entra test users: Alice (the initially allowed user) and Bob
(the control user). Create a dedicated SharePoint site, document library, and test
folder; do not point AccessProof at a production library.

Create a customer-owned app registration for the mutation credential. Configure the
connector with its short-lived Graph access token, the target `drive_id`, and the
test folder's `test_root_item_id`. The token needs permission to read that boundary,
create and delete the synthetic file, and add/remove the file permissions it owns.
Prefer site-scoped access such as `Sites.Selected`; broader `Sites.ReadWrite.All`
and directory permissions should be used only in a dedicated non-production test
tenant when required by the chosen scenario.

For the group-membership scenario, also create one dedicated AccessProof test group
outside normal production groups. Configure `advanced_directory_mode`,
`test_group_id`, and `test_group_email`. The group must be used only for this test.
AccessProof never creates arbitrary Entra groups and refuses to alter a group other
than the configured test group.

Store a delegated Graph access token for each test identity in **Test identities**.
Alice and Bob need access tokens for the same tenant. AccessProof uses Alice's
delegated token to request the created file content after revocation; a Graph
`403` or `404` proves effective source denial. Rate limits, timeouts, and `5xx`
responses are transient and do not count as denial.

## Direct-access run

1. Connect the Microsoft 365 source using the dedicated folder.
2. Create Alice and Bob test identities with their stable Entra object IDs and
   encrypted delegated tokens.
3. Create a suite using direct permission revocation.
4. Select the SharePoint source, a configured RAG target, Alice, and Bob, then
   queue one run.

The run records T0 when Graph accepts the permission deletion, T1 when Alice's own
token can no longer fetch the test file, and T2 once the RAG meets the configured
stable-denial count. The important AI exposure window is T2 minus T1.

## Required Graph permissions

The exact least-privilege permission set depends on the SharePoint tenancy and
scenario. At a minimum the mutation app needs access to the selected site/library
and drive-item create, read, invite, permission-delete, and delete operations. The
group scenario additionally needs permission to add/remove members only from the
dedicated test group. Do not grant directory-wide group-management permissions to a
production app merely for testing; use a dedicated test tenant or an explicitly
scoped service principal.

AccessProof does not currently claim support for inherited-permission revocation,
cross-tenant guests, arbitrary production groups, or browser-only SSO RAGs.
