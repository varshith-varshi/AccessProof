# SharePoint / OneDrive setup

AccessProof uses Microsoft Graph v1.0 and requires an explicit `drive_id` plus `test_root_item_id`. Keep the root dedicated to synthetic AccessProof resources.

Current implemented direct-user flow:

1. upload synthetic file under the configured test root;
2. grant a user with `POST /drives/{drive-id}/items/{item-id}/invite` and `sendInvitation=false`;
3. inspect item permissions;
4. revoke the tracked permission object;
5. confirm item permission ground truth;
6. delete only the tracked synthetic item.

Microsoft documents `invite` for user sharing on SharePoint/OneDrive and `createLink` for link sharing. Do not assume inherited SharePoint permissions are equivalent to direct item permission records. Group/inheritance/share-link mutation are not marked complete in this build.

Official references:
- https://learn.microsoft.com/en-us/graph/api/driveitem-invite?view=graph-rest-1.0
- https://learn.microsoft.com/en-us/graph/api/driveitem-createlink?view=graph-rest-1.0
