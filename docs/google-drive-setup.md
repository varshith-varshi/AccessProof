# Google Drive setup

Configure an explicit test root folder in My Drive or a Shared Drive. The adapter supports synthetic file creation, direct user permission grant/revoke, permission inspection and tracked deletion.

Google Drive v3 uses:

```text
POST   /drive/v3/files/{fileId}/permissions
DELETE /drive/v3/files/{fileId}/permissions/{permissionId}
```

`supportsAllDrives=true` is used for operations that can target Shared Drives. Service accounts and domain-wide delegation must be configured explicitly; this build does not pretend a service account is equivalent to every human test identity.

Official references:
- https://developers.google.com/workspace/drive/api/reference/rest/v3/permissions/create
- https://developers.google.com/workspace/drive/api/reference/rest/v3/permissions/delete
