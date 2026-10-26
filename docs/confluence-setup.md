# Confluence setup

Confluence Cloud is configured with an explicit test space key. The adapter currently contract-tests connection validation plus synthetic page creation/deletion.

Content restrictions, space permissions and effective user access are separate concepts. The repository therefore does **not** claim direct-user revocation support yet: removing a restriction record can broaden access depending on the surrounding permission model, so a simplistic implementation would be unsafe.

Official reference:
- https://developer.atlassian.com/cloud/confluence/rest/v1/api-group-content-restrictions/
