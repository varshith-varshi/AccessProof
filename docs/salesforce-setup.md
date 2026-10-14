# Salesforce setup

Use a Salesforce sandbox, Developer Edition or scratch org for active testing. Configure a dedicated test object such as `AccessProof_Test__c` with synthetic body/canary fields.

The adapter currently contract-tests sandbox connectivity, synthetic record creation/deletion and `UserRecordAccess`-style effective read checks. Direct record-share grant/revoke is intentionally capability-gated because the appropriate share object and sharing model are customer/object specific.

Official REST API reference:
- https://developer.salesforce.com/docs/platform/api-rest/guide/intro-rest-resources.html
