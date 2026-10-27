# Customer onboarding

1. Create an organization and administrator through web-v2.
2. Enroll a customer-hosted Guard and wait for a healthy heartbeat.
3. Connect Google Workspace through the server OAuth workflow.
4. Set a narrow Drive root boundary and validate the source.
5. Configure employee/group synchronization and confirm expected effective access.
6. Register the customer RAG application and use its adapter to call the local Guard before retrieval or generation.
7. Pass the authenticated principal and canonical retrieved document IDs to the Guard; enforce deny responses before generating an answer.
8. Exercise positive access, direct revoke, group revoke, nested group, inherited folder, shared-drive and stale-cache tests in staging.
9. Enable protection only after the live checklist and customer change-control approval.
