# Pilot runbook

1. Create workspace and sign in to web-v2. 2. Connect a least-privilege Google Drive root and separate Directory scope if group ACLs are required. 3. Validate ACL and directory health. 4. Register the RAG application with its exact source and adapter. 5. Enrol a Guard next to the RAG. 6. Integrate the SDK around every retrieval/tool/cache-to-model route and buffer output. 7. Start in Shadow, inspect evidence, then enable Protect only after Guard policy and source freshness are healthy. 8. Run allowed, denied, and revoke controls in a disposable folder.
