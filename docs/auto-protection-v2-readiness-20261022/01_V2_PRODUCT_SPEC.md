# V2 customer experience — honest current behavior

**Intended flow:** connect exactly one Google Drive/SharePoint/OneDrive authorization source, install/enroll a customer-side Guard beside the existing RAG service, register one application with a supported SDK adapter, and click **Enable Protection**. Once real trusted checks pass, the Guard must acknowledge the installed Protect policy before the UI shows active.

**Implemented in `web-v2`:** AI applications list uses **Enable Protection**, removes the manually entered 3 audit request IDs and buffering checkbox, maps legacy machine mode jargon to human-readable protection status, and presents an accessible step panel with blockers and Retry. The automatic preflight performs registered app/Guard/source/freshness checks, writes one idempotent tenant-scoped run, and never reports Protect on a button click.

**Not yet working end to end:** no enrolled customer-side challenge worker, route manifest, signed machine proof of the real customer RAG release boundary or unattended attempt completion. Until then the UI states **Action required**. The current implementation is a secure partial V2 foundation, not 'one-click automatically active'.

**Label contract:** Protection not enabled / Checking integration / Action required / Protection needs attention. Protected should only appear after a verified route check and Guard policy acknowledgement; at present certification is not obtainable. Single-source only, and no public callback to a private customer RAG.
