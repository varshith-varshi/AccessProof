# Gateway threat model

Defended local threats include forged resource metadata, altered content, wrong tenant/application/source/resource/chunk/revision, expired or unknown signing keys, system/developer prompt injection, tool/cache-context injection, Guard failure, Layer 2 denial, oversized payloads, and direct employee-token forwarding to the model.

Not established: provider-origin proof without an authenticated provider ingestion deployment, arbitrary application bypass prevention, and real Google Workspace or Microsoft effective-permission validation.
