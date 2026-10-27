# Local architecture

Synthetic provider-shaped data → real AccessProof ACL/directory/policy pipeline → real Guard HTTP API → real Python RAG SDK → deterministic fake generation. The integration tests use loopback TCP for control-plane/Guard/RAG boundaries. Google Drive, Directory, IdP, and LLM external endpoints are mocked only at their network contracts.
