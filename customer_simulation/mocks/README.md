# External-boundary doubles

The committed tests use `httpx.MockTransport` and injectable provider classes rather than a parallel fake authorization engine. This is intentional: Drive, Directory, OAuth, and IdP responses cross the same adapter code used by AccessProof. The provider-fidelity report records semantics not faithfully emulated locally.
