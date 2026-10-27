# Guard installation, release and rollback

The customer-side Guard, policy cache, enrollment and heartbeat implementations were preserved. No semver release was built, signed or distributed as part of this continuation. No Docker restart, server deployment or machine credential regeneration occurred.

Before pilot: rebuild Guard release from an isolated, clean tagged branch; verify SDK/Guard version compatibility, encrypted enrollment secret storage, non-root container user, restricted listening address, state volume security, machine credential permissions, correct SHA-256 sidecar, no `.env`/SQLite/JWT/keys in bundle and rollback to previous version.

Run the new challenge protocol only once implemented. Verify control plane denies Protect on older Guard/SDK that cannot attest protected route/complete provenance and that policy sync health failures produce a safe deny. Test local Linux startup; Windows/macOS unsupported in this test run. Production service must be 24/7 independently of the browser/laptop session, with durable database and Redis.
