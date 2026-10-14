# AccessProof pilot quickstart

AccessProof tests whether a configured enterprise AI target stops exposing controlled source content after a configured source-side access change.

1. Create an organization and project in the web application.
2. Open **Runners**, select the project, generate an enrollment code, and enroll an Ubuntu runner with the packaged desktop application.
3. Create a source, test identities, and an AI target from their respective web pages. Stored credentials are encrypted and are not returned after saving.
4. Create a test suite and queue a run from **Runs**.
5. Follow the persisted timeline through source access confirmation, mutation, source denial, AI probes, stable denial, and the final SLO outcome.

For a developer-only local demonstration:

```bash
cd ~/Downloads/accessproof/f15
make demo
```

For a Linux runner package release build:

```bash
cd ~/Downloads/accessproof/f15
chmod +x scripts/build-runner-linux.sh
scripts/build-runner-linux.sh
```

The resulting package is written to `dist/`. See [runner enrollment](docs/runner-enrollment.md) and [deployment](docs/deployment.md) before a customer pilot.
