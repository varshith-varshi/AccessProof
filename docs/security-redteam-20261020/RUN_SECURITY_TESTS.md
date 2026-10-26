# Reproduce the AccessProof local security audit

All commands below run from the tested snapshot directory. **No production credentials or customer endpoints.** Do not load live .env files.

```bash
cd /tmp/accessproof-redteam-20261020/repo
TMPDIR=/dev/shm env -u PYTHONPATH PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -p pytest_asyncio.plugin -q
.venv/bin/ruff check apps connectors packages tests
.venv/bin/python security_review/benchmark_guard_cache.py
cd web-v2
npm run lint
npm run typecheck
npm run build -- --webpack
npm run test:e2e -- --config playwright.redteam.config.ts
cd ..
PATH="$PWD/web-v2/node_modules/.bin:$PATH" npm --prefix packages/rag-sdk-typescript test
```

The snapshot uses symlinked Python/node dependency installations from the active checkout for offline tests. The browser test config uses an isolated `127.0.0.1:3011` Webpack dev server and mocked API responses. Default Turbopack cannot build from this snapshot symlink; the Webpack path passed.

For a **real** customer RAG or Google Drive test, first obtain written customer consent and a dedicated synthetic sandbox. Do not treat local tests as production certification. Preserve/report failed cases before changing code.