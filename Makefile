.PHONY: test demo api runner web backup build-runner

test:
	env -u PYTHONPATH PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 uv run --extra dev pytest -p pytest_asyncio.plugin

demo:
	python scripts/demo.py

api:
	uvicorn apps.api.accessproof_api.app:app --reload --port 8000

runner:
	python -m apps.runner.accessproof_runner.main

web:
	cd apps/web && npm run dev

backup:
	python scripts/database_backup.py --database-url "$${DATABASE_URL:-sqlite:///./accessproof.db}" --output accessproof-backup.dump --verify

build-runner:
	bash scripts/build-runner-linux.sh
