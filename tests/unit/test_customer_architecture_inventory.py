"""Read-only customer architecture inventory: cache discovery is never authorization."""
from __future__ import annotations

import json
from pathlib import Path

from scripts.customer_architecture_inventory import SCHEMA, discover, main


def _put(root: Path, rel: str, value: str) -> None:
    target = root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(value)


def test_hidden_multi_layer_cache_and_framework_are_inventory_candidates(tmp_path):
    _put(tmp_path, "app/main.py", """
from langchain_core.caches import InMemoryCache
from qdrant_client import QdrantClient
from openai import OpenAI
answer_cache = cachetools.TTLCache(maxsize=32, ttl=5)
""")
    _put(tmp_path, "compose.yaml", """
services:
  rag:
    image: customer-rag:1
    environment:
      REDIS_URL: "redis://private-password@redis:6379/0"
    labels:
      com.accessproof.cache.return_path: signed-manifest-guard-reauthorization/v1
  redis:
    image: redis:7
  memcached:
    image: memcached:1
""")
    result = discover(tmp_path)
    assert result["schema"] == SCHEMA
    assert result["certification_status"] == "NOT_CERTIFIED"
    assert result["cache_inventory_state"] == "CANDIDATES_FOUND_UNVERIFIED"
    assert result["cache_return_path_declared"] is True
    assert {"redis", "memcached", "langchain-cache", "process-local"} <= {
        row["name"] for row in result["architecture"]["caches"]
    }
    assert any(row["name"] == "langchain" for row in result["architecture"]["frameworks"])
    assert any(row["name"] == "qdrant" for row in result["architecture"]["vectors"])
    assert "CUSTOMER_ROUTE_AND_CACHE_COVERAGE_NOT_VERIFIED" in result["blockers"]
    assert "private-password" not in json.dumps(result)
    assert "redis://private-password" not in json.dumps(result)


def test_no_cache_unknown_without_explicit_assertion(tmp_path):
    _put(tmp_path, "app.py", "print('hello')")
    result = discover(tmp_path)
    assert result["cache_inventory_state"] == "UNKNOWN"
    assert any("CACHE_DISCOVERY_UNKNOWN" in item for item in result["blockers"])
    assert result["coverage"]["cache_return_paths"] == "NOT_VERIFIED"


def test_explicit_no_cache_is_declared_not_certified(tmp_path):
    _put(tmp_path, "docker-compose.yml", """
services:
  rag:
    image: customer-app:1
    labels:
      com.accessproof.cache.mode: none
""")
    result = discover(tmp_path)
    assert result["cache_inventory_state"] == "NO_CACHE_DECLARED_UNVERIFIED"
    assert result["certification_status"] == "NOT_CERTIFIED"
    assert result["coverage"]["response_routes"] == "NOT_VERIFIED"


def test_conflicting_cache_declaration_is_flagged(tmp_path):
    _put(tmp_path, "compose.yml", """
services:
  rag:
    image: customer-rag:1
    labels:
      com.accessproof.cache.mode: none
  redis:
    image: redis:7
""")
    result = discover(tmp_path)
    assert "CACHE_DECLARATION_CONTRADICTS_DISCOVERY" in result["blockers"]


def test_secret_files_symlink_and_code_not_executed(tmp_path):
    marker = tmp_path / "execution.marker"
    _put(tmp_path, "app.py", f"open({str(marker)!r}, 'w').write('oops')")
    _put(tmp_path, ".env", "PASSWORD=super-secret-unique-marker")
    _put(tmp_path, "secret-settings.py", "print('super-secret-unique-marker')")
    outside = tmp_path.parent / (tmp_path.name + "-external.py")
    outside.write_text("open('should-never-run','w')")
    (tmp_path / "linked.py").symlink_to(outside)
    result = discover(tmp_path)
    assert result["customer_code_executed"] is False
    assert result["network_connections_made"] is False
    assert "super-secret-unique-marker" not in json.dumps(result)
    assert "linked.py" not in json.dumps(result)
    assert not marker.exists()
    outside.unlink()


def test_broken_compose_is_an_uncertainty_not_no_cache(tmp_path):
    _put(tmp_path, "compose.yml", "services:\n  rag: [not a service mapping]")
    result = discover(tmp_path)
    assert any("UNREVIEWABLE_COMPOSE" in item for item in result["parse_warnings"])
    assert result["cache_inventory_state"] == "UNKNOWN"


def test_cli_writes_private_report_without_overwriting(tmp_path, capsys):
    _put(tmp_path, "app.py", "import redis")
    output = tmp_path / "report.json"
    assert main([str(tmp_path), "--output", str(output)]) == 0
    assert output.stat().st_mode & 0o777 == 0o600
    report = json.loads(output.read_text())
    assert report["certification_status"] == "NOT_CERTIFIED"
    assert main([str(tmp_path), "--output", str(output)]) == 2
    assert "OUTPUT_EXISTS_OR_UNSAFE" in capsys.readouterr().out


def test_config_manifests_only_emit_recognized_keys_not_values(tmp_path):
    _put(tmp_path, "compose.yml", """
services:
  rag:
    environment:
      DATABASE_URL: "postgresql://very-private-secret"
      REDIS_URL: "redis://very-private-secret"
      RANDOM_AUTHENTICATION_SECRET: "sensitive-information"
""")
    result = discover(tmp_path)
    assert set(result["configuration_key_names_observed"]) == {"DATABASE_URL", "REDIS_URL"}
    assert "very-private-secret" not in json.dumps(result)
    assert "sensitive-information" not in json.dumps(result)


def test_symlink_directories_are_not_followed(tmp_path):
    outside = tmp_path.parent / (tmp_path.name + "-untrusted-tree")
    outside.mkdir()
    _put(outside, "cache.py", "import redis\nSECRET_VALUE = 'never-read-external'\n")
    (tmp_path / "customer-linked-dependency").symlink_to(outside, target_is_directory=True)
    result = discover(tmp_path)
    assert result["cache_inventory_state"] == "UNKNOWN"
    assert "customer-linked-dependency" not in json.dumps(result)
    assert "never-read-external" not in json.dumps(result)
    (tmp_path / "customer-linked-dependency").unlink()
    (outside / "cache.py").unlink()
    outside.rmdir()


def test_missing_yaml_parser_never_claims_compose_has_no_cache(tmp_path, monkeypatch):
    from scripts import customer_architecture_inventory as inventory
    _put(tmp_path, "compose.yml", "services:\n  redis:\n    image: redis:7\n")
    monkeypatch.setattr(inventory, "yaml", None)
    result = inventory.discover(tmp_path)
    assert result["cache_inventory_state"] == "CANDIDATES_FOUND_UNVERIFIED"
    assert "compose.yml:PY_YAML_REQUIRED" in result["parse_warnings"]
    assert result["certification_status"] == "NOT_CERTIFIED"
