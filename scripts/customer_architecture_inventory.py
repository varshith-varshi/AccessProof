"""Read-only customer-side architecture and cache inventory (never a security certificate).

Consumes bounded source/config files without importing or executing customer code,
opening network sockets, inspecting secrets, or altering the deployment. Outputs
only recognized technology names, evidence file:line references and statuses;
never emits environment values, prompts, or customer document content.

The result is *discovery*, not proof that every return path is intercepted.
"""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # The optional local discovery utility must not break core Gateway.
    yaml = None

from scripts.compatibility_scan import payload as compatibility_payload, scan as compatibility_scan

SCHEMA = "accessproof.architecture_inventory/v1"
_MAX_CONFIG_BYTES = 512 * 1024
_IGNORED = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", ".next",
    "dist", "build", "vendor", "test", "tests", "archive", "backups",
}
_COMPOSE_NAMES = {
    "compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml",
    "compose.prod.yml", "compose.prod.yaml", "docker-compose.prod.yml",
    "docker-compose.prod.yaml",
}
_FRAMEWORKS = {
    "langchain": re.compile(r"\b(?:langchain(?:_[A-Za-z0-9]+)*|langgraph)\b", re.I),
    "llamaindex": re.compile(r"\b(?:llama_index|llama-index)\b", re.I),
    "haystack": re.compile(r"\b(?:haystack|farm-haystack|haystack-ai)\b", re.I),
    "semantic-kernel": re.compile(r"\b(?:semantic_kernel|semantic-kernel)\b", re.I),
}
_CACHES = {
    "redis": re.compile(r"\b(?:redis|rediss|ioredis|redis-py)\b", re.I),
    "memcached": re.compile(r"\b(?:memcached|pymemcache|python-memcached)\b", re.I),
    "postgresql": re.compile(r"\b(?:postgresql|pg8000|asyncpg|psycopg)\b", re.I),
    "sqlite": re.compile(r"\b(?:sqlite|aiosqlite)\b", re.I),
    "langchain-cache": re.compile(r"\b(?:InMemoryCache|RedisCache|SQLiteCache|set_llm_cache|BaseCache)\b"),
    "semantic-cache": re.compile(r"\b(?:GPTCache|gptcache|semantic[_ -]?cache|MomentoCache)\b", re.I),
    "process-local": re.compile(r"\b(?:functools\.lru_cache|functools\.cache|cachetools|TTLCache|lru_cache|@cache)\b"),
}
_VECTORS = {
    "pgvector": re.compile(r"\bpgvector\b", re.I),
    "qdrant": re.compile(r"\bqdrant(?:_[A-Za-z0-9]+)*\b", re.I),
    "pinecone": re.compile(r"\bpinecone\b", re.I),
    "faiss": re.compile(r"\bfaiss\b", re.I),
    "chroma": re.compile(r"\bchromadb?\b", re.I),
    "weaviate": re.compile(r"\bweaviate\b", re.I),
    "milvus": re.compile(r"\bmilvus\b", re.I),
    "elasticsearch": re.compile(r"\b(?:elasticsearch|opensearch)\b", re.I),
}
_MODELS = {
    "openai-compatible": re.compile(r"\b(?:openai|vllm|ollama|litellm|llama_cpp|llama-cpp)\b", re.I),
    "anthropic": re.compile(r"\b(?:anthropic|claude)\b", re.I),
    "gemini": re.compile(r"\b(?:gemini|generativeai|google_genai|google-genai)\b", re.I),
}
# Paths and common code/dependency manifests only: credentials are deliberately skipped.
_TEXT_EXTS = {".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".toml"}
_CODE_NAMES = {"requirements.txt", "package.json", "pyproject.toml"}
_ENV_REFERENCE_KEYS = {
    "ACCESSPROOF_DEMO_CACHE_BACKEND", "ACCESSPROOF_DEMO_CACHE_URL",
    "ACCESSPROOF_DEMO_CACHE_MEMCACHED_HOST", "ACCESSPROOF_DEMO_CACHE_SQLALCHEMY_URL",
    "REDIS_URL", "CACHE_REDIS_URL", "MEMCACHED_HOST", "CACHE_BACKEND",
    "CACHE_URL", "DATABASE_URL", "ACCESSPROOF_GATEWAY_MODEL_PROVIDER",
}
# No env/config *values* are included in result; only selected key names are allowed.
_SECRET_FILE = re.compile(r"(?:^\.env|secret|credential|private|password|token|\.key$|\.pem$|\.p12$|\.pfx$)", re.I)


def _files(root: Path) -> list[Path]:
    found: list[Path] = []
    # Prune dependency and secret directories BEFORE descending into them.
    # Path.rglob() plus post-filtering would still crawl large node_modules and
    # hidden trees, making inspection unpredictably slow for real customers.
    for current, directories, filenames in os.walk(root, followlinks=False):
        directories[:] = sorted(
            name for name in directories
            if name not in _IGNORED and not name.startswith(".")
            and not _SECRET_FILE.search(name)
            and not (Path(current) / name).is_symlink()
        )
        for name in sorted(filenames):
            if _SECRET_FILE.search(name) or name.startswith("."):
                continue
            entry = Path(current) / name
            if entry.suffix.lower() not in _TEXT_EXTS and name not in _CODE_NAMES and name not in _COMPOSE_NAMES:
                continue
            try:
                if entry.is_symlink() or not entry.is_file() or entry.stat().st_size > _MAX_CONFIG_BYTES:
                    continue
            except OSError:
                continue
            found.append(entry)
            if len(found) >= 5000:
                return found
    return found


def _component(kind: str, name: str, evidence: str, confidence: str = "POSSIBLE") -> dict[str, str]:
    return {
        "type": kind, "name": name, "evidence": evidence,
        "confidence": confidence, "authorization_coverage": "NOT_VERIFIED",
    }


def _safe_env_keys(value: Any) -> set[str]:
    if isinstance(value, dict):
        return {key for key in value if isinstance(key, str) and key in _ENV_REFERENCE_KEYS}
    if isinstance(value, list):
        return {item.split("=", 1)[0] for item in value if isinstance(item, str)
                and item.split("=", 1)[0] in _ENV_REFERENCE_KEYS}
    return set()


def discover(root: Path) -> dict[str, Any]:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("CUSTOMER_RAG_ROOT_NOT_DIRECTORY")
    scanner = compatibility_payload(root, compatibility_scan(root))
    found: dict[str, list[dict[str, str]]] = {
        "frameworks": [], "caches": [], "vectors": [], "models": [], "deployments": [],
    }
    env_key_names: set[str] = set()
    declared_no_cache = False
    declared_cache_return = False
    parse_warnings: list[str] = []
    for file in _files(root):
        evidence = file.relative_to(root).as_posix()
        try:
            raw = file.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            parse_warnings.append(evidence + ":UNREADABLE")
            continue
        for section, patterns in (
            ("frameworks", _FRAMEWORKS), ("caches", _CACHES),
            ("vectors", _VECTORS), ("models", _MODELS),
        ):
            for name, pattern in patterns.items():
                match = pattern.search(raw)
                if match:
                    line_number = raw.count("\n", 0, match.start()) + 1
                    found[section].append(_component(section[:-1], name, f"{evidence}:{line_number}"))
        if file.name in _COMPOSE_NAMES:
            if yaml is None:
                parse_warnings.append(evidence + ":PY_YAML_REQUIRED")
                continue
            try:
                data = yaml.safe_load(raw)
            except yaml.YAMLError:
                parse_warnings.append(evidence + ":INVALID_COMPOSE")
                continue
            if (not isinstance(data, dict) or not isinstance(data.get("services"), dict)
                    or any(not isinstance(item, dict) for item in data["services"].values())):
                parse_warnings.append(evidence + ":UNREVIEWABLE_COMPOSE")
                continue
            found["deployments"].append(_component("deployment", "docker-compose", evidence, "DECLARED"))
            for service_name, value in data["services"].items():
                if not isinstance(service_name, str) or not isinstance(value, dict):
                    continue
                # Only a fixed vocabulary of technology matches can appear in output.
                descriptor = service_name + " " + str(value.get("image", ""))[:250]
                env_key_names.update(_safe_env_keys(value.get("environment")))
                labels = value.get("labels", {})
                if isinstance(labels, list):
                    labels = {entry.split("=", 1)[0]: entry.split("=", 1)[1]
                              for entry in labels if isinstance(entry, str) and "=" in entry}
                if isinstance(labels, dict):
                    if labels.get("com.accessproof.cache.mode") == "none":
                        declared_no_cache = True
                    if labels.get("com.accessproof.cache.return_path") == "signed-manifest-guard-reauthorization/v1":
                        declared_cache_return = True
                for name, pattern in _CACHES.items():
                    if pattern.search(descriptor):
                        found["caches"].append(_component("cache", name, evidence, "DECLARED"))
                for name, pattern in _MODELS.items():
                    if pattern.search(descriptor):
                        found["models"].append(_component("model", name, evidence, "DECLARED"))
        if file.name in {"deployment.yaml", "deployment.yml", "kustomization.yaml", "Chart.yaml"}:
            found["deployments"].append(_component("deployment", "kubernetes-possible", evidence))
        if file.name == "serverless.yml":
            found["deployments"].append(_component("deployment", "serverless-possible", evidence))
        # Never inspect or disclose configuration values; these names alone are insufficient.
        for key in _ENV_REFERENCE_KEYS:
            if re.search(r"\b" + re.escape(key) + r"\b", raw):
                env_key_names.add(key)

    # Backend hints are not proof of an answer cache: Redis/PostgreSQL often store
    # sessions, queues or vectors. Never report "none" without an explicit assertion.
    if "ACCESSPROOF_DEMO_CACHE_URL" in env_key_names or "CACHE_REDIS_URL" in env_key_names:
        found["caches"].append(_component("cache", "redis", "configuration:key-name", "CONFIGURED"))
    if "ACCESSPROOF_DEMO_CACHE_MEMCACHED_HOST" in env_key_names:
        found["caches"].append(_component("cache", "memcached", "configuration:key-name", "CONFIGURED"))
    if "ACCESSPROOF_DEMO_CACHE_SQLALCHEMY_URL" in env_key_names:
        found["caches"].append(_component("cache", "postgresql", "configuration:key-name", "CONFIGURED"))

    for section in found:
        unique = {(item["name"], item["evidence"]): item for item in found[section]}
        found[section] = sorted(unique.values(), key=lambda item: (item["name"], item["evidence"]))[:300]

    cache_candidates = found["caches"]
    if cache_candidates:
        cache_state = "CANDIDATES_FOUND_UNVERIFIED"
    elif declared_no_cache:
        cache_state = "NO_CACHE_DECLARED_UNVERIFIED"
    else:
        cache_state = "UNKNOWN"
    blockers = list(scanner["certification_blockers"])
    if cache_state == "UNKNOWN":
        blockers.append("CACHE_DISCOVERY_UNKNOWN: no inspected signal proves the absence of answer caches")
    if declared_no_cache and cache_candidates:
        blockers.append("CACHE_DECLARATION_CONTRADICTS_DISCOVERY")
    if cache_candidates and not declared_cache_return:
        blockers.append("CACHE_RETURN_PATH_UNVERIFIED: signed return-path contract not declared")
    # Even if declared, a return-path label does not attest runtime interception.
    blockers.append("CUSTOMER_ROUTE_AND_CACHE_COVERAGE_NOT_VERIFIED")
    blockers = list(dict.fromkeys(blockers))
    return {
        "schema": SCHEMA,
        "certification_status": "NOT_CERTIFIED",
        "customer_traffic_changed": False,
        "customer_code_executed": False,
        "network_connections_made": False,
        "source_scan": scanner,
        "architecture": found,
        "cache_inventory_state": cache_state,
        "cache_return_path_declared": declared_cache_return,
        "no_cache_declared": declared_no_cache,
        "configuration_key_names_observed": sorted(env_key_names),
        "parse_warnings": parse_warnings[:100],
        "coverage": {
            "retrieval_provenance": "NOT_VERIFIED",
            "llm_egress": "NOT_VERIFIED",
            "cache_return_paths": "NOT_VERIFIED",
            "response_routes": "NOT_VERIFIED",
            "identity_mapping": "NOT_VERIFIED",
            "revocation": "NOT_VERIFIED",
        },
        "blockers": blockers,
        "next_actions": [
            "Review every detected cache and route with the customer; UNKNOWN never means no cache.",
            "Install signed cache manifests on each answer return path; test unauthorized and revoked users.",
            "Use a customer-approved enrolled Guard and live route challenges before Protect.",
            "Verify runtime model egress and alternate API/worker/WebSocket paths separately.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="Authorized local customer RAG source root")
    parser.add_argument("--output", type=Path, help="Optional private JSON report output (new file only)")
    args = parser.parse_args(argv)
    try:
        report = discover(args.root)
    except (ValueError, OSError) as exc:
        print(json.dumps({"error": type(exc).__name__}))
        return 2
    serialized = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        dest = args.output
        if dest.is_symlink() or dest.exists():
            print(json.dumps({"error": "OUTPUT_EXISTS_OR_UNSAFE"}))
            return 2
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(serialized + "\n")
        print(json.dumps({"schema": SCHEMA, "report_file": str(dest), "certification_status": "NOT_CERTIFIED"}))
    else:
        print(serialized)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
