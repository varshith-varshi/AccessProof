#!/usr/bin/env python3
"""Read-only, evidence-oriented compatibility scan for a customer RAG tree.

The scanner never imports or executes target code, never follows symlinks, skips
secret-bearing files, and emits file:line evidence only - never source lines,
credentials, prompts or document content. Its output can qualify an integration
discussion, but it can never certify an integration by itself.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import hashlib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

SCANNER_SCHEMA = "accessproof.compatibility_scan/v1"
SCANNER_VERSION = "0.1.0"
_TEXT_SUFFIXES = {".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}
_SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "dist", "build",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".next", "coverage",
    "tests", "test", "__tests__", "vendor",
}
_ARCHIVE_DIR_NAMES = {"archive", "archives", "snapshot", "snapshots", "backup", "backups", "old"}
_SKIP_NAMES = re.compile(
    r"(^\.env($|\.)|\.pem$|\.key$|\.p12$|\.pfx$|id_rsa|secrets?\.|credentials?\.)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Finding:
    type: str
    status: str
    evidence: str
    reason: str

    @property
    def confidence(self) -> str:
        # Static matching is evidence, never a proof of a runtime bypass.
        return "HIGH" if self.status == "UNSUPPORTED" else "MEDIUM" if self.status == "PARTIAL" else "LOW"

    @property
    def finding_id(self) -> str:
        normalized = "|".join((self.type, self.status, self.evidence, self.reason))
        return "APCS-" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:12]


@dataclass
class ScanResult:
    files_scanned: int = 0
    skipped_large: int = 0
    skipped_secret: int = 0
    identity: list[Finding] = field(default_factory=list)
    routes: list[Finding] = field(default_factory=list)
    model_paths: list[Finding] = field(default_factory=list)
    cache_paths: list[Finding] = field(default_factory=list)
    retrieval: list[Finding] = field(default_factory=list)
    provenance: list[Finding] = field(default_factory=list)
    tool_paths: list[Finding] = field(default_factory=list)
    route_classes: list[Finding] = field(default_factory=list)
    bypass_findings: list[Finding] = field(default_factory=list)
    certification_blockers: list[str] = field(default_factory=list)
    artifacts_examined: list[str] = field(default_factory=list)

    def blocker(self, value: str) -> None:
        if value not in self.certification_blockers:
            self.certification_blockers.append(value)


_ROUTE_PATTERNS = (
    re.compile(r"^\s*@(?:app|router|bp)\.(get|post|put|patch|delete)\(\s*[\"']([^\"']{1,200})"),
    re.compile(r"^\s*(?:app|router|server)\.(get|post|put|patch|delete)\(\s*[\"']([^\"']{1,200})"),
    re.compile(r"^\s*(?:def|async\s+def)\s+([A-Za-z_][A-Za-z0-9_]{1,80})\s*\([^)]*\)\s*:\s*$"),
)
_AI_HINT = re.compile(
    r"(chat|rag|ask|query|retriev|completion|answer|search|agent|assistant|prompt)",
    re.IGNORECASE,
)
_STREAMING = re.compile(r"(StreamingResponse|text/event-stream|EventSource|ReadableStream|yield\s+)")
_WEBSOCKET = re.compile(r"(WebSocket|websocket|socket\.io|SocketIO)")
_ACCESS_PROOF = re.compile(
    r"(accessproof|ProtectedRAG|GuardClient|RAGAdapter|verify_cached_answer|check_output|authorization_scope)",
    re.IGNORECASE,
)
_IDENTITY = re.compile(
    r"(JWKS|jwks|OIDC|oidc|jwt\.decode|jose\.jwt|Authorization.*Bearer|Bearer\s*\$|Bearer\s*\{)",
)
_PROVENANCE = re.compile(
    r"(resource_id|source_id|chunk_id|content_attestation|content_version|document_id)",
)
_PROMPT = re.compile(r"(PromptTemplate|ChatPromptTemplate|messages\s*=|prompt\s*=)", re.IGNORECASE)
_MODEL_PROVIDERS = (
    ("openai", re.compile(r"(from\s+openai|import\s+openai|api\.openai\.com|openai\.(OpenAI|AsyncOpenAI)|chat\.completions)")),
    ("anthropic", re.compile(r"(from\s+anthropic|import\s+anthropic|api\.anthropic\.com|anthropic\.(Anthropic|AsyncAnthropic))")),
    ("gemini", re.compile(r"(google\.generativeai|generativelanguage\.googleapis\.com|genai\.GenerativeModel)")),
)
_DIRECT_MODEL_HOST = re.compile(
    r"(api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com)"
)
_VECTOR = re.compile(
    r"(pgvector|pinecone|chromadb?|faiss|qdrant|weaviate|milvus|elasticsearch|vector\s*search|similarity_search)",
    re.IGNORECASE,
)
_SCOPED_RETRIEVAL = re.compile(
    r"(allowed_resource_ids|authorization[_ -]?scope|document_id\s*=\s*ANY|resource_id\s+IN|WHERE.*tenant_id)",
    re.IGNORECASE,
)
_CACHE = re.compile(r"(redis|memcache|redis\.Redis|sqlalchemy.*cache|cache\.get|cache\.set)", re.IGNORECASE)
_CACHE_REAUTH = re.compile(
    r"(verify_cached_answer|authorize_cached|authorization_revision|ProtectedRAG|GuardClient)",
    re.IGNORECASE,
)
_TOOLS = re.compile(r"(@tool|Tool\(|AgentExecutor|function_call|tool_calls|mcp_server|ModelContextProtocol)")
_BACKGROUND = re.compile(r"(Celery|celery|BackgroundTasks|dramatiq|rq\.Queue|enqueue\()")


def _iter_files(
    root: Path, max_bytes: int, skipped: dict[str, int], excluded_dirs: set[str],
) -> Iterable[tuple[Path, str]]:
    for current, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(
            name for name in dirnames
            if name not in _SKIP_DIRS and name not in excluded_dirs and not name.startswith(".")
        )
        for name in sorted(filenames):
            path = Path(current) / name
            if _SKIP_NAMES.search(name):
                skipped["secret"] = skipped.get("secret", 0) + 1
                continue
            if path.suffix.lower() not in _TEXT_SUFFIXES:
                continue
            if path.is_symlink():
                continue
            try:
                if path.stat().st_size > max_bytes:
                    yield path, ""
                    continue
                raw = path.read_bytes()
            except OSError:
                continue
            if b"\x00" in raw[:4096]:
                continue
            yield path, raw.decode("utf-8", errors="replace")


def _evidence(root: Path, path: Path, line: int) -> str:
    try:
        relative = path.relative_to(root)
    except ValueError:
        relative = Path(path.name)
    return f"{relative.as_posix()}:{line}"


def scan(
    root: Path, *, max_files: int = 5000, max_bytes: int = 512 * 1024,
    excluded_dirs: Iterable[str] = _ARCHIVE_DIR_NAMES,
) -> ScanResult:
    root = root.resolve()
    if not root.is_dir():
        raise ValueError("SCAN_ROOT_NOT_A_DIRECTORY")
    result = ScanResult()
    skipped = {"secret": 0}
    clean_exclusions = {item.strip() for item in excluded_dirs if item and item.strip()}
    for path, text in _iter_files(root, max_bytes, skipped, clean_exclusions):
        result.skipped_secret = skipped["secret"]
        if result.files_scanned >= max_files:
            result.blocker("SCAN_FILE_LIMIT_REACHED")
            break
        if not text:
            if path.stat().st_size > max_bytes:
                result.skipped_large += 1
            continue
        result.files_scanned += 1
        if len(result.artifacts_examined) < 200:
            result.artifacts_examined.append(_evidence(root, path, 1).rsplit(":", 1)[0])
        lines = text.splitlines()
        accessproof_present = bool(_ACCESS_PROOF.search(text))
        file_cache_reauth = bool(_CACHE_REAUTH.search(text))

        identity_seen = False
        provenance_seen = False
        prompt_seen = False
        vector_seen = False
        scoped_retrieval = False
        cache_seen = False
        tool_seen = False
        websocket_seen = False
        background_seen = False
        streaming_seen = False
        direct_model = False
        providers: set[str] = set()

        for number, line in enumerate(lines, start=1):
            evidence = _evidence(root, path, number)
            if _IDENTITY.search(line):
                identity_seen = True
                result.identity.append(Finding(
                    "identity", "SUPPORTED" if accessproof_present else "PARTIAL",
                    evidence,
                    "OIDC/bearer identity pattern detected; verify issuer, audience, tenant and source mapping.",
                ))
            if _PROVENANCE.search(line):
                provenance_seen = True
                result.provenance.append(Finding(
                    "provenance", "SUPPORTED" if accessproof_present else "PARTIAL",
                    evidence,
                    "Stable resource/chunk metadata detected; verify it originates from trusted ingestion.",
                ))
            if _PROMPT.search(line):
                prompt_seen = True
            if _VECTOR.search(line):
                vector_seen = True
                result.retrieval.append(Finding(
                    "retrieval", "PARTIAL", evidence,
                    "Vector retrieval detected; static scanning cannot prove the authorization predicate runs in the datastore.",
                ))
            if _SCOPED_RETRIEVAL.search(line):
                scoped_retrieval = True
            if _CACHE.search(line):
                cache_seen = True
            if _TOOLS.search(line):
                tool_seen = True
                result.tool_paths.append(Finding(
                    "tool_or_agent", "UNSUPPORTED", evidence,
                    "Tool/agent action path is outside the protected RAG output-release boundary.",
                ))
            if _WEBSOCKET.search(line):
                websocket_seen = True
                result.route_classes.append(Finding(
                    "websocket", "UNSUPPORTED", evidence,
                    "WebSocket response path has no certification path.",
                ))
            if _BACKGROUND.search(line):
                background_seen = True
                result.route_classes.append(Finding(
                    "background_worker", "UNSUPPORTED", evidence,
                    "Background worker result path is not certified by a synchronous response gate.",
                ))
            if _STREAMING.search(line):
                streaming_seen = True
            if _DIRECT_MODEL_HOST.search(line):
                direct_model = True
            for provider, pattern in _MODEL_PROVIDERS:
                if pattern.search(line):
                    providers.add(provider)
                    result.model_paths.append(Finding(
                        provider, "PARTIAL", evidence,
                        f"{provider} client detected; live-provider conformance is per deployment.",
                    ))
            route = None
            for pattern in _ROUTE_PATTERNS:
                match = pattern.search(line)
                if match:
                    route = match.group(2) if pattern is _ROUTE_PATTERNS[0] or pattern is _ROUTE_PATTERNS[1] else None
                    break
            if route and _AI_HINT.search(route):
                status = "SUPPORTED" if accessproof_present else "PARTIAL"
                result.routes.append(Finding(
                    "route", status, evidence,
                    "AI-related route detected; confirm every response path reaches Guard Layer 2 before release."
                    if accessproof_present else
                    "AI-related route detected without an AccessProof boundary in this file.",
                ))
                if accessproof_present and streaming_seen:
                    result.bypass_findings.append(Finding(
                        "STREAMING_ROUTE", "PARTIAL", evidence,
                        "Streaming is present in a file that also references AccessProof; prove release is buffered until Layer 2.",
                    ))

        if streaming_seen:
            result.route_classes.append(Finding(
                "streaming", "PARTIAL", _evidence(root, path, 1),
                "Streaming construct detected; only buffered-release SSE is acceptable on a protected route.",
            ))
            result.blocker("Uncertified streaming response path; prove buffered Layer 2 release or keep it outside Protect.")
        if websocket_seen:
            result.blocker("Uncertified WebSocket response path.")
            result.bypass_findings.append(Finding(
                "WEBSOCKET_ROUTE", "UNSUPPORTED", _evidence(root, path, 1),
                "WebSocket route is outside the protected claim.",
            ))
        if tool_seen:
            result.blocker("Tool/agent side-effect path is not covered by RAG output authorization.")
            result.bypass_findings.append(Finding(
                "TOOL_OR_AGENT_PATH", "UNSUPPORTED", _evidence(root, path, 1),
                "Tool/agent path requires separate action authorization.",
            ))
        if background_seen:
            result.blocker("Background worker result path is not certified.")
            result.bypass_findings.append(Finding(
                "BACKGROUND_RESULT_PATH", "UNSUPPORTED", _evidence(root, path, 1),
                "Background result can bypass the synchronous release gate.",
            ))
        if cache_seen:
            status = "PARTIAL" if file_cache_reauth else "UNSUPPORTED"
            result.cache_paths.append(Finding(
                "cache", status, _evidence(root, path, 1),
                "Cache path references current-authorization checks."
                if file_cache_reauth else
                "Cache path detected without a current-authorization recheck; cache invalidation is not authorization.",
            ))
            if not file_cache_reauth:
                result.blocker("Cache return path lacks a current authorization recheck.")
                result.bypass_findings.append(Finding(
                    "CACHE_WITHOUT_REAUTH", "UNSUPPORTED", _evidence(root, path, 1),
                    "Cache hit can bypass retrieval authorization unless reauthorized at release.",
                ))
        if vector_seen and not scoped_retrieval:
            result.blocker("Vector retrieval may rely on global ANN plus post-filter; no authorization-first predicate detected.")
            result.bypass_findings.append(Finding(
                "GLOBAL_ANN_POST_FILTER_RISK", "PARTIAL", _evidence(root, path, 1),
                "Verify allowed-resource scope is applied inside the datastore query.",
            ))
        if direct_model:
            result.blocker("Direct model provider endpoint is reachable outside the Gateway.")
            result.bypass_findings.append(Finding(
                "DIRECT_MODEL_ENDPOINT", "UNSUPPORTED", _evidence(root, path, 1),
                "A direct provider host can bypass Guard unless network/egress policy blocks it.",
            ))
        if providers and not accessproof_present and not direct_model:
            result.blocker("Model client detected without an AccessProof boundary in the same artifact.")

        if identity_seen and not accessproof_present:
            result.blocker("Identity pattern exists outside a file that references the AccessProof boundary.")
        if prompt_seen and not provenance_seen:
            result.blocker("Prompt construction found without stable source/resource provenance in the same artifact.")

    return result


def _dedupe(findings: Iterable[Finding]) -> list[dict[str, str]]:
    # Multiple lines in the same execution artifact are one root-cause lead;
    # retain the first precise location rather than flooding reviewers.
    seen: set[tuple[str, str, str]] = set()
    output: list[dict[str, str]] = []
    for item in findings:
        path = item.evidence.rsplit(":", 1)[0]
        key = (item.type, item.status, path)
        if key in seen:
            continue
        seen.add(key)
        output.append({
            "type": item.type, "status": item.status,
            "evidence": item.evidence, "reason": item.reason,
            "finding_id": item.finding_id,
            "confidence": item.confidence,
            "classification": "SUSPECTED_RISK" if item.status != "UNSUPPORTED" else "STATIC_BYPASS_CANDIDATE",
        })
    return output


def payload(root: Path, result: ScanResult) -> dict[str, Any]:
    findings = {
        "identity": _dedupe(result.identity),
        "routes": _dedupe(result.routes),
        "model_paths": _dedupe(result.model_paths),
        "cache_paths": _dedupe(result.cache_paths),
        "retrieval": _dedupe(result.retrieval),
        "provenance": _dedupe(result.provenance),
        "tool_paths": _dedupe(result.tool_paths),
        "route_classes": _dedupe(result.route_classes),
    }
    status_counts = Counter(item["status"] for group in findings.values() for item in group)
    return {
        "schema": SCANNER_SCHEMA,
        "scanner": {
            "version": SCANNER_VERSION,
            "read_only": True,
            "executed_target_code": False,
            "followed_symlinks": False,
            "files_scanned": result.files_scanned,
            "skipped_large_files": result.skipped_large,
            "skipped_secret_or_key_files": result.skipped_secret,
        },
        "certification_status": "NOT_CERTIFIED",
        "certification_note": "A static read-only scan cannot certify compatibility. It identifies evidence and blockers for human review and a live route challenge.",
        **findings,
        "bypass_findings": _dedupe(result.bypass_findings),
        "certification_blockers": result.certification_blockers,
        "summary": {
            "statuses": {state: status_counts.get(state, 0) for state in (
                "SUPPORTED", "PARTIAL", "UNKNOWN", "UNSUPPORTED",
            )},
            "bypass_findings": len(_dedupe(result.bypass_findings)),
            "blockers": len(result.certification_blockers),
        },
        "artifacts_examined": result.artifacts_examined[:200],
        "limitations": [
            "Static detection only; no target code was imported or executed.",
            "Only Python/TypeScript/JavaScript text artifacts were inspected; other languages are not covered.",
            "Secret-bearing files, symlinks, tests and dependency directories were skipped.",
            "A clean scan never means SUPPORTED or CERTIFIED; a live, authenticated route challenge is still required.",
        ],
    }


def prometheus_text(data: dict[str, Any]) -> str:
    lines = [
        "# HELP accessproof_scanner_bypass_finding_total Read-only compatibility scanner bypass findings.",
        "# TYPE accessproof_scanner_bypass_finding_total counter",
    ]
    counts = Counter(item["type"] for item in data["bypass_findings"])
    for finding_type in sorted(counts):
        label = re.sub(r"[^A-Za-z0-9_:]", "_", finding_type)
        lines.append(
            f'accessproof_scanner_bypass_finding_total{{type="{label}"}} {counts[finding_type]}'
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", default=".")
    parser.add_argument("--format", choices=("json", "text", "prometheus"), default="json")
    parser.add_argument("--max-files", type=int, default=5000)
    parser.add_argument("--max-file-bytes", type=int, default=512 * 1024)
    parser.add_argument(
        "--exclude-dir", action="append", default=[],
        help="Additional directory basename to skip (repeatable). Archive-like directories are skipped by default.",
    )
    args = parser.parse_args(argv)
    if not 1 <= args.max_files <= 50_000 or not 1024 <= args.max_file_bytes <= 10 * 1024 * 1024:
        parser.error("bounds are invalid")
    try:
        result = scan(
            Path(args.path), max_files=args.max_files, max_bytes=args.max_file_bytes,
            excluded_dirs=set(_ARCHIVE_DIR_NAMES) | set(args.exclude_dir),
        )
    except ValueError as exc:
        print(json.dumps({"error": str(exc)}))
        return 2
    data = payload(Path(args.path).resolve(), result)
    if args.format == "prometheus":
        print(prometheus_text(data), end="")
    elif args.format == "text":
        print(f"CERTIFICATION_STATUS={data['certification_status']}")
        print(f"FILES_SCANNED={data['scanner']['files_scanned']}")
        for blocker in data["certification_blockers"]:
            print(f"BLOCKER={blocker}")
    else:
        print(json.dumps(data, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
