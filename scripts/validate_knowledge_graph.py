#!/usr/bin/env python3
"""Validate the checked-in architecture knowledge graph and its Mermaid view.

Offline and read-only by default. Never scans private customer data, invokes
services, probes production, or treats graph entries as security attestation.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
GRAPH_PATH = PROJECT_ROOT / "docs/knowledge-graph/graph.json"
DIAGRAM_PATH = PROJECT_ROOT / "docs/knowledge-graph/architecture.mmd"
IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]*$")
BLOCKED_PATH_PARTS = {".env", ".git", ".venv", "node_modules", "__pycache__"}
REQUIRED_NODES = {"product", "sharepoint", "entra", "rag", "api", "guard",
                  "gateway", "layer1", "layer2", "audit", "activation", "state"}


def _valid_path(raw: str) -> bool:
    p = Path(raw)
    if not raw or p.is_absolute() or ".." in p.parts:
        return False
    if any(part in BLOCKED_PATH_PARTS or part.startswith(".env") for part in p.parts):
        return False
    resolved = (PROJECT_ROOT / p).resolve()
    return resolved.is_relative_to(PROJECT_ROOT.resolve()) and resolved.exists()


def validate(graph: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if graph.get("schema") != "accessproof.knowledge_graph/v1":
        errors.append("unsupported knowledge graph schema")
    scopes = graph.get("scopes")
    if not isinstance(scopes, dict) or not scopes:
        errors.append("scopes must be a nonempty mapping")
        scopes = {}
    nodes = graph.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        return errors + ["nodes must be a nonempty list"]
    ids: set[str] = set()
    for i, node in enumerate(nodes):
        if not isinstance(node, dict):
            errors.append(f"nodes[{i}] is not an object")
            continue
        nid = node.get("id")
        if not isinstance(nid, str) or not IDENTIFIER.fullmatch(nid):
            errors.append(f"nodes[{i}] has invalid id")
            continue
        if nid in ids:
            errors.append(f"duplicate node id: {nid}")
        ids.add(nid)
        for attr in ("kind", "label", "description"):
            if not isinstance(node.get(attr), str) or not node[attr].strip():
                errors.append(f"{nid}: missing {attr}")
        if node.get("scope") not in scopes:
            errors.append(f"{nid}: unknown scope {node.get('scope')!r}")
        paths = node.get("source_paths")
        if not isinstance(paths, list) or not paths:
            errors.append(f"{nid}: no source paths")
        else:
            for path in paths:
                if not isinstance(path, str) or not _valid_path(path):
                    errors.append(f"{nid}: missing/unsafe source path {path!r}")
    if not REQUIRED_NODES.issubset(ids):
        errors.append(f"missing mandatory nodes: {sorted(REQUIRED_NODES - ids)}")

    edges = graph.get("edges")
    if not isinstance(edges, list):
        errors.append("edges must be a list")
        edges = []
    triples: set[tuple[str, str, str]] = set()
    pairs: set[tuple[str, str]] = set()
    for i, edge in enumerate(edges):
        if not isinstance(edge, dict):
            errors.append(f"edges[{i}] is not an object")
            continue
        source, target, relation = edge.get("from"), edge.get("to"), edge.get("type")
        if source not in ids or target not in ids:
            errors.append(f"edges[{i}] has dangling source or target: {source!r} -> {target!r}")
            continue
        if not isinstance(relation, str) or not IDENTIFIER.fullmatch(relation):
            errors.append(f"edges[{i}] has invalid relation")
            continue
        triple = (source, target, relation)
        if triple in triples:
            errors.append(f"duplicate edge: {triple}")
        triples.add(triple)
        pairs.add((source, target))

    workflows = graph.get("workflows")
    if not isinstance(workflows, list) or not workflows:
        errors.append("workflows must be a nonempty list")
    else:
        seen_workflows: set[str] = set()
        for workflow in workflows:
            if not isinstance(workflow, dict):
                errors.append("invalid workflow")
                continue
            wid = workflow.get("id")
            if not isinstance(wid, str) or not IDENTIFIER.fullmatch(wid) or wid in seen_workflows:
                errors.append(f"invalid/duplicate workflow id: {wid!r}")
            else:
                seen_workflows.add(wid)
            steps = workflow.get("steps")
            if not isinstance(steps, list) or len(steps) < 2 or any(step not in ids for step in steps):
                errors.append(f"workflow {wid}: missing or unknown step")
    diagram = graph.get("diagram")
    if not isinstance(diagram, dict):
        errors.append("missing diagram")
    else:
        view_ids = diagram.get("nodes")
        view_edges = diagram.get("edges")
        if not isinstance(view_ids, list) or not view_ids or any(x not in ids for x in view_ids):
            errors.append("diagram references unknown nodes")
            view_ids = []
        if not isinstance(view_edges, list):
            errors.append("diagram.edges must be a list")
        else:
            for e in view_edges:
                if not isinstance(e, list) or len(e) != 2 or not all(isinstance(x, str) for x in e):
                    errors.append(f"malformed diagram edge: {e!r}")
                    continue
                if e[0] not in view_ids or e[1] not in view_ids or tuple(e) not in pairs:
                    errors.append(f"diagram edge not present in knowledge graph: {e!r}")
    if not isinstance(graph.get("guardrails"), list) or len(graph["guardrails"]) < 3:
        errors.append("missing security guardrails")
    return errors


def render_mermaid(graph: dict[str, Any]) -> str:
    by_id = {node["id"]: node for node in graph["nodes"]}
    view = graph["diagram"]
    out = [
        "%% Generated from graph.json by scripts/validate_knowledge_graph.py.",
        "%% Do not hand-edit; run --write-diagram.",
        "%% Architecture/navigation view only, not certification evidence.",
        "flowchart LR",
    ]
    for nid in view["nodes"]:
        label = by_id[nid]["label"].replace("\\", "\\\\").replace('"', "\\\"")
        out.append(f'    {nid}["{label}"]')
    for source, target in view["edges"]:
        out.append(f"    {source} --> {target}")
    return "\n".join(out) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-diagram", action="store_true",
                        help="Regenerate checked-in Mermaid from validated JSON.")
    parser.add_argument("--validate-only", action="store_true",
                        help="Skip checked-in Mermaid sync check.")
    args = parser.parse_args()
    try:
        graph = json.loads(GRAPH_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"Invalid knowledge graph: {exc}", file=sys.stderr)
        return 1
    if not isinstance(graph, dict):
        print("Knowledge graph root must be a JSON object", file=sys.stderr)
        return 1
    problems = validate(graph)
    if problems:
        for issue in problems:
            print(f"ERROR: {issue}", file=sys.stderr)
        print(f"{len(problems)} validation errors.", file=sys.stderr)
        return 1
    output = render_mermaid(graph)
    if args.write_diagram:
        DIAGRAM_PATH.write_text(output, encoding="utf-8")
    elif not args.validate_only:
        if not DIAGRAM_PATH.exists() or DIAGRAM_PATH.read_text(encoding="utf-8") != output:
            print("Mermaid diagram drifted. Run --write-diagram.", file=sys.stderr)
            return 1
    print(f"OK: {len(graph['nodes'])} nodes, {len(graph['edges'])} edges, "
          f"{len(graph['workflows'])} workflows; source paths verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
