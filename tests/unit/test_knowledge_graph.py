"""Schema, link, workflow and rendered-view regression checks for the AI knowledge graph."""
from __future__ import annotations

import copy
import json

from scripts.validate_knowledge_graph import (
    DIAGRAM_PATH,
    GRAPH_PATH,
    render_mermaid,
    validate,
)


def _graph() -> dict:
    return json.loads(GRAPH_PATH.read_text(encoding="utf-8"))


def test_knowledge_graph_matches_repo() -> None:
    graph = _graph()
    assert validate(graph) == []
    assert DIAGRAM_PATH.read_text(encoding="utf-8") == render_mermaid(graph)


def test_knowledge_graph_rejects_dangling_edges() -> None:
    graph = copy.deepcopy(_graph())
    graph["edges"].append({"from": "gateway", "to": "does_not_exist", "type": "routes_to"})
    assert any("dangling" in e for e in validate(graph))


def test_knowledge_graph_rejects_missing_source_paths() -> None:
    graph = copy.deepcopy(_graph())
    graph["nodes"][0]["source_paths"] = ["DOES_NOT_EXIST_knowledge_graph.md"]
    assert any("missing/unsafe source path" in e for e in validate(graph))


def test_knowledge_graph_rejects_duplicate_nodes() -> None:
    graph = copy.deepcopy(_graph())
    graph["nodes"].append(copy.deepcopy(graph["nodes"][0]))
    assert any("duplicate node id" in e for e in validate(graph))


def test_knowledge_graph_rejects_diagram_drift() -> None:
    graph = copy.deepcopy(_graph())
    graph["diagram"]["edges"].append(["gateway", "entra"])
    assert any("diagram edge not present" in e for e in validate(graph))


def test_knowledge_graph_protect_rules_not_regressed() -> None:
    graph = _graph()
    content = " ".join(graph["guardrails"]).lower()
    assert "owner approval" in content
    assert "enable protection" in content
    assert "source/guard/gateway" in content
    assert "not" in content and "kms" in content
