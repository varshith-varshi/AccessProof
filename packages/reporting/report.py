from __future__ import annotations

from typing import Any

import hashlib
import json
from dataclasses import asdict
from datetime import datetime, timezone
from packages.domain.models import EngineResult


def result_to_dict(result: EngineResult) -> dict[str, Any]:
    data = asdict(result)
    data["run_id"] = str(result.run_id)
    data["outcome"] = result.outcome.value
    for event in data["timeline"]:
        event["state"] = (
            event["state"].value if hasattr(event["state"], "value") else event["state"]
        )
        event["at"] = event["at"].isoformat()
    for obs in data["observations"]:
        obs["observed_at"] = obs["observed_at"].isoformat()
        if obs["evidence_level"] is not None and hasattr(obs["evidence_level"], "value"):
            obs["evidence_level"] = obs["evidence_level"].value
    metrics = data["metrics"]
    for key, value in list(metrics.items()):
        if hasattr(value, "isoformat"):
            metrics[key] = value.isoformat()
    ground_truth = data.get("source_ground_truth_detail")
    if ground_truth and hasattr(ground_truth.get("confirmed_at"), "isoformat"):
        ground_truth["confirmed_at"] = ground_truth["confirmed_at"].isoformat()
    if data["synthetic_resource"] is not None:
        data["synthetic_resource"]["canary"] = "REDACTED"
    data["derived"] = {
        "provider_mutation_latency_seconds": result.metrics.provider_mutation_latency_seconds,
        "initial_propagation_latency_seconds": result.metrics.initial_propagation_latency_seconds,
        "stable_propagation_latency_seconds": result.metrics.stable_propagation_latency_seconds,
        "exposure_window_seconds": result.metrics.exposure_window_seconds,
    }
    return data


def build_manifest(result: EngineResult) -> dict[str, Any]:
    payload = result_to_dict(result)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return {
        "report_id": f"APR-{result.run_id}",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "report_sha256": hashlib.sha256(canonical).hexdigest(),
        "evidence_hashes": result.evidence_hashes,
        "payload": payload,
    }


def render_html(result: EngineResult) -> str:
    d = result_to_dict(result)
    stable = d["derived"]["stable_propagation_latency_seconds"]
    return f"""<!doctype html><html><head><meta charset='utf-8'><title>AccessProof Report</title></head>
<body><h1>AccessProof Report</h1><p>Run: {d["run_id"]}</p><p>Result: <strong>{d["outcome"]}</strong></p>
<p>Expected SLO: {d["expected_slo_seconds"]} seconds</p><p>Observed stable denial: {stable}</p>
<p>Reason: {d["reason"]}</p></body></html>"""


def render_junit(result: EngineResult) -> str:
    import xml.etree.ElementTree as ET

    testsuite = ET.Element("testsuite", name="AccessProof", tests="1")
    testcase = ET.SubElement(
        testsuite, "testcase", classname="permission_regression", name=str(result.run_id)
    )
    if result.outcome.value == "FAIL":
        failure = ET.SubElement(testcase, "failure", message=result.reason)
        failure.text = result.reason
    elif result.outcome.value == "ERROR":
        error = ET.SubElement(testcase, "error", message=result.reason)
        error.text = result.reason
    elif result.outcome.value in {"INCONCLUSIVE", "PRECONDITION_FAILURE", "CANCELED"}:
        skipped = ET.SubElement(testcase, "skipped", message=result.reason)
        skipped.text = result.reason
    props = ET.SubElement(testcase, "properties")
    ET.SubElement(props, "property", name="outcome", value=result.outcome.value)
    ET.SubElement(
        props, "property", name="expected_slo_seconds", value=str(result.expected_slo_seconds)
    )
    if result.metrics.stable_propagation_latency_seconds is not None:
        ET.SubElement(
            props,
            "property",
            name="stable_propagation_latency_seconds",
            value=str(result.metrics.stable_propagation_latency_seconds),
        )
    return ET.tostring(testsuite, encoding="unicode")


def render_sarif(result: EngineResult) -> dict[str, Any]:
    results = []
    if result.outcome.value == "FAIL":
        results.append(
            {
                "ruleId": "AP001",
                "level": "error",
                "message": {"text": result.reason},
                "properties": {
                    "runId": str(result.run_id),
                    "expectedSloSeconds": result.expected_slo_seconds,
                    "observedStableDenialSeconds": result.metrics.stable_propagation_latency_seconds,
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AccessProof",
                        "rules": [{"id": "AP001", "name": "PermissionPropagationRegression"}],
                    }
                },
                "results": results,
            }
        ],
    }


def render_pdf_bytes(result: EngineResult) -> bytes:
    from io import BytesIO
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas

    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    width, height = A4
    y = height - 54
    lines = [
        "AccessProof Permission Regression Report",
        f"Run ID: {result.run_id}",
        f"Outcome: {result.outcome.value}",
        f"Expected SLO: {result.expected_slo_seconds:.1f} seconds",
        f"Observed stable denial: {result.metrics.stable_propagation_latency_seconds}",
        f"Exposure window: {result.metrics.exposure_window_seconds}",
        f"Reason: {result.reason}",
        "",
        "Timeline",
    ]
    for event in result.timeline:
        lines.append(f"{event.at.isoformat()}  {event.state.value}  {event.detail}")
    for line in lines:
        if y < 54:
            c.showPage()
            y = height - 54
        c.setFont(
            "Helvetica-Bold"
            if line in {"AccessProof Permission Regression Report", "Timeline"}
            else "Helvetica",
            11 if line.startswith("AccessProof") else 8,
        )
        c.drawString(54, y, line[:120])
        y -= 14
    c.save()
    return buf.getvalue()


def render_html_payload(payload: dict[str, Any]) -> str:
    derived = payload.get("derived", {})
    return f"""<!doctype html><html><head><meta charset='utf-8'><title>AccessProof Report</title></head><body>
<h1>AccessProof Report</h1><p>Run: {payload.get("run_id")}</p><p>Result: <strong>{payload.get("outcome")}</strong></p>
<p>Expected SLO: {payload.get("expected_slo_seconds")} seconds</p><p>Observed stable denial: {derived.get("stable_propagation_latency_seconds")}</p>
<p>Reason: {payload.get("reason")}</p></body></html>"""


def render_junit_payload(payload: dict[str, Any]) -> str:
    import xml.etree.ElementTree as ET

    suite = ET.Element("testsuite", name="AccessProof", tests="1")
    case = ET.SubElement(
        suite, "testcase", classname="permission_regression", name=str(payload.get("run_id"))
    )
    outcome = payload.get("outcome")
    if outcome == "FAIL":
        ET.SubElement(case, "failure", message=str(payload.get("reason", "failed")))
    elif outcome == "ERROR":
        ET.SubElement(case, "error", message=str(payload.get("reason", "error")))
    elif outcome in {"INCONCLUSIVE", "PRECONDITION_FAILURE", "CANCELED"}:
        ET.SubElement(case, "skipped", message=str(payload.get("reason", outcome)))
    return ET.tostring(suite, encoding="unicode")


def render_sarif_payload(payload: dict[str, Any]) -> dict[str, Any]:
    results = []
    if payload.get("outcome") == "FAIL":
        derived = payload.get("derived", {})
        results.append(
            {
                "ruleId": "AP001",
                "level": "error",
                "message": {
                    "text": str(payload.get("reason") or "Permission propagation regression")
                },
                "properties": {
                    "runId": str(payload.get("run_id")),
                    "expectedSloSeconds": payload.get("expected_slo_seconds"),
                    "observedStableDenialSeconds": derived.get(
                        "stable_propagation_latency_seconds"
                    ),
                    "failureBoundary": (payload.get("diagnostic") or {}).get("boundary"),
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AccessProof",
                        "rules": [{"id": "AP001", "name": "PermissionPropagationRegression"}],
                    }
                },
                "results": results,
            }
        ],
    }


def render_pdf_payload(payload: dict[str, Any]) -> bytes:
    from io import BytesIO
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas

    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    _, height = A4
    y = height - 54
    derived = payload.get("derived", {})
    lines = [
        "AccessProof Permission Regression Report",
        f"Run ID: {payload.get('run_id')}",
        f"Outcome: {payload.get('outcome')}",
        f"Expected SLO: {payload.get('expected_slo_seconds')} seconds",
        f"Observed stable denial: {derived.get('stable_propagation_latency_seconds')}",
        f"Reason: {payload.get('reason')}",
        "",
        "Timeline",
    ]
    for e in payload.get("timeline", []):
        lines.append(f"{e.get('at')}  {e.get('state')}  {e.get('detail')}")
    for line in lines:
        if y < 54:
            c.showPage()
            y = height - 54
        c.setFont(
            "Helvetica-Bold"
            if line in {"AccessProof Permission Regression Report", "Timeline"}
            else "Helvetica",
            10,
        )
        c.drawString(54, y, str(line)[:120])
        y -= 14
    c.save()
    return buf.getvalue()
