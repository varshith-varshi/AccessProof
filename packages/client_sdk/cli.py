from __future__ import annotations

from typing import Any

import json
import os
import time
from pathlib import Path
import httpx
import typer

app = typer.Typer(help="AccessProof CLI")
projects_app = typer.Typer(help="Project commands")
reports_app = typer.Typer(help="Report commands")
app.add_typer(projects_app, name="projects")
app.add_typer(reports_app, name="reports")
CONFIG = Path.home() / ".accessproof" / "config.json"


def _load() -> dict[str, Any]:
    cfg = json.loads(CONFIG.read_text()) if CONFIG.exists() else {}
    # CI can use a scoped AccessProof API key without writing a credential file.
    if os.getenv("ACCESSPROOF_API_URL"):
        cfg["api_url"] = os.environ["ACCESSPROOF_API_URL"].rstrip("/")
    if os.getenv("ACCESSPROOF_API_TOKEN"):
        cfg["session_token"] = os.environ["ACCESSPROOF_API_TOKEN"]
    if os.getenv("ACCESSPROOF_ORG_ID"):
        cfg["organization_id"] = os.environ["ACCESSPROOF_ORG_ID"]
    missing = [key for key in ("api_url", "session_token", "organization_id") if not cfg.get(key)]
    if missing:
        raise typer.BadParameter(
            "Missing AccessProof CLI configuration: "
            + ", ".join(missing)
            + ". Run login or set ACCESSPROOF_API_URL, ACCESSPROOF_API_TOKEN and ACCESSPROOF_ORG_ID."
        )
    return cfg


def _save(data: dict[str, Any]) -> None:
    CONFIG.parent.mkdir(parents=True, exist_ok=True)
    CONFIG.write_text(json.dumps(data))


def _headers(cfg: dict[str, Any]) -> dict[str, Any]:
    return {
        "Authorization": f"Bearer {cfg['session_token']}",
        "X-Organization-ID": cfg["organization_id"],
    }


@app.command()
def login(
    email: str,
    password: str = typer.Option(..., prompt=True, hide_input=True),
    organization_id: str | None = None,
    api_url: str = "http://127.0.0.1:8000",
) -> None:
    r = httpx.post(
        f"{api_url}/api/v1/auth/login",
        json={"email": email, "password": password, "organization_id": organization_id},
        timeout=30,
    )
    r.raise_for_status()
    data = r.json()
    org = organization_id or data["organizations"][0]["id"]
    _save({"api_url": api_url, "session_token": data["session_token"], "organization_id": org})
    typer.echo(f"Logged in to organization {org}")


@app.command("projects-list")
def projects_list(json_output: bool = False) -> None:
    cfg = _load()
    r = httpx.get(f"{cfg['api_url']}/api/v1/projects", headers=_headers(cfg), timeout=30)
    r.raise_for_status()
    data = r.json()
    if json_output:
        typer.echo(json.dumps(data))
        return
    for p in data:
        typer.echo(f"{p['id']}  {p['name']}  {'PAUSED' if p['paused'] else ''}")


@app.command()
def run(
    project_arg: str | None = typer.Argument(
        None, metavar="[PROJECT]", help="Project ID (legacy positional form)."
    ),
    suite_arg: str | None = typer.Argument(
        None, metavar="[SUITE]", help="Suite ID (legacy positional form)."
    ),
    project: str | None = typer.Option(None, "--project", help="Project ID."),
    suite: str | None = typer.Option(None, "--suite", help="Test suite ID."),
    release: str = "manual",
    git_sha: str | None = None,
    wait: bool = False,
    json_output: bool = False,
    block_on_inconclusive: bool = typer.Option(
        True, "--block-on-inconclusive/--warn-on-inconclusive"
    ),
) -> None:
    project_id = project or project_arg
    suite_id = suite or suite_arg
    if not project_id or not suite_id:
        raise typer.BadParameter(
            "Both project and suite are required. Use --project/--suite or the legacy positional form."
        )
    cfg = _load()
    headers = _headers(cfg)
    r = httpx.post(
        f"{cfg['api_url']}/api/v1/runs",
        headers=headers,
        json={
            "project_id": project_id,
            "suite_id": suite_id,
            "release": release,
            "git_sha": git_sha,
        },
        timeout=30,
    )
    r.raise_for_status()
    data = r.json()
    run_id = data["id"]
    if not wait:
        typer.echo(json.dumps(data) if json_output else run_id)
        return
    while True:
        rr = httpx.get(f"{cfg['api_url']}/api/v1/runs/{run_id}", headers=headers, timeout=30)
        rr.raise_for_status()
        current = rr.json()
        if current.get("outcome"):
            if json_output:
                typer.echo(json.dumps(current))
            else:
                typer.echo(f"{current['outcome']}  {run_id}")
            if current["outcome"] == "PASS":
                code = 0
            elif current["outcome"] == "FAIL":
                code = 1
            elif current["outcome"] in {"INCONCLUSIVE", "PRECONDITION_FAILURE"}:
                code = 2 if block_on_inconclusive else 0
            else:
                code = 3
            raise typer.Exit(code=code)
        time.sleep(2)


@app.command("reports-download")
def reports_download(run_id: str, output: Path = Path("accessproof-report.json")) -> None:
    cfg = _load()
    r = httpx.get(
        f"{cfg['api_url']}/api/v1/reports/{run_id}.json", headers=_headers(cfg), timeout=30
    )
    r.raise_for_status()
    output.write_text(json.dumps(r.json(), indent=2))
    typer.echo(str(output))


@app.command("reports-sarif")
def reports_sarif(run_id: str, output: Path = Path("accessproof-report.sarif.json")) -> None:
    cfg = _load()
    r = httpx.get(
        f"{cfg['api_url']}/api/v1/reports/{run_id}.sarif.json", headers=_headers(cfg), timeout=30
    )
    r.raise_for_status()
    output.write_text(json.dumps(r.json(), indent=2))
    typer.echo(str(output))


@app.command("reports-verify")
def reports_verify(run_id: str, json_output: bool = False) -> None:
    cfg = _load()
    r = httpx.get(
        f"{cfg['api_url']}/api/v1/reports/{run_id}/integrity", headers=_headers(cfg), timeout=30
    )
    r.raise_for_status()
    data = r.json()
    if json_output:
        typer.echo(json.dumps(data, sort_keys=True))
    else:
        state = "VERIFIED" if data.get("verified") else "INVALID"
        typer.echo(f"{state}  {run_id}  {data.get('key_id') or '-'}")
    if not data.get("verified"):
        raise typer.Exit(code=4)


@projects_app.command("list")
def projects_list_nested(json_output: bool = False) -> None:
    """List projects (nested form; `projects-list` remains for compatibility)."""
    return projects_list(json_output=json_output)


@reports_app.command("download")
def reports_download_nested(run_id: str, output: Path = Path("accessproof-report.json")) -> None:
    return reports_download(run_id=run_id, output=output)


@reports_app.command("sarif")
def reports_sarif_nested(run_id: str, output: Path = Path("accessproof-report.sarif.json")) -> None:
    return reports_sarif(run_id=run_id, output=output)


@reports_app.command("verify")
def reports_verify_nested(run_id: str, json_output: bool = False) -> None:
    return reports_verify(run_id=run_id, json_output=json_output)


if __name__ == "__main__":
    app()
