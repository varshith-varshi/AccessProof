"""Enrollment command for a customer-side AccessProof Guard."""
from __future__ import annotations

import json
import os
from pathlib import Path

import httpx
import typer


app = typer.Typer(add_completion=False)


@app.command()
def enroll(
    server: str = typer.Option(..., help="AccessProof control-plane URL"),
    token: str = typer.Option(..., prompt=True, hide_input=True, help="One-time Guard enrollment token"),
    version: str = typer.Option("0.1.0", help="Guard version"),
    state_dir: Path = typer.Option(Path("/var/lib/accessproof-guard"), help="Private Guard state directory"),
) -> None:
    """Exchange a one-time enrollment token and save a private machine credential."""
    response = httpx.post(
        f"{server.rstrip('/')}/api/v1/guards/exchange",
        json={"enrollment_token": token, "version": version},
        timeout=15,
        follow_redirects=False,
        trust_env=False,
    )
    response.raise_for_status()
    payload = response.json()
    guard_id = payload.get("guard_id")
    credential = payload.get("guard_credential")
    if not isinstance(guard_id, str) or not isinstance(credential, str):
        raise typer.BadParameter("The control plane returned an invalid enrollment response.")
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(state_dir, 0o700)
    credentials = state_dir / "credentials.json"
    temporary = state_dir / ".credentials.json.tmp"
    temporary.write_text(
        json.dumps({"control_plane_url": server.rstrip("/"), "guard_id": guard_id, "credential": credential}),
        encoding="utf-8",
    )
    os.chmod(temporary, 0o600)
    temporary.replace(credentials)
    typer.echo(f"Guard enrolled. Private credentials saved to {credentials}.")
