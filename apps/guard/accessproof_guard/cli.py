"""Enrollment command for a customer-side AccessProof Guard."""
from __future__ import annotations

from pathlib import Path

import typer

from .onboarding import EnrollmentError, enroll_guard


app = typer.Typer(add_completion=False)


@app.command()
def enroll(
    server: str = typer.Option(..., help="AccessProof control-plane URL"),
    token: str = typer.Option(..., prompt=True, hide_input=True, help="One-time Guard enrollment token"),
    issuer: str = typer.Option(..., help="Trusted employee OIDC issuer (HTTPS)"),
    audience: str = typer.Option(..., help="Expected employee JWT audience"),
    version: str = typer.Option("0.1.0", help="Guard version"),
    state_dir: Path = typer.Option(Path("/var/lib/accessproof-guard"), help="Private Guard state directory"),
) -> None:
    """Exchange a one-time enrollment token and save a private machine credential."""
    try:
        enroll_guard(server=server, token=token, version=version, state_dir=state_dir, issuer=issuer, audience=audience)
    except EnrollmentError as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(f"Guard enrolled. Private credentials saved to {state_dir / 'credentials.json'}.")
