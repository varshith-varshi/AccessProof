from typer.testing import CliRunner

from packages.client_sdk.cli import app


def test_cli_supports_documented_nested_commands_and_legacy_aliases():
    runner = CliRunner()
    root = runner.invoke(app, ["--help"])
    assert root.exit_code == 0
    assert "projects" in root.stdout
    assert "reports" in root.stdout
    assert "projects-list" in root.stdout
    projects = runner.invoke(app, ["projects", "--help"])
    assert projects.exit_code == 0
    assert "list" in projects.stdout
    reports = runner.invoke(app, ["reports", "--help"])
    assert reports.exit_code == 0
    for command in ("download", "sarif", "verify"):
        assert command in reports.stdout


def test_gitlab_template_uses_scoped_cli_gate_contract():
    text = open("integrations/gitlab/.gitlab-ci.accessproof.yml", encoding="utf-8").read()
    assert "ACCESSPROOF_API_TOKEN" in text
    assert "ACCESSPROOF_PROJECT_ID" in text
    assert "ACCESSPROOF_SUITE_ID" in text
    assert "accessproof run" in text
    assert "--wait" in text
    assert "--block-on-inconclusive" in text


def test_run_supports_documented_project_and_suite_options():
    runner = CliRunner()
    result = runner.invoke(app, ["run", "--help"])
    assert result.exit_code == 0
    assert "--project" in result.stdout
    assert "--suite" in result.stdout
