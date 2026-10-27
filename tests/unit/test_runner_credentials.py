import os

from apps.runner.accessproof_runner.config import RunnerCredentials, load_credentials, save_credentials


def test_runner_credentials_are_written_with_owner_only_permissions(tmp_path, monkeypatch):
    monkeypatch.setenv("ACCESSPROOF_RUNNER_STATE_DIR", str(tmp_path))
    credentials = RunnerCredentials(
        api_url="https://api.example.test",
        runner_id="runner-1",
        runner_secret="secret",
        name="test-runner",
        version="0.9.0-pilot",
    )
    save_credentials(credentials)
    path = tmp_path / "credentials.json"
    assert path.exists()
    assert os.stat(path).st_mode & 0o777 == 0o600
    assert load_credentials() == credentials
