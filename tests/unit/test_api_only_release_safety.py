"""The API release never repeats the on-host web build outage."""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SERVER = ROOT / "deploy/ec2-release/deploy_api_only_on_ec2.sh"
DISPATCHER = ROOT / "deploy/ec2-release/deploy_on_ec2.sh"
CLIENT = ROOT / "deploy/deployer/ship_production.sh"


def test_isolated_api_deploy_invariants():
    server = SERVER.read_text()
    dispatch = DISPATCHER.read_text()
    client = CLIENT.read_text()
    for path in (SERVER, DISPATCHER, CLIENT):
        assert subprocess.run(["bash", "-n", str(path)], capture_output=True).returncode == 0
    assert 'if [[ "$RELEASE_ID" == api-* ]]' in dispatch
    assert 'deploy_api_only_on_ec2.sh' in dispatch
    assert 'elif [[ "$RID" == api-* ]]; then bundle_api_images' in client
    assert 'git archive --format=tar "$COMMIT"' in client
    assert 'docker build --platform linux/amd64' in client
    assert 'docker load' in server
    assert 'docker build' not in server
    assert 'alembic upgrade' not in server
    assert 'alembic downgrade' not in server
    assert 'pg_dump' in server
    assert 'pg_restore --list' in server
    assert 'health api 240' in server
    assert 'health worker 120' in server
    assert 'reload_nginx' in server
    assert 'rollback' in server
    assert 'public_health' in server
    assert 'sha256sum' in server
    assert 'api-image.digests' not in server or '$svc-image.digests' in server
    assert '--force-recreate api' in server
    assert '--force-recreate worker' in server
    for forbidden in ('--force-recreate web', 'docker image prune', 'docker system prune', 'docker volume prune', 'growpart', 'reboot'):
        assert forbidden not in server
