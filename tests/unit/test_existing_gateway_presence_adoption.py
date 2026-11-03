"""O-09: adopting an existing Gateway delivers its rotated heartbeat credential."""
from pathlib import Path

from apps.gateway.accessproof_gateway.existing_gateway import local_installation


def _install(tmp: Path) -> tuple[Path, Path]:
    install = tmp / "accessproof-install"
    install.mkdir()
    (install / "installation.json").write_text("{}")
    override = install / "gateway.override.json"
    override.write_text("{}")
    compose = tmp / "docker-compose.yml"
    compose.write_text("services: {}")
    return compose, override


def test_genuine_staged_installation_is_located(tmp_path):
    compose, override = _install(tmp_path)
    labels = {"com.docker.compose.project.config_files": f"{compose},{override}"}
    assert local_installation(labels, "accessproof-gateway") == {
        "customer_compose": str(compose), "override": str(override),
        "gateway_service": "accessproof-gateway", "installation_dir": str(override.parent)}


def test_anything_unusual_is_refused(tmp_path):
    compose, override = _install(tmp_path)
    assert local_installation({}, "accessproof-gateway") is None
    assert local_installation({"com.docker.compose.project.config_files": str(compose)}, "g") is None
    extra = tmp_path / "other.yml"
    extra.write_text("x")
    assert local_installation({"com.docker.compose.project.config_files": f"{compose},{extra},{override}"}, "g") is None
    (override.parent / "installation.json").unlink()
    assert local_installation({"com.docker.compose.project.config_files": f"{compose},{override}"}, "g") is None
    (override.parent / "installation.json").write_text("{}")
    link = tmp_path / "gateway.override.json"
    link.symlink_to(override)
    assert local_installation({"com.docker.compose.project.config_files": f"{compose},{link}"}, "g") is None
    assert local_installation({"com.docker.compose.project.config_files": f"relative.yml,gateway.override.json"}, "g") is None
