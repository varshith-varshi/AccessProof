from pathlib import Path


def test_all_runtime_images_drop_root_privileges():
    dockerfiles = [
        Path("apps/api/Dockerfile"),
        Path("apps/worker/Dockerfile"),
        Path("apps/runner/Dockerfile"),
        Path("apps/web/Dockerfile"),
    ]
    for dockerfile in dockerfiles:
        text = dockerfile.read_text()
        assert "USER " in text, f"{dockerfile} must declare a non-root runtime USER"
        assert "USER root" not in text


def test_runner_compose_profile_is_read_only():
    compose = Path("docker-compose.yml").read_text()
    runner_block = compose.split("  runner:", 1)[1]
    assert "read_only: true" in runner_block
    assert "tmpfs:" in runner_block


def test_web_image_consumes_api_url_build_argument():
    dockerfile = Path("apps/web/Dockerfile").read_text()
    assert "ARG API_URL=" in dockerfile
    assert "ENV API_URL=$API_URL" in dockerfile
    compose = Path("docker-compose.yml").read_text()
    assert "args:" in compose and "API_URL: http://api:8000" in compose
