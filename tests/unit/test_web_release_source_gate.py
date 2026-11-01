"""Release gate prevents compiled-only onboarding from being deployed."""
from pathlib import Path

from scripts.verify_web_release_source import verify_frontend_route_source


def test_missing_onboarding_source_blocks_release(tmp_path: Path) -> None:
    errors = verify_frontend_route_source(tmp_path)
    assert len(errors) == 1
    assert "MISSING_CANONICAL_ONBOARDING_PAGE" in errors[0]


def test_trivial_placeholder_source_blocks_release(tmp_path: Path) -> None:
    path = tmp_path / "web-v2/app/onboarding/page.tsx"
    path.parent.mkdir(parents=True)
    path.write_text("export default function Onboarding(){return null}")
    errors = verify_frontend_route_source(tmp_path)
    assert len(errors) == 1
    assert "INCOMPLETE_CANONICAL_ONBOARDING_PAGE" in errors[0]


def test_substantial_route_source_passes_initial_gate(tmp_path: Path) -> None:
    path = tmp_path / "web-v2/app/onboarding/page.tsx"
    path.parent.mkdir(parents=True)
    path.write_text(
        "export default function Onboarding(){return <main>"
        + "Connect SharePoint, connect customer RAG, verify and protect."
        + (" Require real security evidence before activation." * 5)
        + "</main>}"
    )
    assert verify_frontend_route_source(tmp_path) == []


def test_symlinked_route_does_not_satisfy_source_parity(tmp_path: Path) -> None:
    actual = tmp_path / "noncanonical-page.tsx"
    actual.write_text("function Real(){return <>security</>}" * 12)
    path = tmp_path / "web-v2/app/onboarding/page.tsx"
    path.parent.mkdir(parents=True)
    path.symlink_to(actual)
    errors = verify_frontend_route_source(tmp_path)
    assert len(errors) == 1
    assert "MISSING_CANONICAL_ONBOARDING_PAGE" in errors[0]
