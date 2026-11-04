"""Every module the production API image runs must import using ONLY what the
image ships (apps/api, packages, connectors, integrations): r38 shipped a gates
module that imported apps.gateway and crashed in production."""
import ast
from pathlib import Path

SHIPPED = ("apps.api", "packages", "connectors", "integrations")
ENTRY = [Path("scripts/production_security_gates.py"), Path("scripts/remote_route_certificate.py"),
         *Path("apps/api/accessproof_api").glob("*.py")]


def test_api_image_modules_import_only_shipped_first_party_code():
    bad = []
    for path in ENTRY:
        for node in ast.walk(ast.parse(path.read_text())):
            mods = [node.module] if isinstance(node, ast.ImportFrom) and node.module else \
                   [a.name for a in node.names] if isinstance(node, ast.Import) else []
            for m in mods:
                if m.split(".")[0] in ("apps", "packages", "connectors", "integrations", "scripts") \
                        and not m.startswith(SHIPPED):
                    bad.append((str(path), m))
    assert not bad, bad
