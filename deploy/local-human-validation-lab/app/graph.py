"""Read-only, boundary-scoped Microsoft Graph SharePoint document ingestion.

The app-only credentials must be granted access only to an approved test site
(e.g. Sites.Selected + explicit site assignment). They belong in the ingest
process, NEVER the web/LLM/Redis container.
"""
from __future__ import annotations

import io
import re
import time
from dataclasses import dataclass
from urllib.parse import quote, urlsplit

import httpx
from docx import Document
from pypdf import PdfReader

GRAPH = "https://graph.microsoft.com/v1.0"


class GraphError(RuntimeError):
    pass


@dataclass(frozen=True)
class SourceDoc:
    item_id: str
    name: str
    url: str
    version: str
    text: str


def extract_content(data: bytes, name: str, mime: str) -> str:
    """Supported test-lab formats only. Do not silently pretend binary is text."""
    suffix = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if suffix in {"txt", "md", "csv", "json", "log", "py"} or mime.startswith("text/"):
        return data.decode("utf-8-sig").strip()
    if suffix == "docx":
        doc = Document(io.BytesIO(data))
        return "\n".join(p.text for p in doc.paragraphs if p.text.strip()).strip()
    if suffix == "pdf":
        pdf = PdfReader(io.BytesIO(data))
        if len(pdf.pages) > 250:
            raise GraphError("PDF_PAGE_LIMIT")
        return "\n".join(page.extract_text() or "" for page in pdf.pages).strip()
    raise GraphError("FILE_FORMAT_UNSUPPORTED")


class SharePointGraph:
    """OAuth client-credentials Graph adapter; caller supplies explicit drive ID."""

    def __init__(
        self, tenant_id: str, client_id: str, client_secret: str, drive_id: str,
        root_item_id: str = "", *, client: httpx.Client | None = None,
        max_files: int = 250, max_file_bytes: int = 2_000_000,
        tenant_download_host: str = "",
    ):
        if not all((tenant_id, client_id, client_secret, drive_id)):
            raise GraphError("GRAPH_TENANT_CLIENT_SECRET_DRIVE_REQUIRED")
        if not re.fullmatch(r"[A-Za-z0-9_!.-]{4,250}", drive_id):
            raise GraphError("GRAPH_DRIVE_ID_INVALID")
        if root_item_id and not re.fullmatch(r"[A-Za-z0-9_!.-]{2,250}", root_item_id):
            raise GraphError("GRAPH_ROOT_ID_INVALID")
        self.tenant_id, self.client_id, self.client_secret = tenant_id, client_id, client_secret
        self.drive_id, self.root_item_id = drive_id, root_item_id
        self.max_files, self.max_file_bytes = max_files, max_file_bytes
        self.tenant_download_host = tenant_download_host.lower().strip()
        if self.tenant_download_host and not (
            self.tenant_download_host.endswith(".sharepoint.com")
            and self.tenant_download_host.count(".") >= 2
        ):
            raise GraphError("DOWNLOAD_HOST_INVALID")
        self.client = client or httpx.Client(timeout=25, trust_env=False, follow_redirects=False)
        self._token, self._expires = "", 0.0

    def _auth(self) -> str:
        if self._token and time.monotonic() < self._expires:
            return self._token
        try:
            response = self.client.post(
                f"https://login.microsoftonline.com/{quote(self.tenant_id, safe='')}/oauth2/v2.0/token",
                data={"client_id": self.client_id, "client_secret": self.client_secret,
                      "scope": "https://graph.microsoft.com/.default",
                      "grant_type": "client_credentials"},
            )
            response.raise_for_status()
            data = response.json()
            token = data.get("access_token")
            if not isinstance(token, str) or not token:
                raise ValueError("missing access token")
            self._expires = time.monotonic() + max(10, int(data.get("expires_in", 3600)) - 120)
            self._token = token
            return token
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            raise GraphError("GRAPH_APP_AUTH_FAILED") from exc

    def _get(self, url: str) -> httpx.Response:
        if not (url.startswith(GRAPH + "/drives/" + quote(self.drive_id, safe="") + "/")):
            raise GraphError("GRAPH_OUTSIDE_APPROVED_DRIVE")
        for attempt in range(2):
            try:
                response = self.client.get(url, headers={"Authorization": "Bearer " + self._auth()})
            except httpx.HTTPError as exc:
                raise GraphError("GRAPH_REQUEST_UNAVAILABLE") from exc
            if response.status_code != 401:
                break
            self._token = ""
        if response.status_code != 200:
            raise GraphError(f"GRAPH_HTTP_{response.status_code}")
        return response

    def _pages(self, url: str):
        visited: set[str] = set()
        expected_path = urlsplit(url).path
        for _ in range(100):
            if url in visited:
                raise GraphError("GRAPH_PAGE_LOOP")
            visited.add(url)
            try:
                payload = self._get(url).json()
            except ValueError as exc:
                raise GraphError("GRAPH_PAGE_INVALID_JSON") from exc
            if not isinstance(payload, dict) or not isinstance(payload.get("value"), list):
                raise GraphError("GRAPH_PAGE_INVALID")
            for item in payload["value"]:
                if not isinstance(item, dict):
                    raise GraphError("GRAPH_ITEM_INVALID")
                yield item
            nxt = payload.get("@odata.nextLink")
            if not nxt:
                return
            parts = urlsplit(str(nxt))
            if (parts.scheme != "https" or parts.netloc != "graph.microsoft.com"
                    or parts.path != expected_path
                    or parts.username or parts.password or parts.fragment):
                raise GraphError("GRAPH_PAGE_OUTSIDE_BOUNDARY")
            url = str(nxt)
        raise GraphError("GRAPH_PAGINATION_LIMIT")

    def _iter_items(self):
        root = self.root_item_id
        base = f"{GRAPH}/drives/{quote(self.drive_id, safe='')}"
        queue = [(root, 0)]
        seen: set[str] = set()
        folders = 0
        while queue:
            folder_id, depth = queue.pop(0)
            if depth > 16 or folders > 2500:
                raise GraphError("GRAPH_FOLDER_LIMIT")
            folders += 1
            url = (base + "/root/children" if not folder_id else
                   base + f"/items/{quote(folder_id, safe='')}/children")
            for item in self._pages(url):
                item_id = item.get("id")
                if not isinstance(item_id, str) or not item_id or item_id in seen:
                    raise GraphError("GRAPH_DUPLICATE_OR_MISSING_ID")
                parent = item.get("parentReference")
                if (not isinstance(parent, dict)
                        or str(parent.get("driveId")) != self.drive_id
                        or (folder_id and str(parent.get("id")) != folder_id)):
                    raise GraphError("GRAPH_FOREIGN_DRIVE_ITEM")
                seen.add(item_id)
                if "remoteItem" in item:
                    continue
                if isinstance(item.get("folder"), dict):
                    queue.append((item_id, depth + 1))
                    continue
                if isinstance(item.get("file"), dict):
                    yield item

    def _download(self, item_id: str) -> bytes:
        base = f"{GRAPH}/drives/{quote(self.drive_id, safe='')}/items/{quote(item_id, safe='')}/content"
        for attempt in range(2):
            try:
                response = self.client.get(
                    base, headers={"Authorization": "Bearer " + self._auth()})
            except httpx.HTTPError as exc:
                raise GraphError("GRAPH_DOWNLOAD_UNAVAILABLE") from exc
            if response.status_code != 401:
                break
            self._token = ""
        if response.status_code != 302:
            raise GraphError(f"GRAPH_CONTENT_HTTP_{response.status_code}")
        target = response.headers.get("location", "")
        parsed = urlsplit(target)
        host = (parsed.hostname or "").lower()
        # SharePoint's preauthenticated download endpoint is host allowlisted.
        # Never forward the Graph OAuth token, ever.
        if (parsed.scheme != "https" or parsed.username or parsed.password
                or parsed.port not in (None, 443) or not host
                or not (host.endswith(".sharepoint.com")
                        or host.endswith(".sharepoint-df.com"))
                or (self.tenant_download_host and host != self.tenant_download_host)):
            raise GraphError("GRAPH_UNTRUSTED_CONTENT_REDIRECT")
        try:
            with self.client.stream("GET", target, follow_redirects=False) as download:
                if download.status_code != 200:
                    raise GraphError(f"SHAREPOINT_DOWNLOAD_HTTP_{download.status_code}")
                chunks, size = [], 0
                for part in download.iter_bytes(32768):
                    size += len(part)
                    if size > self.max_file_bytes:
                        raise GraphError("DOCUMENT_BYTES_LIMIT")
                    chunks.append(part)
                return b"".join(chunks)
        except httpx.HTTPError as exc:
            raise GraphError("SHAREPOINT_DOWNLOAD_UNAVAILABLE") from exc

    def documents(self) -> tuple[list[SourceDoc], list[str]]:
        documents: list[SourceDoc] = []
        skipped: list[str] = []
        for item in self._iter_items():
            if len(documents) + len(skipped) >= self.max_files:
                raise GraphError("GRAPH_FILE_COUNT_LIMIT")
            item_id, name = str(item["id"]), str(item.get("name") or "")
            version = item.get("eTag") or item.get("cTag")
            if not name or not isinstance(version, str) or not version:
                raise GraphError("GRAPH_FILE_VERSION_UNKNOWN")
            if (not isinstance(item.get("size"), int)
                    or item["size"] > self.max_file_bytes):
                skipped.append(item_id + ": oversize_or_unknown_size")
                continue
            try:
                raw = self._download(item_id)
                body = extract_content(raw, name, str(item.get("file", {}).get("mimeType", "")))
                if not body:
                    skipped.append(item_id + ": empty_or_image_only")
                    continue
            except GraphError as exc:
                if str(exc) == "FILE_FORMAT_UNSUPPORTED":
                    skipped.append(item_id + ": unsupported_format")
                    continue
                raise
            # URL is a citation only; not a document authorization proof.
            url = str(item.get("webUrl") or "")
            if url:
                u = urlsplit(url)
                if u.scheme != "https" or not (u.hostname or "").endswith(".sharepoint.com"):
                    url = ""
            documents.append(SourceDoc(item_id, name, url, version, body))
        return documents, skipped
