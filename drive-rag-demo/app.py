import os
import time

import httpx
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

DRIVE_TOKEN = os.environ["DRIVE_OWNER_TOKEN"]
ROOT_FOLDER_ID = os.environ["DRIVE_ROOT_FOLDER_ID"]

ALICE_EMAIL = os.environ["ALICE_EMAIL"].lower()
ALICE_TOKEN = os.environ["ALICE_RAG_TOKEN"]

BOB_EMAIL = os.environ["BOB_EMAIL"].lower()
BOB_TOKEN = os.environ["BOB_RAG_TOKEN"]

CACHE_SECONDS = float(os.getenv("ACL_CACHE_SECONDS", "20"))

app = FastAPI(title="AccessProof Google Drive RAG Demo")

cached_files = []
last_refresh = 0.0


class ChatRequest(BaseModel):
    message: str


def identity_from_token(auth: str | None) -> str:
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(401, "Bearer token required")

    token = auth[7:]

    if token == ALICE_TOKEN:
        return ALICE_EMAIL

    if token == BOB_TOKEN:
        return BOB_EMAIL

    raise HTTPException(401, "Invalid test identity")


async def drive_get(client, url, **kwargs):
    headers = {
        "Authorization": f"Bearer {DRIVE_TOKEN}"
    }

    try:
        r = await client.get(url, headers=headers, **kwargs)
        r.raise_for_status()
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 401:
            raise HTTPException(
                503,
                "GOOGLE_DRIVE_TOKEN_EXPIRED_OR_INVALID",
            ) from exc
        raise HTTPException(502, "GOOGLE_DRIVE_API_ERROR") from exc
    except httpx.RequestError as exc:
        raise HTTPException(503, "GOOGLE_DRIVE_UNAVAILABLE") from exc
    return r


async def refresh_cache():
    global cached_files, last_refresh

    result = []

    async with httpx.AsyncClient(timeout=20) as client:

        files_response = await drive_get(
            client,
            "https://www.googleapis.com/drive/v3/files",
            params={
                "q": f"'{ROOT_FOLDER_ID}' in parents and trashed=false",
                "fields": "files(id,name,mimeType)",
                "pageSize": 100,
            },
        )

        files = files_response.json().get("files", [])

        for file in files:

            file_id = file["id"]

            permissions_response = await drive_get(
                client,
                f"https://www.googleapis.com/drive/v3/files/{file_id}/permissions",
                params={
                    "fields": "permissions(emailAddress,type,role)"
                },
            )

            allowed = set()

            for permission in permissions_response.json().get(
                "permissions", []
            ):
                email = permission.get("emailAddress")

                if email:
                    allowed.add(email.lower())

            content_response = await drive_get(
                client,
                f"https://www.googleapis.com/drive/v3/files/{file_id}",
                params={"alt": "media"},
            )

            result.append(
                {
                    "id": file_id,
                    "name": file["name"],
                    "content": content_response.text,
                    "allowed": allowed,
                }
            )

    cached_files = result
    last_refresh = time.monotonic()


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "cached_files": len(cached_files),
        "acl_cache_seconds": CACHE_SECONDS,
    }


@app.post("/v1/chat")
async def chat(
    payload: ChatRequest,
    authorization: str | None = Header(default=None),
):
    global last_refresh

    user = identity_from_token(authorization)

    now = time.monotonic()

    # This intentionally simulates a RAG ACL/index cache.
    if not cached_files or now - last_refresh >= CACHE_SECONDS:
        await refresh_cache()

    accessible = [
        doc for doc in cached_files
        if user in doc["allowed"]
    ]

    if not accessible:
        return {
            "answer": "I do not have access to that information.",
            "citations": [],
            "retrieved_documents": [],
            "tool_outputs": [],
        }

    doc = accessible[0]

    return {
        "answer": f"Based on the retrieved document: {doc['content']}",
        "citations": [doc["id"]],
        "retrieved_documents": [
            {
                "id": doc["id"],
                "content": doc["content"],
            }
        ],
        "tool_outputs": [],
    }
