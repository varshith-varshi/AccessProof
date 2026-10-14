from __future__ import annotations

from typing import Any

import asyncio
import httpx
from integrations.webhooks.signing import canonical_payload, sign_payload


async def deliver(
    url: str, secret: str, event: dict[str, Any], *, max_attempts: int = 5
) -> list[dict[str, Any]]:
    attempts: list[dict[str, Any]] = []
    async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
        for attempt in range(1, max_attempts + 1):
            headers = sign_payload(secret, event)
            headers["Content-Type"] = "application/json"
            try:
                response = await client.post(url, content=canonical_payload(event), headers=headers)
                attempts.append({"attempt": attempt, "status_code": response.status_code})
                if 200 <= response.status_code < 300:
                    return attempts
                if 400 <= response.status_code < 500 and response.status_code != 429:
                    return attempts
                retry_after = response.headers.get("Retry-After")
                delay = (
                    float(retry_after)
                    if retry_after and retry_after.isdigit()
                    else min(30, 2 ** (attempt - 1))
                )
            except httpx.HTTPError as exc:
                attempts.append({"attempt": attempt, "error": type(exc).__name__})
                delay = min(30, 2 ** (attempt - 1))
            if attempt < max_attempts:
                await asyncio.sleep(delay)
    return attempts
