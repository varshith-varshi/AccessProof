from __future__ import annotations

from typing import Any

import asyncio
import httpx

from integrations.webhooks.signing import canonical_payload, sign_payload
from packages.connector_sdk.http_target import _pin_https_url


async def deliver(
    url: str, secret: str, event: dict[str, Any], *, max_attempts: int = 5
) -> list[dict[str, Any]]:
    """Deliver a signed webhook without following redirects or trusting proxies.

    Webhook endpoints are validated when saved, then resolved and pinned again
    immediately before this request. This closes the DNS-rebinding window that
    would otherwise let a public endpoint pivot delivery to a private address.
    """
    attempts: list[dict[str, Any]] = []
    try:
        pinned_url, host, sni = _pin_https_url(url)
    except ValueError:
        # Do not expose a target URL or DNS details through delivery status.
        return [{"attempt": 0, "error": "invalid_endpoint"}]

    async with httpx.AsyncClient(
        timeout=15, follow_redirects=False, trust_env=False
    ) as client:
        for attempt in range(1, max_attempts + 1):
            headers = sign_payload(secret, event)
            headers["Content-Type"] = "application/json"
            headers["Host"] = host
            try:
                response = await client.post(
                    pinned_url,
                    content=canonical_payload(event),
                    headers=headers,
                    extensions={"sni_hostname": sni},
                )
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
