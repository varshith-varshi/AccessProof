from __future__ import annotations

import asyncio
import email.utils
from datetime import datetime, timezone
from collections.abc import Awaitable, Callable

import httpx
from packages.connector_sdk.base import (
    AuthenticationError,
    AuthorizationError,
    ProviderUnavailableError,
    RateLimitError,
)


def retry_after_seconds(
    response: httpx.Response, *, default: float = 1.0, maximum: float = 30.0
) -> float:
    value = response.headers.get("Retry-After")
    if not value:
        return default
    try:
        return max(0.0, min(maximum, float(value)))
    except ValueError:
        try:
            parsed = email.utils.parsedate_to_datetime(value)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return max(0.0, min(maximum, (parsed - datetime.now(timezone.utc)).total_seconds()))
        except (TypeError, ValueError, OverflowError):
            return default


def normalize_http_error(response: httpx.Response) -> None:
    if response.status_code in (401,):
        raise AuthenticationError(f"provider returned {response.status_code}")
    if response.status_code in (403,):
        raise AuthorizationError(f"provider returned {response.status_code}")
    if response.status_code == 429:
        raise RateLimitError(f"provider rate limit; retry_after={retry_after_seconds(response)}")
    if response.status_code >= 500:
        raise ProviderUnavailableError(f"provider returned {response.status_code}")
    response.raise_for_status()


async def bounded_idempotent_request(
    send: Callable[[], Awaitable[httpx.Response]], *, max_attempts: int = 3
) -> httpx.Response:
    """Retry only requests whose caller has explicitly classified them idempotent.

    This helper is deliberately never applied implicitly to provider mutations.
    """
    for attempt in range(1, max_attempts + 1):
        response = await send()
        if response.status_code == 429 and attempt < max_attempts:
            await asyncio.sleep(retry_after_seconds(response))
            continue
        if response.status_code >= 500 and attempt < max_attempts:
            await asyncio.sleep(min(2 ** (attempt - 1), 4))
            continue
        normalize_http_error(response)
        return response
    raise RuntimeError("unreachable retry loop")
