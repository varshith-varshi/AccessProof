from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import Protocol

import httpx

from packages.connector_sdk.http_target import _pin_https_url, validate_cloud_url
from packages.domain.models import ProbeGenerationInfo
from packages.domain.scenario import LlmProbePolicy
from packages.test_engine.synthetic import SyntheticDocument


class ProbeGenerationError(RuntimeError):
    pass


class ProbeGenerator(Protocol):
    async def generate(
        self, document: SyntheticDocument, policy: LlmProbePolicy
    ) -> tuple[list[str], ProbeGenerationInfo]: ...


@dataclass(slots=True)
class OpenAICompatibleProbeGenerator:
    endpoint: str
    api_key: str
    model: str
    provider: str = "openai-compatible"
    version: str | None = None
    input_cost_per_million_tokens: float = 0.0
    output_cost_per_million_tokens: float = 0.0
    timeout_seconds: float = 30.0
    transport: httpx.AsyncBaseTransport | None = None
    _last_request_at: float = field(init=False, default=0.0, repr=False)
    _lock: asyncio.Lock = field(init=False, repr=False)

    def __post_init__(self) -> None:
        validate_cloud_url(self.endpoint)
        self._last_request_at = 0.0
        self._lock = asyncio.Lock()

    async def _rate_limit(self, rpm: int) -> None:
        minimum_interval = 60.0 / max(1, rpm)
        async with self._lock:
            now = time.monotonic()
            wait = minimum_interval - (now - self._last_request_at)
            if self._last_request_at and wait > 0:
                await asyncio.sleep(wait)
            self._last_request_at = time.monotonic()

    def _maximum_estimated_cost(self, document: SyntheticDocument, policy: LlmProbePolicy) -> float:
        # Conservative tokenizer-independent upper bound. The exact post-call cost
        # uses provider usage metadata when available.
        input_tokens_upper = max(1, len(document.body) // 3 + 250)
        return (
            input_tokens_upper * self.input_cost_per_million_tokens
            + policy.max_output_tokens * self.output_cost_per_million_tokens
        ) / 1_000_000

    async def generate(
        self, document: SyntheticDocument, policy: LlmProbePolicy
    ) -> tuple[list[str], ProbeGenerationInfo]:
        if not policy.enabled:
            return [], ProbeGenerationInfo(
                provider=self.provider,
                model=self.model,
                version=self.version,
                generated_count=0,
                status="disabled",
            )
        max_cost = self._maximum_estimated_cost(document, policy)
        if policy.cost_budget_usd and max_cost > policy.cost_budget_usd:
            raise ProbeGenerationError(
                f"Configured LLM probe request could cost up to ${max_cost:.6f}, above ${policy.cost_budget_usd:.6f} budget"
            )
        await self._rate_limit(policy.requests_per_minute)
        pinned, host, sni = _pin_https_url(self.endpoint)
        # Only AccessProof-generated synthetic material is supplied here. The API
        # deliberately accepts SyntheticDocument rather than arbitrary customer text.
        payload = {
            "model": self.model,
            "temperature": 0.3,
            "max_tokens": policy.max_output_tokens,
            "messages": [
                {
                    "role": "system",
                    "content": "Generate diverse questions for a synthetic access-control security test. Return only a JSON array of strings. Do not add facts.",
                },
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "category": document.category,
                            "subject": document.subject,
                            "synthetic_fact": document.semantic_fact,
                            "synthetic_body": document.body,
                            "max_questions": policy.max_probes,
                        },
                        sort_keys=True,
                    ),
                },
            ],
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Host": host,
        }
        async with httpx.AsyncClient(
            timeout=min(self.timeout_seconds, 60.0),
            follow_redirects=False,
            trust_env=False,
            transport=self.transport,
        ) as client:
            try:
                response = await client.post(
                    pinned, headers=headers, json=payload, extensions={"sni_hostname": sni}
                )
            except httpx.HTTPError as exc:
                raise ProbeGenerationError("LLM probe provider request failed") from exc
        if response.status_code >= 400:
            raise ProbeGenerationError(f"LLM probe provider returned HTTP {response.status_code}")
        try:
            body = response.json()
            content = body["choices"][0]["message"]["content"]
            parsed = json.loads(content)
        except (ValueError, KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
            raise ProbeGenerationError(
                "LLM probe provider returned an invalid probe payload"
            ) from exc
        if not isinstance(parsed, list):
            raise ProbeGenerationError("LLM probe provider must return a JSON array")
        probes: list[str] = []
        for item in parsed:
            if isinstance(item, str):
                value = item.strip()
                if 3 <= len(value) <= 1000 and value not in probes:
                    probes.append(value)
                if len(probes) >= policy.max_probes:
                    break
        usage = body.get("usage") or {}
        input_tokens = (
            int(str(usage.get("prompt_tokens")))
            if str(usage.get("prompt_tokens", "")).isdigit()
            else None
        )
        output_tokens = (
            int(str(usage.get("completion_tokens")))
            if str(usage.get("completion_tokens", "")).isdigit()
            else None
        )
        estimated_cost = None
        if input_tokens is not None and output_tokens is not None:
            estimated_cost = (
                input_tokens * self.input_cost_per_million_tokens
                + output_tokens * self.output_cost_per_million_tokens
            ) / 1_000_000
            if policy.cost_budget_usd and estimated_cost > policy.cost_budget_usd:
                raise ProbeGenerationError("LLM probe generation exceeded configured cost budget")
        return probes, ProbeGenerationInfo(
            provider=self.provider,
            model=self.model,
            version=self.version,
            generated_count=len(probes),
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            estimated_cost_usd=estimated_cost,
        )
