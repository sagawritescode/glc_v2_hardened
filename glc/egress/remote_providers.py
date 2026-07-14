"""Function-side provider/embedder proxies for the A3 egress wall.

These wrap the real `glc.providers` / `glc.embedders` objects but relocate only
the *network* methods (`chat`, `stream`, `embed`) into a domain-allowlisted
Modal Sandbox via `SandboxEgressClient`. Everything else — the provider's
`name`/`model`/`capabilities` metadata and the embedder's in-process rate state
— stays in the Function, so the router, retry loop, DB logging, and rate/quota
bookkeeping in `glc/routes/chat.py` and `glc/embedders.py` work unchanged.

The Function never opens a provider connection itself; it only ships a JSON
command to the sandbox worker and interprets the reply. The blocking Modal I/O
is offloaded with `asyncio.to_thread` so the event loop is not stalled.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any


def _jsonify_tools(tools: Any) -> list[dict] | None:
    if not tools:
        return None
    return [t.model_dump() if hasattr(t, "model_dump") else t for t in tools]


def _jsonify_response_format(response_format: Any) -> Any:
    if response_format is None or isinstance(response_format, dict):
        return response_format
    if hasattr(response_format, "model_dump"):
        return response_format.model_dump(by_alias=True)
    return response_format


def _jsonify_system_blocks(system_blocks: Any) -> Any:
    if system_blocks is None or isinstance(system_blocks, str):
        return system_blocks
    if isinstance(system_blocks, list):
        return [b.model_dump() if hasattr(b, "model_dump") else b for b in system_blocks]
    return system_blocks


class RemoteProvider:
    """Runs `provider.chat()` inside the egress-walled sandbox.

    Mirrors the metadata surface the router reads (`name`, `model`,
    `capabilities`, `base_url`) so it is a drop-in for a real provider.
    """

    def __init__(self, real: Any, client: Any, pool: str) -> None:
        self.name = real.name
        self.model = real.model
        self.capabilities = getattr(real, "capabilities", {})
        self.base_url = getattr(real, "base_url", "")
        self._client = client
        self._pool = pool

    def _payload(
        self,
        messages: Any,
        *,
        max_tokens: int,
        temperature: float,
        model: Any,
        tools: Any,
        tool_choice: Any,
        reasoning: Any,
        response_format: Any,
        system_blocks: Any,
        cache_system: bool,
    ) -> dict[str, Any]:
        return {
            "command": "chat",
            "pool": self._pool,
            "provider": self.name,
            "messages": messages,
            "kwargs": {
                "max_tokens": max_tokens,
                "temperature": temperature,
                "model": model,
                "tools": _jsonify_tools(tools),
                "tool_choice": tool_choice,
                "reasoning": reasoning,
                "response_format": _jsonify_response_format(response_format),
                "system_blocks": _jsonify_system_blocks(system_blocks),
                "cache_system": cache_system,
            },
        }

    @staticmethod
    def _unwrap(envelope: dict[str, Any]) -> dict[str, Any]:
        from glc import providers as P

        if envelope.get("ok"):
            return envelope["result"]
        raise P.ProviderError(
            envelope.get("error", "sandbox chat failed"),
            status=envelope.get("status"),
            retryable=bool(envelope.get("retryable", True)),
        )

    async def chat(
        self,
        messages: Any,
        *,
        max_tokens: int = 2048,
        temperature: float = 0.7,
        model: Any = None,
        tools: Any = None,
        tool_choice: Any = None,
        reasoning: Any = None,
        response_format: Any = None,
        system_blocks: Any = None,
        cache_system: bool = False,
    ) -> dict[str, Any]:
        payload = self._payload(
            messages,
            max_tokens=max_tokens,
            temperature=temperature,
            model=model,
            tools=tools,
            tool_choice=tool_choice,
            reasoning=reasoning,
            response_format=response_format,
            system_blocks=system_blocks,
            cache_system=cache_system,
        )
        envelope = await asyncio.to_thread(self._client.run, payload)
        return self._unwrap(envelope)

    async def stream(
        self,
        messages: Any,
        *,
        max_tokens: int = 2048,
        temperature: float = 0.7,
        model: Any = None,
        tools: Any = None,
        tool_choice: Any = None,
        reasoning: Any = None,
        response_format: Any = None,
        system_blocks: Any = None,
        cache_system: bool = False,
    ) -> AsyncIterator[str]:
        # Step 2: run the call in the sandbox and emit the text in one chunk
        # (matches BaseProvider's non-streaming fallback). Incremental
        # token-by-token streaming across the sandbox boundary is a later
        # checkpoint; the SSE envelope shape in chat.py is preserved.
        result = await self.chat(
            messages,
            max_tokens=max_tokens,
            temperature=temperature,
            model=model,
            tools=tools,
            tool_choice=tool_choice,
            reasoning=reasoning,
            response_format=response_format,
            system_blocks=system_blocks,
            cache_system=cache_system,
        )
        if result.get("text"):
            yield result["text"]


class RemoteEmbedder:
    """Runs `embedder.embed()` inside the egress-walled sandbox.

    Keeps the real embedder's `state` (EmbedRateState) object so the Function's
    failover/rate/backoff gating in `embed_with_failover` is unchanged.
    """

    def __init__(self, real: Any, client: Any) -> None:
        self.name = real.name
        self.model = real.model
        self.state = real.state
        self._client = client

    async def embed(self, text: str, task_type: str) -> dict[str, Any]:
        payload = {
            "command": "embed",
            "provider": self.name,
            "text": text,
            "task_type": task_type,
        }
        envelope = await asyncio.to_thread(self._client.run, payload)
        if envelope.get("ok"):
            return envelope["result"]
        from glc import embedders as E

        raise E.EmbedderError(
            envelope.get("error", "sandbox embed failed"),
            status=envelope.get("status"),
        )


def wrap_for_egress(
    *,
    providers: dict[str, Any],
    router_providers: dict[str, Any],
    embedders: list[Any],
    client: Any,
) -> tuple[dict[str, Any], dict[str, Any], list[Any]]:
    """Wrap built providers/embedders so their network calls run in the sandbox."""
    wrapped_providers = {n: RemoteProvider(p, client, "worker") for n, p in providers.items()}
    wrapped_routers = {n: RemoteProvider(p, client, "router") for n, p in router_providers.items()}
    wrapped_embedders = [RemoteEmbedder(e, client) for e in embedders]
    return wrapped_providers, wrapped_routers, wrapped_embedders
