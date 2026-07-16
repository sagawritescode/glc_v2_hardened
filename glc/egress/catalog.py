"""Keyless Function-side provider metadata for the A4 / A3 egress wall.

When provider API keys live only in the Sandbox, the public Function cannot
call ``build_providers()`` / ``build_embedders()`` (those gate on key env vars
and would return an empty pool). This module builds lightweight stubs that
expose the metadata ``RemoteProvider`` / ``RemoteEmbedder`` and listing routes
need, without ever reading ``PROVIDER_SECRET_ENV_VARS``.

Real provider objects with real keys are still constructed inside the Sandbox
worker via ``glc.providers.build_providers`` / ``glc.embedders.build_embedders``.
"""

from __future__ import annotations

import os
from types import SimpleNamespace
from typing import Any

from glc import embedders as E
from glc import providers as P


def _stub(
    *,
    name: str,
    model: str,
    base_url: str,
    default_caps: dict[str, Any],
) -> SimpleNamespace:
    """Metadata-only stand-in; deliberately has no ``api_key`` attribute."""
    return SimpleNamespace(
        name=name,
        model=model,
        base_url=base_url,
        capabilities=P.model_capabilities(name, model, default_caps),
    )


def build_egress_provider_catalog() -> dict[str, Any]:
    """Worker-pool catalog for the Function when the egress wall is on.

    Always includes the cloud workers (keys may or may not exist in the
    Sandbox — missing keys surface later as Sandbox ``ProviderError``).
    Ollama is included only when ``OLLAMA_MODEL`` is set (same rule as
    ``build_providers``, and it needs no API key).
    """
    openai_caps = dict(P.OpenAICompatProvider.capabilities)
    openai_reasoning_caps = {**openai_caps, "reasoning": True}

    out: dict[str, Any] = {
        "gemini": _stub(
            name="gemini",
            model=os.getenv("GEMINI_MODEL", "gemini-2.5-flash"),
            base_url="https://generativelanguage.googleapis.com/v1beta",
            default_caps=dict(P.GeminiProvider.capabilities),
        ),
        "nvidia": _stub(
            name="nvidia",
            model=os.getenv("NVIDIA_MODEL", "deepseek-ai/deepseek-v3.2"),
            base_url="https://integrate.api.nvidia.com/v1",
            default_caps=openai_reasoning_caps,
        ),
        "groq": _stub(
            name="groq",
            model=os.getenv("GROQ_MODEL", "openai/gpt-oss-120b"),
            base_url="https://api.groq.com/openai/v1",
            default_caps=openai_reasoning_caps,
        ),
        "cerebras": _stub(
            name="cerebras",
            model=os.getenv("CEREBRAS_MODEL", "zai-glm-4.7"),
            base_url="https://api.cerebras.ai/v1",
            default_caps=openai_reasoning_caps,
        ),
        "openrouter": _stub(
            name="openrouter",
            model=os.getenv("OPENROUTER_MODEL", "nvidia/nemotron-3-super-120b-a12b:free"),
            base_url="https://openrouter.ai/api/v1",
            default_caps=openai_reasoning_caps,
        ),
        "github": _stub(
            name="github",
            model=os.getenv("GITHUB_MODEL", "openai/gpt-4.1-mini"),
            base_url="https://models.github.ai/inference",
            default_caps=openai_reasoning_caps,
        ),
    }

    if om := os.getenv("OLLAMA_MODEL"):
        out["ollama"] = _stub(
            name="ollama",
            model=om,
            base_url=os.getenv("OLLAMA_URL", "http://localhost:11434"),
            default_caps=dict(P.OllamaProvider.capabilities),
        )
    return out


def build_egress_router_catalog() -> dict[str, Any]:
    """Router-pool catalog for the Function when the egress wall is on.

    Same four providers as ``build_router_providers``, with router-specific
    model defaults from ``ROUTER_DEFAULTS`` / ``ROUTER_*_MODEL``. Never reads
    provider secret env vars.
    """
    openai_reasoning_caps = {
        **dict(P.OpenAICompatProvider.capabilities),
        "reasoning": True,
    }
    defaults = P.ROUTER_DEFAULTS
    return {
        "cerebras": _stub(
            name="cerebras",
            model=os.getenv("ROUTER_CEREBRAS_MODEL", defaults["cerebras"]),
            base_url="https://api.cerebras.ai/v1",
            default_caps=openai_reasoning_caps,
        ),
        "groq": _stub(
            name="groq",
            model=os.getenv("ROUTER_GROQ_MODEL", defaults["groq"]),
            base_url="https://api.groq.com/openai/v1",
            default_caps=openai_reasoning_caps,
        ),
        "nvidia": _stub(
            name="nvidia",
            model=os.getenv("ROUTER_NVIDIA_MODEL", defaults["nvidia"]),
            base_url="https://integrate.api.nvidia.com/v1",
            default_caps=openai_reasoning_caps,
        ),
        "github": _stub(
            name="github",
            model=os.getenv("ROUTER_GITHUB_MODEL", defaults["github"]),
            base_url="https://models.github.ai/inference",
            default_caps=openai_reasoning_caps,
        ),
    }


def build_egress_embedder_catalog() -> tuple[list[Any], list[str]]:
    """Embedder catalog for the Function when the egress wall is on.

    Same shape as ``build_embedders()``: ``(embedders, order_names)``.
    Ollama needs no key. Gemini is always registered when it is the configured
    fallback — without reading ``GEMINI_API_KEY`` — so failover metadata and
    ``RemoteEmbedder.state`` still work. Never attaches an ``api_key``.
    """
    ollama_model = os.getenv("EMBED_OLLAMA_MODEL", "nomic-embed-text")
    fallback_provider = os.getenv("EMBED_FALLBACK_PROVIDER", "gemini").lower()
    fallback_model = os.getenv("EMBED_FALLBACK_MODEL", "gemini-embedding-001")

    # RemoteEmbedder only needs name / model / state; OLLAMA_URL is used inside
    # the Sandbox when the worker rebuilds the real OllamaEmbedder.
    registry: dict[str, Any] = {
        "ollama": SimpleNamespace(
            name="ollama",
            model=ollama_model,
            state=E.EmbedRateState(rpm=0, cooldown=0.0),
        ),
    }
    if fallback_provider == "gemini":
        # Match GeminiEmbedder's default rate limits so Function-side failover
        # gating behaves the same after RemoteEmbedder wrap.
        registry["gemini"] = SimpleNamespace(
            name="gemini",
            model=fallback_model,
            state=E.EmbedRateState(rpm=5, cooldown=5.0),
        )

    default_order = ["ollama", fallback_provider]
    order_env = os.getenv("EMBED_ORDER", ",".join(default_order))
    order = [n.strip() for n in order_env.split(",") if n.strip()]
    embedders = [registry[n] for n in order if n in registry]
    return embedders, [e.name for e in embedders]
