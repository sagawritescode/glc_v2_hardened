"""Provider API-key environment variable names (A4).

These names are the credentials Section 2 theft reads from ``os.environ`` when
they live in the public Modal Function. After A4 they must be injected only
into the domain-allowlisted Sandbox (``glc-llm-keys``), never into the public
Function's environment alongside the data-plane auth token.

This module is the single source of truth for *which* env vars count as
provider secrets. Later A4 steps use it for catalog boot (no key reads) and
for regression probes that assert the Function path has none of them set.
"""

from __future__ import annotations

PROVIDER_SECRET_ENV_VARS: frozenset[str] = frozenset(
    {
        # LLM / embed / Gemini Live voice (glc/providers.py, embedders, voice).
        "GEMINI_API_KEY",
        "NVIDIA_API_KEY",
        "GROQ_API_KEY",
        "CEREBRAS_API_KEY",
        "OPEN_ROUTER_API_KEY",
        "GITHUB_ACCESS_TOKEN",
        # Network TTS providers (glc/voice/tts).
        "CARTESIA_API_KEY",
        "ELEVENLABS_API_KEY",
    }
)
