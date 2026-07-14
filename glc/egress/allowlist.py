"""Minimal provider egress allowlist for the A3 Sandbox wall.

Single source of truth for the domains the gateway legitimately needs to
reach when it makes outbound provider calls. This list is passed verbatim to
`modal.Sandbox.create(outbound_domain_allowlist=...)`, which restricts the
Sandbox's outbound TLS (port 443) traffic to exactly these hosts. Anything
else — the classic exfiltration / SSRF target — is blocked by Modal.

Scope decision (deliberate):
  - INCLUDED: the fixed base URLs of the configured LLM, embedding, and voice
    providers. Each entry below names the module that dials it.
  - EXCLUDED: anything whose host is chosen at request time. That means
    user-supplied image URLs (glc/routes/chat.py::_resolve_image_urls),
    `WEBHOOK_DEFAULT_TARGET_URL`, and the channel/demo APIs (Telegram,
    Discord, Teams, WhatsApp/Twilio, Slack, LINE, Gmail). Putting an
    attacker-controllable host on the provider wall would defeat the wall.
    If a deployment must support one of those, it belongs behind its own
    explicit, separately-reviewed opt-in — not in this list.
  - EXCLUDED: `OLLAMA_URL` (local, defaults to http://localhost:11434). Local
    loopback is not internet egress and is not a provider domain.

Entries are exact hostnames (no `*.` wildcards) to keep the wall as tight as
Modal allows; `*.` would widen the match to every subdomain.
"""

from __future__ import annotations

PROVIDER_EGRESS_ALLOWLIST: tuple[str, ...] = (
    # Google Gemini: chat (glc/providers.py::GeminiProvider), prompt cache
    # (glc/cache.py), embeddings (glc/embedders.py::GeminiEmbedder), and the
    # Gemini Live voice WebSocket (glc/voice/*/gemini_live).
    "generativelanguage.googleapis.com",
    # Groq: chat/router worker (glc/providers.py::GroqProvider) and Whisper
    # STT (glc/voice/stt/providers/groq_whisper).
    "api.groq.com",
    # Cerebras chat/router worker (glc/providers.py::CerebrasProvider).
    "api.cerebras.ai",
    # NVIDIA NIM chat/router worker (glc/providers.py::NvidiaProvider).
    "integrate.api.nvidia.com",
    # OpenRouter chat worker (glc/providers.py::OpenRouterProvider).
    "openrouter.ai",
    # GitHub Models chat/router worker (glc/providers.py::GitHubProvider).
    "models.github.ai",
    # Cartesia Sonic TTS (glc/voice/tts/providers/cartesia).
    "api.cartesia.ai",
    # ElevenLabs Flash TTS (glc/voice/tts/providers/elevenlabs).
    "api.elevenlabs.io",
)
