"""Sandbox-side worker for the A3 egress wall.

This module runs INSIDE a Modal Sandbox that was created with
`outbound_domain_allowlist` set to the provider domains. It is the only place
that performs outbound provider HTTP; the public Function delegates to it
across the process boundary.

Protocol (one command per invocation):
  - read a single JSON object from stdin: {"command": <str>, ...args}
  - dispatch on "command"
  - write a single JSON object to stdout with the result

Commands:
  - egress_probe: attempt an HTTPS GET to a URL and report reachable/blocked.
    Demonstrates the wall (allowlisted host -> ok; blocked host -> transport
    error). Result: {"ok": bool, "status"|"error"|"error_type": ...}.
  - chat: rebuild the named provider (worker or router pool) here — where the
    provider keys and the allowlisted network live — and run provider.chat().
    Result envelope: {"ok": True, "result": <normalized chat dict>} or
    {"ok": False, "error", "error_type", "status", "retryable"}.
  - embed: rebuild the named embedder here and run embedder.embed().
    Result envelope: {"ok": True, "result": <embedding dict>} or
    {"ok": False, "error", "status"}.
  - speak: run TTS via glc.voice.tts.synthesize (prefer -> provider map).
    Network-backed prefers (quality/streaming/realtime) belong here;
    local prefers stay in the Function. Result: SynthesizeResult as a dict.
  - transcribe: run STT via glc.voice.stt.transcribe. Audio arrives as
    base64 so it can cross the JSON stdin boundary. Result: TranscribeResult
    as a dict.

The provider/embedder/voice logic itself is unchanged glc code; only its
*location* moves inside the wall.
"""

from __future__ import annotations

import asyncio
import base64
import json
import sys
from dataclasses import asdict
from typing import Any

import httpx

DEFAULT_PROBE_TIMEOUT = 10.0


def _probe(url: str, timeout: float = DEFAULT_PROBE_TIMEOUT) -> dict[str, Any]:
    """Attempt an HTTPS GET and report reachability.

    A success (any HTTP status) means the Sandbox was allowed to open the TLS
    connection to the host. A transport-level exception means the host was
    unreachable — which, inside a domain-allowlisted Sandbox, is exactly what a
    blocked non-allowlisted domain looks like.
    """
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False) as client:
            resp = client.get(url)
        return {"ok": True, "status": resp.status_code, "final_url": str(resp.url)}
    except Exception as exc:  # noqa: BLE001 - any transport failure means "not reachable"
        return {"ok": False, "error": str(exc)[:300], "error_type": type(exc).__name__}


def _build_pool(pool: str) -> dict[str, Any]:
    """Rebuild a provider pool inside the sandbox from the ambient provider keys."""
    from glc import providers as P

    if pool == "router":
        return P.build_router_providers()
    from glc.cache import GeminiCache

    # A fresh cache per invocation: the Gemini prompt-cache does not persist
    # across sandbox calls (it lived in the Function's app.state before A3).
    # Functionally a cache miss, never a correctness problem.
    return P.build_providers(GeminiCache(ttl_seconds=300))


def _chat(payload: dict[str, Any]) -> dict[str, Any]:
    from glc import providers as P

    name = payload.get("provider")
    if not name:
        return {"ok": False, "error": "chat requires 'provider'", "status": 400, "retryable": False}
    pool = payload.get("pool", "worker")
    providers = _build_pool(pool)
    provider = providers.get(name)
    if provider is None:
        return {
            "ok": False,
            "error": f"provider {name!r} not configured in sandbox pool {pool!r}",
            "status": 502,
            "retryable": False,
        }
    messages = payload.get("messages") or []
    kwargs = payload.get("kwargs") or {}
    try:
        result = asyncio.run(provider.chat(messages, **kwargs))
        return {"ok": True, "result": result}
    except P.ProviderError as exc:
        return {
            "ok": False,
            "error": str(exc)[:500],
            "error_type": "ProviderError",
            "status": getattr(exc, "status", None),
            "retryable": bool(getattr(exc, "retryable", True)),
        }
    except Exception as exc:  # noqa: BLE001 - normalize any upstream failure
        return {
            "ok": False,
            "error": str(exc)[:500],
            "error_type": type(exc).__name__,
            "status": getattr(exc, "status", None),
            "retryable": True,
        }


def _embed(payload: dict[str, Any]) -> dict[str, Any]:
    from glc import embedders as E

    name = payload.get("provider")
    if not name:
        return {"ok": False, "error": "embed requires 'provider'", "status": 400}
    text = payload.get("text", "")
    task_type = payload.get("task_type", "retrieval_document")
    embedders, _names = E.build_embedders()
    registry = {e.name: e for e in embedders}
    embedder = registry.get(name)
    if embedder is None:
        return {"ok": False, "error": f"embedder {name!r} not configured in sandbox", "status": 502}
    try:
        result = asyncio.run(embedder.embed(text, task_type))
        return {"ok": True, "result": result}
    except E.EmbedderError as exc:
        return {"ok": False, "error": str(exc)[:500], "status": getattr(exc, "status", None)}
    except Exception as exc:  # noqa: BLE001 - normalize any upstream failure
        return {"ok": False, "error": str(exc)[:500], "status": getattr(exc, "status", None)}


def _speak(payload: dict[str, Any]) -> dict[str, Any]:
    """Run TTS inside the sandbox via the existing voice router."""
    from glc.voice.tts import TTSError, synthesize

    text = payload.get("text")
    if text is None:
        return {"ok": False, "error": "speak requires 'text'", "status": 400}
    prefer = payload.get("prefer", "default")
    voice_id = payload.get("voice_id")
    try:
        result = asyncio.run(synthesize(text, voice_id=voice_id, prefer=prefer))
        return {"ok": True, "result": asdict(result)}
    except TTSError as exc:
        return {"ok": False, "error": str(exc)[:500], "status": getattr(exc, "status", None)}
    except NotImplementedError as exc:
        # Stub providers raise this; the Function maps it to TTSError/501.
        return {"ok": False, "error": str(exc)[:500], "status": 501}
    except Exception as exc:  # noqa: BLE001 - normalize any upstream failure
        return {"ok": False, "error": str(exc)[:500], "status": getattr(exc, "status", None)}


def _transcribe(payload: dict[str, Any]) -> dict[str, Any]:
    """Run STT inside the sandbox via the existing voice router."""
    from glc.voice.stt import STTError, transcribe

    audio_b64 = payload.get("audio_b64")
    if not audio_b64:
        return {"ok": False, "error": "transcribe requires 'audio_b64'", "status": 400}
    try:
        audio = base64.b64decode(audio_b64)
    except Exception as exc:  # noqa: BLE001 - bad base64 is a client error
        return {"ok": False, "error": f"audio_b64 is not valid base64: {exc}", "status": 400}
    mime = payload.get("mime", "audio/wav")
    prefer = payload.get("prefer", "default")
    try:
        result = asyncio.run(transcribe(audio, mime, prefer=prefer))
        return {"ok": True, "result": asdict(result)}
    except STTError as exc:
        return {"ok": False, "error": str(exc)[:500], "status": getattr(exc, "status", None)}
    except NotImplementedError as exc:
        return {"ok": False, "error": str(exc)[:500], "status": 501}
    except Exception as exc:  # noqa: BLE001 - normalize any upstream failure
        return {"ok": False, "error": str(exc)[:500], "status": getattr(exc, "status", None)}


def handle(payload: dict[str, Any]) -> dict[str, Any]:
    """Dispatch a single command payload to its handler."""
    command = payload.get("command")
    if command == "egress_probe":
        url = payload.get("url")
        if not url:
            return {"ok": False, "error": "egress_probe requires a 'url'"}
        timeout = float(payload.get("timeout", DEFAULT_PROBE_TIMEOUT))
        return _probe(url, timeout=timeout)
    if command == "chat":
        return _chat(payload)
    if command == "embed":
        return _embed(payload)
    if command == "speak":
        return _speak(payload)
    if command == "transcribe":
        return _transcribe(payload)
    return {"ok": False, "error": f"unknown command: {command!r}"}


def main() -> None:
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError as exc:
        sys.stdout.write(json.dumps({"ok": False, "error": f"invalid json: {exc}"}))
        sys.stdout.flush()
        return
    result = handle(payload)
    sys.stdout.write(json.dumps(result))
    sys.stdout.flush()


if __name__ == "__main__":
    main()
