"""POST /v1/speak — TTS through the voice routing layer."""

from __future__ import annotations

import asyncio
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from glc.voice.tts import TTSError, synthesize
from glc.voice.tts.base import SynthesizeResult

router = APIRouter()

# Prefers whose providers dial the open internet. When an egress client is
# present these run inside the domain-allowlisted Sandbox (A3). Local prefers
# (kokoro / system_fallback) stay in-process — they make no outbound calls.
_NETWORK_PREFER = frozenset({"quality", "streaming", "realtime"})


class SpeakRequest(BaseModel):
    text: str
    voice_id: str | None = None
    agent: str | None = None
    prefer: Literal["default", "quality", "streaming", "realtime", "fallback"] = "default"


class SpeakResponse(BaseModel):
    audio_b64: str
    mime: str
    sample_rate: int
    provider: str
    cost_usd: float = 0.0


async def _synthesize_via_sandbox(req: SpeakRequest, client) -> SynthesizeResult:
    """Run TTS inside the egress-walled Sandbox and rebuild SynthesizeResult."""
    envelope = await asyncio.to_thread(
        client.run,
        {
            "command": "speak",
            "text": req.text,
            "voice_id": req.voice_id,
            "prefer": req.prefer,
        },
    )
    if envelope.get("ok"):
        return SynthesizeResult(**envelope["result"])
    raise TTSError(envelope.get("error", "sandbox speak failed"), status=envelope.get("status"))


@router.post("/v1/speak", response_model=SpeakResponse)
async def speak_route(req: SpeakRequest, request: Request):
    egress = getattr(request.app.state, "egress_client", None)
    try:
        if egress is not None and req.prefer in _NETWORK_PREFER:
            r = await _synthesize_via_sandbox(req, egress)
        else:
            r = await synthesize(req.text, voice_id=req.voice_id, prefer=req.prefer)
    except TTSError as e:
        raise HTTPException(e.status or 502, str(e)) from e
    return SpeakResponse(
        audio_b64=r.audio_b64,
        mime=r.mime,
        sample_rate=r.sample_rate,
        provider=r.provider,
        cost_usd=r.cost_usd,
    )
