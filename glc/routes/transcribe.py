"""POST /v1/transcribe — STT through the voice routing layer."""

from __future__ import annotations

import asyncio
import base64
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from glc.voice.stt import STTError, transcribe
from glc.voice.stt.base import TranscribeResult

router = APIRouter()

# Prefers whose providers dial the open internet. When an egress client is
# present these run inside the domain-allowlisted Sandbox (A3). `local`
# (whisper.cpp) stays in-process — it makes no outbound calls.
_NETWORK_PREFER = frozenset({"default", "streaming"})


class TranscribeRequest(BaseModel):
    audio_b64: str
    mime: str = "audio/wav"
    agent: str | None = None
    prefer: Literal["default", "local", "streaming"] = "default"


class TranscribeResponse(BaseModel):
    text: str
    language: str
    duration_ms: int
    provider: str
    cost_usd: float = Field(default=0.0)


async def _transcribe_via_sandbox(req: TranscribeRequest, client) -> TranscribeResult:
    """Run STT inside the egress-walled Sandbox and rebuild TranscribeResult."""
    envelope = await asyncio.to_thread(
        client.run,
        {
            "command": "transcribe",
            "audio_b64": req.audio_b64,
            "mime": req.mime,
            "prefer": req.prefer,
        },
    )
    if envelope.get("ok"):
        return TranscribeResult(**envelope["result"])
    raise STTError(envelope.get("error", "sandbox transcribe failed"), status=envelope.get("status"))


@router.post("/v1/transcribe", response_model=TranscribeResponse)
async def transcribe_route(req: TranscribeRequest, request: Request):
    try:
        audio = base64.b64decode(req.audio_b64)
    except Exception as e:
        raise HTTPException(400, f"audio_b64 is not valid base64: {e}") from e

    egress = getattr(request.app.state, "egress_client", None)
    try:
        if egress is not None and req.prefer in _NETWORK_PREFER:
            r = await _transcribe_via_sandbox(req, egress)
        else:
            r = await transcribe(audio, req.mime, prefer=req.prefer)
    except STTError as e:
        if req.prefer == "streaming":
            raise HTTPException(400, str(e)) from e
        raise HTTPException(e.status or 502, str(e)) from e
    return TranscribeResponse(
        text=r.text,
        language=r.language,
        duration_ms=r.duration_ms,
        provider=r.provider,
        cost_usd=r.cost_usd,
    )
