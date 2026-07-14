"""A3 (egress wall) — voice routes go through the Sandbox when they dial out.

/v1/speak and /v1/transcribe keep local providers in-process (kokoro,
system_fallback, whisper.cpp) and relocate network-backed prefers into the
domain-allowlisted Sandbox when an egress client is present.
"""

from __future__ import annotations

import base64

from fastapi.testclient import TestClient

from glc.egress import worker


class _FakeEgressClient:
    def __init__(self, *, speak_result=None, transcribe_result=None, fail=None):
        self.calls: list[dict] = []
        self._speak = speak_result
        self._transcribe = transcribe_result
        self._fail = fail

    def run(self, payload):
        self.calls.append(payload)
        if self._fail is not None:
            return self._fail
        command = payload.get("command")
        if command == "speak":
            return {"ok": True, "result": self._speak}
        if command == "transcribe":
            return {"ok": True, "result": self._transcribe}
        return {"ok": False, "error": f"unexpected command {command!r}"}


def _app_with_egress(monkeypatch, fake):
    import glc.main as m
    from glc.security.auth import require_data_plane_auth

    app = m.create_app()
    app.state.egress_client = fake
    app.dependency_overrides[require_data_plane_auth] = lambda: None
    return app


# ── worker dispatch ───────────────────────────────────────────────────────


def test_worker_speak_success(monkeypatch):
    from glc.voice.tts import base as tts_base
    from glc.voice.tts import router as tts_router

    async def _fake_synthesize(text, voice_id=None, prefer="default"):
        return tts_base.SynthesizeResult(
            audio_b64="YWFh",
            mime="audio/mpeg",
            sample_rate=44100,
            provider="elevenlabs",
            cost_usd=0.0,
        )

    monkeypatch.setattr(tts_router, "synthesize", _fake_synthesize)
    # worker imports synthesize from glc.voice.tts package __init__
    import glc.voice.tts as tts_pkg

    monkeypatch.setattr(tts_pkg, "synthesize", _fake_synthesize)

    out = worker.handle({"command": "speak", "text": "hi", "prefer": "quality"})
    assert out["ok"] is True
    assert out["result"]["provider"] == "elevenlabs"
    assert out["result"]["audio_b64"] == "YWFh"


def test_worker_speak_tts_error(monkeypatch):
    from glc.voice.tts import TTSError
    import glc.voice.tts as tts_pkg

    async def _boom(text, voice_id=None, prefer="default"):
        raise TTSError("quota", status=429)

    monkeypatch.setattr(tts_pkg, "synthesize", _boom)
    out = worker.handle({"command": "speak", "text": "hi", "prefer": "quality"})
    assert out["ok"] is False
    assert out["status"] == 429


def test_worker_transcribe_success(monkeypatch):
    from glc.voice.stt import base as stt_base
    import glc.voice.stt as stt_pkg

    async def _fake_transcribe(audio, mime, prefer="default"):
        return stt_base.TranscribeResult(
            text="hello",
            language="en",
            duration_ms=12,
            provider="groq_whisper",
            cost_usd=0.0,
        )

    monkeypatch.setattr(stt_pkg, "transcribe", _fake_transcribe)
    out = worker.handle(
        {
            "command": "transcribe",
            "audio_b64": base64.b64encode(b"\x00\x00").decode(),
            "mime": "audio/wav",
            "prefer": "default",
        }
    )
    assert out["ok"] is True
    assert out["result"]["text"] == "hello"
    assert out["result"]["provider"] == "groq_whisper"


def test_worker_transcribe_requires_audio():
    out = worker.handle({"command": "transcribe", "prefer": "default"})
    assert out["ok"] is False
    assert out["status"] == 400


# ── route integration ─────────────────────────────────────────────────────


def test_speak_network_prefer_goes_through_sandbox(monkeypatch):
    fake = _FakeEgressClient(
        speak_result={
            "audio_b64": "YWFh",
            "mime": "audio/mpeg",
            "sample_rate": 44100,
            "provider": "elevenlabs",
            "cost_usd": 0.0,
        }
    )
    app = _app_with_egress(monkeypatch, fake)
    with TestClient(app) as client:
        r = client.post("/v1/speak", json={"text": "hi", "prefer": "quality"})
    assert r.status_code == 200, r.text
    assert r.json()["provider"] == "elevenlabs"
    assert fake.calls and fake.calls[0]["command"] == "speak"
    assert fake.calls[0]["prefer"] == "quality"


def test_speak_local_prefer_skips_sandbox(monkeypatch):
    """prefer=default (kokoro) must not dial the Sandbox even when the wall is on."""
    from glc.voice.tts.base import SynthesizeResult, TTSProvider
    from glc.voice.tts.router import register_test_provider

    class FakeKokoro(TTSProvider):
        name = "kokoro"

        async def synthesize(self, text, voice_id=None):
            return SynthesizeResult(
                audio_b64="bG9jYWw=",
                mime="audio/wav",
                sample_rate=24000,
                provider="kokoro",
                cost_usd=0.0,
            )

    register_test_provider("kokoro", FakeKokoro())
    try:
        fake = _FakeEgressClient(speak_result={"should": "not be used"})
        app = _app_with_egress(monkeypatch, fake)
        with TestClient(app) as client:
            r = client.post("/v1/speak", json={"text": "hi", "prefer": "default"})
        assert r.status_code == 200, r.text
        assert r.json()["provider"] == "kokoro"
        assert fake.calls == []
    finally:
        register_test_provider("kokoro", None)


def test_transcribe_network_prefer_goes_through_sandbox(monkeypatch):
    fake = _FakeEgressClient(
        transcribe_result={
            "text": "via sandbox",
            "language": "en",
            "duration_ms": 9,
            "provider": "groq_whisper",
            "cost_usd": 0.0,
        }
    )
    app = _app_with_egress(monkeypatch, fake)
    with TestClient(app) as client:
        r = client.post(
            "/v1/transcribe",
            json={
                "audio_b64": base64.b64encode(b"\x00" * 8).decode(),
                "mime": "audio/wav",
                "prefer": "default",
            },
        )
    assert r.status_code == 200, r.text
    assert r.json()["text"] == "via sandbox"
    assert fake.calls and fake.calls[0]["command"] == "transcribe"


def test_transcribe_local_prefer_skips_sandbox(monkeypatch):
    from glc.voice.stt.base import STTProvider, TranscribeResult
    from glc.voice.stt.router import register_test_provider

    class FakeLocal(STTProvider):
        name = "whisper_cpp"

        async def transcribe(self, audio, mime):
            return TranscribeResult(
                text="local",
                language="en",
                duration_ms=1,
                provider="whisper_cpp",
                cost_usd=0.0,
            )

    register_test_provider("whisper_cpp", FakeLocal())
    try:
        fake = _FakeEgressClient(transcribe_result={"should": "not be used"})
        app = _app_with_egress(monkeypatch, fake)
        with TestClient(app) as client:
            r = client.post(
                "/v1/transcribe",
                json={
                    "audio_b64": base64.b64encode(b"\x00").decode(),
                    "mime": "audio/wav",
                    "prefer": "local",
                },
            )
        assert r.status_code == 200, r.text
        assert r.json()["provider"] == "whisper_cpp"
        assert fake.calls == []
    finally:
        register_test_provider("whisper_cpp", None)
