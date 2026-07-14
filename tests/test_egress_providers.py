"""A3 (egress wall) — step 2 regression.

Provider/embedder network calls are relocated behind the Modal Sandbox wall via
`RemoteProvider` / `RemoteEmbedder` proxies. These tests prove, without a live
Modal network:

- the proxies forward the call to the egress client (serializing pydantic
  tools / response_format), preserve provider metadata + embedder rate-state,
  and re-raise provider/embedder errors so the existing retry/failover logic is
  unchanged;
- the sandbox-side worker rebuilds the named provider/embedder and runs the
  real call there, returning a normalized envelope; and
- with an egress client injected, `/v1/chat` and `/v1/embed` actually route the
  outbound call through the sandbox path (the wall), not in-process.
"""

from __future__ import annotations

import asyncio
import types

import pytest
from fastapi.testclient import TestClient

from glc.egress import worker
from glc.egress.remote_providers import RemoteEmbedder, RemoteProvider, wrap_for_egress

# ── proxy unit tests ──────────────────────────────────────────────────────


class _RecordingClient:
    def __init__(self, response):
        self.calls: list[dict] = []
        self._response = response

    def run(self, payload):
        self.calls.append(payload)
        return self._response


def test_remote_provider_forwards_and_serializes():
    client = _RecordingClient({"ok": True, "result": {"text": "x"}})
    real = types.SimpleNamespace(name="gemini", model="m", capabilities={"tools": True}, base_url="u")
    proxy = RemoteProvider(real, client, "worker")

    from glc.llm_schemas import ResponseFormat, ToolDef

    tools = [ToolDef(name="t", description="d", input_schema={"type": "object"})]
    rf = ResponseFormat(type="json_object")

    out = asyncio.run(proxy.chat([{"role": "user", "content": "hi"}], tools=tools, response_format=rf))

    assert out == {"text": "x"}
    payload = client.calls[0]
    assert payload["command"] == "chat"
    assert payload["pool"] == "worker"
    assert payload["provider"] == "gemini"
    # pydantic tools/response_format are serialized to JSON-safe dicts.
    assert payload["kwargs"]["tools"] == [
        {"name": "t", "description": "d", "input_schema": {"type": "object"}}
    ]
    assert payload["kwargs"]["response_format"] == {
        "type": "json_object",
        "schema": None,
        "name": "out",
        "strict": True,
    }
    # metadata surface the router reads is preserved.
    assert proxy.model == "m"
    assert proxy.capabilities == {"tools": True}


def test_remote_provider_raises_provider_error():
    from glc import providers as P

    client = _RecordingClient({"ok": False, "error": "nope", "status": 401, "retryable": False})
    real = types.SimpleNamespace(name="g", model="m", capabilities={}, base_url="")
    proxy = RemoteProvider(real, client, "worker")

    with pytest.raises(P.ProviderError) as ei:
        asyncio.run(proxy.chat([{"role": "user", "content": "hi"}]))
    assert ei.value.status == 401
    assert ei.value.retryable is False


def test_remote_provider_stream_yields_text():
    client = _RecordingClient({"ok": True, "result": {"text": "streamed", "tool_calls": []}})
    real = types.SimpleNamespace(name="g", model="m", capabilities={}, base_url="")
    proxy = RemoteProvider(real, client, "worker")

    async def _collect():
        return [chunk async for chunk in proxy.stream([{"role": "user", "content": "hi"}])]

    assert asyncio.run(_collect()) == ["streamed"]


def test_remote_embedder_keeps_state_and_forwards():
    sentinel_state = object()
    client = _RecordingClient({"ok": True, "result": {"embedding": [1.0], "dim": 1, "model": "nomic"}})
    real = types.SimpleNamespace(name="ollama", model="nomic", state=sentinel_state)
    proxy = RemoteEmbedder(real, client)

    # rate-state object is kept in-process so failover/backoff gating is unchanged.
    assert proxy.state is sentinel_state

    out = asyncio.run(proxy.embed("hi", "retrieval_query"))
    assert out["dim"] == 1
    payload = client.calls[0]
    assert payload["command"] == "embed"
    assert payload["provider"] == "ollama"
    assert payload["task_type"] == "retrieval_query"


def test_remote_embedder_raises_embedder_error():
    from glc import embedders as E

    client = _RecordingClient({"ok": False, "error": "down", "status": 503})
    real = types.SimpleNamespace(name="gemini", model="g", state=object())
    proxy = RemoteEmbedder(real, client)

    with pytest.raises(E.EmbedderError) as ei:
        asyncio.run(proxy.embed("hi", "retrieval_document"))
    assert ei.value.status == 503


def test_wrap_for_egress_wraps_all_pools():
    client = _RecordingClient({"ok": True, "result": {}})
    providers = {"gemini": types.SimpleNamespace(name="gemini", model="m", capabilities={}, base_url="")}
    routers = {"cerebras": types.SimpleNamespace(name="cerebras", model="r", capabilities={}, base_url="")}
    embedders = [types.SimpleNamespace(name="ollama", model="nomic", state=object())]

    wp, wr, we = wrap_for_egress(
        providers=providers, router_providers=routers, embedders=embedders, client=client
    )
    assert isinstance(wp["gemini"], RemoteProvider) and wp["gemini"]._pool == "worker"
    assert isinstance(wr["cerebras"], RemoteProvider) and wr["cerebras"]._pool == "router"
    assert isinstance(we[0], RemoteEmbedder)


# ── worker dispatch tests ─────────────────────────────────────────────────


def test_worker_chat_success(monkeypatch):
    from glc import providers as P

    class _FakeProv:
        name = "gemini"
        model = "m"

        async def chat(self, messages, **kwargs):
            return {"text": "ok", "tool_calls": [], "model": "m"}

    monkeypatch.setattr(P, "build_providers", lambda cache: {"gemini": _FakeProv()})
    out = worker.handle(
        {
            "command": "chat",
            "pool": "worker",
            "provider": "gemini",
            "messages": [{"role": "user", "content": "hi"}],
            "kwargs": {"max_tokens": 10},
        }
    )
    assert out["ok"] is True
    assert out["result"]["text"] == "ok"


def test_worker_chat_provider_error(monkeypatch):
    from glc import providers as P

    class _BoomProv:
        name = "gemini"
        model = "m"

        async def chat(self, messages, **kwargs):
            raise P.ProviderError("rate limited", status=429, retryable=True)

    monkeypatch.setattr(P, "build_providers", lambda cache: {"gemini": _BoomProv()})
    out = worker.handle(
        {"command": "chat", "pool": "worker", "provider": "gemini", "messages": [], "kwargs": {}}
    )
    assert out["ok"] is False
    assert out["status"] == 429
    assert out["error_type"] == "ProviderError"
    assert out["retryable"] is True


def test_worker_chat_unknown_provider(monkeypatch):
    from glc import providers as P

    monkeypatch.setattr(P, "build_providers", lambda cache: {})
    out = worker.handle(
        {"command": "chat", "pool": "worker", "provider": "gemini", "messages": [], "kwargs": {}}
    )
    assert out["ok"] is False
    assert out["status"] == 502


def test_worker_chat_uses_router_pool(monkeypatch):
    from glc import providers as P

    class _FakeProv:
        name = "cerebras"
        model = "m"

        async def chat(self, messages, **kwargs):
            return {"text": "TINY"}

    called = {}

    def _fake_router():
        called["router"] = True
        return {"cerebras": _FakeProv()}

    monkeypatch.setattr(P, "build_router_providers", _fake_router)
    out = worker.handle(
        {"command": "chat", "pool": "router", "provider": "cerebras", "messages": [], "kwargs": {}}
    )
    assert out["ok"] is True
    assert called.get("router") is True


def test_worker_embed_success(monkeypatch):
    from glc import embedders as E

    class _FakeEmb:
        name = "ollama"
        model = "nomic"

        async def embed(self, text, task_type):
            return {"embedding": [1.0], "model": "nomic", "dim": 1}

    monkeypatch.setattr(E, "build_embedders", lambda: ([_FakeEmb()], ["ollama"]))
    out = worker.handle(
        {"command": "embed", "provider": "ollama", "text": "hi", "task_type": "retrieval_query"}
    )
    assert out["ok"] is True
    assert out["result"]["dim"] == 1


def test_worker_embed_error(monkeypatch):
    from glc import embedders as E

    class _BoomEmb:
        name = "gemini"
        model = "g"

        async def embed(self, text, task_type):
            raise E.EmbedderError("boom", status=503)

    monkeypatch.setattr(E, "build_embedders", lambda: ([_BoomEmb()], ["gemini"]))
    out = worker.handle(
        {"command": "embed", "provider": "gemini", "text": "hi", "task_type": "retrieval_document"}
    )
    assert out["ok"] is False
    assert out["status"] == 503


# ── route integration tests (the wall in the request path) ─────────────────

CHAT_RESULT = {
    "text": "hello from the sandbox",
    "tool_calls": [],
    "input_tokens": 3,
    "output_tokens": 5,
    "cache_creation_input_tokens": 0,
    "cache_read_input_tokens": 0,
    "stop_reason": "end_turn",
    "model": "gemini-2.5-flash",
    "tool_call_dialect": "native",
    "reasoning_applied": False,
}


class _FakeEgressClient:
    def __init__(self, chat_result=None, embed_result=None):
        self.calls: list[dict] = []
        self._chat_result = chat_result
        self._embed_result = embed_result

    def run(self, payload):
        self.calls.append(payload)
        command = payload.get("command")
        if command == "chat":
            return {"ok": True, "result": self._chat_result}
        if command == "embed":
            return {"ok": True, "result": self._embed_result}
        return {"ok": False, "error": f"unexpected command {command!r}"}


def _egress_app(monkeypatch, fake_client, env=None):
    for key, value in (env or {}).items():
        monkeypatch.setenv(key, value)
    import glc.main as m
    from glc.security.auth import require_data_plane_auth

    app = m.create_app()
    # Injecting the client before the lifespan runs is how the Modal deploy
    # wrapper turns the wall on; the lifespan then wraps the providers.
    app.state.egress_client = fake_client
    app.dependency_overrides[require_data_plane_auth] = lambda: None
    return app


def test_chat_route_goes_through_sandbox(monkeypatch):
    fake = _FakeEgressClient(chat_result=CHAT_RESULT)
    app = _egress_app(monkeypatch, fake, {"GEMINI_API_KEY": "fake-key-for-metadata"})
    with TestClient(app) as client:
        r = client.post("/v1/chat", json={"prompt": "hi", "provider": "gemini"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["text"] == "hello from the sandbox"
    assert body["provider"] == "gemini"
    chat_calls = [p for p in fake.calls if p.get("command") == "chat"]
    assert chat_calls, "chat did not route through the egress client"
    assert chat_calls[0]["pool"] == "worker"
    assert chat_calls[0]["provider"] == "gemini"


def test_embed_route_goes_through_sandbox(monkeypatch):
    fake = _FakeEgressClient(
        embed_result={"embedding": [0.1, 0.2, 0.3], "model": "nomic-embed-text", "dim": 3}
    )
    app = _egress_app(monkeypatch, fake)  # ollama embedder is always registered
    with TestClient(app) as client:
        r = client.post("/v1/embed", json={"text": "hello"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["embedding"] == [0.1, 0.2, 0.3]
    assert body["provider"] == "ollama"
    embed_calls = [p for p in fake.calls if p.get("command") == "embed"]
    assert embed_calls, "embed did not route through the egress client"
    assert embed_calls[0]["provider"] == "ollama"
