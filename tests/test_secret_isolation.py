"""A4 (secret isolation) — regression tests.

Provider API keys must not live in the public Function's ``os.environ``.
Step 1 pins the named set of env vars that count as provider secrets.
Steps 2–4 add keyless worker / router / embedder catalogs for the Function
when egress is on (real keys stay in the Sandbox).
Step 5 wires those catalogs into lifespan when an egress client is present.
Step 6 proves Section 2-style theft fails on the Function path while the
gateway still boots and routes chat/embed through the wall.
Step 8 locks the Modal wiring: Function mounts auth only; Sandbox mounts
provider keys.
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from glc.egress.catalog import (
    build_egress_embedder_catalog,
    build_egress_provider_catalog,
    build_egress_router_catalog,
)
from glc.egress.provider_secrets import PROVIDER_SECRET_ENV_VARS
from glc.embedders import EmbedRateState

REQUIRED_PROVIDER_SECRET_NAMES = {
    "GEMINI_API_KEY",
    "NVIDIA_API_KEY",
    "GROQ_API_KEY",
    "CEREBRAS_API_KEY",
    "OPEN_ROUTER_API_KEY",
    "GITHUB_ACCESS_TOKEN",
    "CARTESIA_API_KEY",
    "ELEVENLABS_API_KEY",
}

EXPECTED_CLOUD_WORKERS = {
    "gemini",
    "nvidia",
    "groq",
    "cerebras",
    "openrouter",
    "github",
}

EXPECTED_ROUTERS = {
    "cerebras",
    "groq",
    "nvidia",
    "github",
}

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


def test_provider_secret_env_vars_is_the_expected_set():
    assert PROVIDER_SECRET_ENV_VARS == REQUIRED_PROVIDER_SECRET_NAMES


def test_provider_secret_env_vars_has_no_blank_names():
    assert all(isinstance(name, str) and name.strip() for name in PROVIDER_SECRET_ENV_VARS)


@pytest.fixture
def no_provider_secrets(monkeypatch):
    for name in PROVIDER_SECRET_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("OLLAMA_MODEL", raising=False)


def test_egress_provider_catalog_builds_without_keys(no_provider_secrets):
    catalog = build_egress_provider_catalog()
    assert set(catalog) == EXPECTED_CLOUD_WORKERS
    for name, stub in catalog.items():
        assert stub.name == name
        assert stub.model
        assert stub.base_url
        assert isinstance(stub.capabilities, dict)
        assert not hasattr(stub, "api_key")


def test_egress_provider_catalog_includes_ollama_when_configured(monkeypatch, no_provider_secrets):
    monkeypatch.setenv("OLLAMA_MODEL", "llama3.2")
    monkeypatch.setenv("OLLAMA_URL", "http://127.0.0.1:11434")
    catalog = build_egress_provider_catalog()
    assert "ollama" in catalog
    assert catalog["ollama"].model == "llama3.2"
    assert catalog["ollama"].base_url == "http://127.0.0.1:11434"
    assert not hasattr(catalog["ollama"], "api_key")


def test_egress_provider_catalog_respects_model_env(monkeypatch, no_provider_secrets):
    monkeypatch.setenv("GEMINI_MODEL", "gemini-2.0-flash")
    catalog = build_egress_provider_catalog()
    assert catalog["gemini"].model == "gemini-2.0-flash"


def test_egress_router_catalog_builds_without_keys(no_provider_secrets):
    catalog = build_egress_router_catalog()
    assert set(catalog) == EXPECTED_ROUTERS
    for name, stub in catalog.items():
        assert stub.name == name
        assert stub.model
        assert stub.base_url
        assert isinstance(stub.capabilities, dict)
        assert not hasattr(stub, "api_key")


def test_egress_router_catalog_respects_router_model_env(monkeypatch, no_provider_secrets):
    monkeypatch.setenv("ROUTER_GROQ_MODEL", "llama-3.1-8b-instant")
    catalog = build_egress_router_catalog()
    assert catalog["groq"].model == "llama-3.1-8b-instant"


def test_egress_embedder_catalog_builds_without_keys(no_provider_secrets):
    embedders, names = build_egress_embedder_catalog()
    assert names == ["ollama", "gemini"]
    assert [e.name for e in embedders] == names
    by_name = {e.name: e for e in embedders}
    assert by_name["ollama"].model == "nomic-embed-text"
    assert by_name["gemini"].model == "gemini-embedding-001"
    for stub in embedders:
        assert isinstance(stub.state, EmbedRateState)
        assert not hasattr(stub, "api_key")


def test_egress_embedder_catalog_respects_order_and_model_env(monkeypatch, no_provider_secrets):
    monkeypatch.setenv("EMBED_ORDER", "gemini,ollama")
    monkeypatch.setenv("EMBED_FALLBACK_MODEL", "text-embedding-004")
    embedders, names = build_egress_embedder_catalog()
    assert names == ["gemini", "ollama"]
    assert embedders[0].model == "text-embedding-004"
    assert not hasattr(embedders[0], "api_key")


# ── Step 6: Section 2 theft fails; Function still boots with egress on ─────


class _FakeEgressClient:
    def __init__(self, *, chat_result=None, embed_result=None):
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


def _section2_stolen_keys() -> dict[str, str]:
    """Simulate a hostile in-process adapter reading provider keys from env."""
    return {k: os.environ[k] for k in PROVIDER_SECRET_ENV_VARS if k in os.environ}


def _egress_app_no_keys(monkeypatch, fake_client):
    for name in PROVIDER_SECRET_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("OLLAMA_MODEL", raising=False)

    import glc.main as m
    from glc.security.auth import require_data_plane_auth

    app = m.create_app()
    app.state.egress_client = fake_client
    app.dependency_overrides[require_data_plane_auth] = lambda: None
    return app


def test_section2_theft_fails_when_egress_on_without_keys(monkeypatch):
    fake = _FakeEgressClient(chat_result=CHAT_RESULT)
    app = _egress_app_no_keys(monkeypatch, fake)

    with TestClient(app) as client:
        # Section 2 probe: nothing to steal from the Function process env.
        assert _section2_stolen_keys() == {}

        r = client.get("/v1/providers")
        assert r.status_code == 200, r.text
        providers = r.json()["providers"]
        assert providers, "egress catalog should register providers without keys"
        assert "gemini" in providers


def test_chat_and_embed_still_route_through_egress_without_keys(monkeypatch):
    fake = _FakeEgressClient(
        chat_result=CHAT_RESULT,
        embed_result={"embedding": [0.1, 0.2], "model": "nomic-embed-text", "dim": 2},
    )
    app = _egress_app_no_keys(monkeypatch, fake)

    with TestClient(app) as client:
        assert _section2_stolen_keys() == {}

        chat = client.post("/v1/chat", json={"prompt": "hi", "provider": "gemini"})
        assert chat.status_code == 200, chat.text
        assert chat.json()["text"] == "hello from the sandbox"

        embed = client.post("/v1/embed", json={"text": "hello"})
        assert embed.status_code == 200, embed.text
        assert embed.json()["embedding"] == [0.1, 0.2]

    chat_calls = [p for p in fake.calls if p.get("command") == "chat"]
    embed_calls = [p for p in fake.calls if p.get("command") == "embed"]
    assert chat_calls and chat_calls[0]["provider"] == "gemini"
    assert embed_calls and embed_calls[0]["provider"] in {"ollama", "gemini"}


# ── Step 8: Modal Function vs Sandbox secret wiring ─────────────────────────


def test_function_secrets_exclude_llm_keys():
    import modal_app as deploy

    assert deploy.llm_secret not in deploy.FUNCTION_SECRETS
    assert deploy.auth_secret in deploy.FUNCTION_SECRETS
    assert deploy.FUNCTION_SECRETS == [deploy.auth_secret]


def test_sandbox_secrets_include_llm_keys_only():
    import modal_app as deploy

    assert deploy.llm_secret in deploy.SANDBOX_SECRETS
    assert deploy.auth_secret not in deploy.SANDBOX_SECRETS
    assert deploy.SANDBOX_SECRETS == [deploy.llm_secret]


def test_build_sandbox_egress_client_uses_sandbox_secrets():
    import modal_app as deploy

    client = deploy.build_sandbox_egress_client()
    kwargs = client.sandbox_create_kwargs()
    assert kwargs["secrets"] is deploy.SANDBOX_SECRETS
    assert deploy.llm_secret in kwargs["secrets"]
    assert deploy.auth_secret not in kwargs["secrets"]
