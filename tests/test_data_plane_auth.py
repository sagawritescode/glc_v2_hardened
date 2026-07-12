"""A1 reproduction: the public data plane must not run without auth.

Before the fix, POST /v1/chat (and the other data-plane routes) ran for
anyone with the URL and returned a provider error, not 401. These tests
pin the hardened behavior:

- no token            -> 401 (not a provider error)
- wrong token         -> 401
- /healthz            -> 200 without any auth (probes stay public)
- token not configured -> 503 (fail closed, never open)
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests.conftest import TEST_DATA_PLANE_TOKEN


@pytest.fixture
def unauth_client():
    """TestClient with no default Authorization header."""
    import glc.main as m

    with TestClient(m.app) as c:
        yield c


def test_chat_without_token_is_401(unauth_client):
    r = unauth_client.post("/v1/chat", json={"prompt": "hi"})
    assert r.status_code == 401


def test_chat_with_wrong_token_is_401(unauth_client):
    r = unauth_client.post(
        "/v1/chat",
        json={"prompt": "hi"},
        headers={"Authorization": "Bearer not-the-real-token"},
    )
    assert r.status_code == 401


def test_chat_with_valid_token_passes_auth(unauth_client):
    r = unauth_client.post(
        "/v1/chat",
        json={"prompt": "hi", "provider": "no_such_provider"},
        headers={"Authorization": f"Bearer {TEST_DATA_PLANE_TOKEN}"},
    )
    # Auth passed, so we reach normal request handling (bad provider -> 400,
    # or 503 if no providers are wired) rather than 401.
    assert r.status_code != 401
    assert r.status_code in (400, 503)


@pytest.mark.parametrize("path", ["/v1/embed", "/v1/vision", "/v1/speak", "/v1/transcribe"])
def test_other_data_plane_routes_require_auth(unauth_client, path):
    r = unauth_client.post(path, json={})
    assert r.status_code == 401


def test_healthz_is_public(unauth_client):
    r = unauth_client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_missing_token_config_fails_closed(monkeypatch, unauth_client):
    """With no configured token, protected routes fail closed with 503."""
    monkeypatch.delenv("GLC_DATA_PLANE_TOKEN", raising=False)
    r = unauth_client.post(
        "/v1/chat",
        json={"prompt": "hi"},
        headers={"Authorization": f"Bearer {TEST_DATA_PLANE_TOKEN}"},
    )
    assert r.status_code == 503
