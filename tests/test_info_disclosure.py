"""A2 reproduction: no unauthenticated info disclosure.

Two surfaces leaked recon-worthy detail (provider order, models, rate limits,
usage, and the full route map):

- the generated docs routes (/docs, /redoc, /openapi.json), which are public
  by default in FastAPI, and
- the read-only JSON listing/status routes.

These tests pin the hardened behavior:

- docs are disabled by default (no GLC_ENABLE_DOCS) -> /openapi.json, /docs,
  and /redoc return 404,
- docs can be explicitly re-enabled for local dev / tests, and
- every JSON info route requires a bearer token (already enforced by the A1
  data-plane dependency) -> 401 without one.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

DOCS_ROUTES = ["/openapi.json", "/docs", "/redoc"]

INFO_ROUTES = [
    "/v1/status",
    "/v1/providers",
    "/v1/capabilities",
    "/v1/cost/by_agent",
    "/v1/calls",
    "/v1/embedders",
    "/v1/routers",
]


def _client(monkeypatch, *, enable_docs: bool) -> TestClient:
    """Build a TestClient over a fresh app with docs on/off.

    No data-plane dependency override is applied, so the bearer check runs for
    real (info routes return 401 without a token).
    """
    import glc.main as m

    if enable_docs:
        monkeypatch.setenv("GLC_ENABLE_DOCS", "1")
    else:
        monkeypatch.delenv("GLC_ENABLE_DOCS", raising=False)
    return TestClient(m.create_app())


@pytest.mark.parametrize("path", DOCS_ROUTES)
def test_docs_disabled_by_default(monkeypatch, path):
    """With no GLC_ENABLE_DOCS, the generated docs surface is 404."""
    with _client(monkeypatch, enable_docs=False) as c:
        assert c.get(path).status_code == 404


@pytest.mark.parametrize("path", DOCS_ROUTES)
def test_docs_enabled_when_flag_set(monkeypatch, path):
    """The docs surface is reachable again when explicitly enabled."""
    with _client(monkeypatch, enable_docs=True) as c:
        assert c.get(path).status_code == 200


@pytest.mark.parametrize("path", INFO_ROUTES)
def test_info_routes_require_auth(monkeypatch, path):
    """Every read-only info route returns 401 without a bearer token."""
    with _client(monkeypatch, enable_docs=False) as c:
        assert c.get(path).status_code == 401


def test_healthz_stays_public(monkeypatch):
    """Health probe must not be gated by the info-disclosure hardening."""
    with _client(monkeypatch, enable_docs=False) as c:
        r = c.get("/healthz")
        assert r.status_code == 200
        assert r.json()["ok"] is True
