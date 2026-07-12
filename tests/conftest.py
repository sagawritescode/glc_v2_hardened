"""Shared fixtures.

Each test session gets a fresh isolated config/db dir so user state at
~/.glc/ is never touched. Per-test, the audit / pairing / gateway DBs
are rolled fresh.
"""

from __future__ import annotations

import pytest

# Known data-plane token for the test session. The gateway now requires a
# bearer token on the data plane (see glc/security/auth.py); tests set it to
# a fixed value so the authenticated default client can present it.
TEST_DATA_PLANE_TOKEN = "test-data-plane-token"


@pytest.fixture(autouse=True)
def _isolated_glc_state(monkeypatch, tmp_path):
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    monkeypatch.setenv("GLC_CONFIG_DIR", str(cfg))
    monkeypatch.setenv("GLC_AUDIT_DB", str(tmp_path / "audit.sqlite"))
    monkeypatch.setenv("GLC_PAIRING_DB", str(tmp_path / "pairings.sqlite"))
    monkeypatch.setenv("GLC_GATEWAY_DB", str(tmp_path / "gateway.sqlite"))
    monkeypatch.setenv("GLC_DATA_PLANE_TOKEN", TEST_DATA_PLANE_TOKEN)

    # Reset singletons that cache config-dir at first access.
    import glc.config as _cfg

    _cfg.CONFIG_DIR = cfg
    import glc.security.pairing as _p

    _p._singleton = None
    import glc.security.rate_limits as _r

    _r._limiter = None
    import glc.policy.engine as _e

    _e._engine = None
    import glc.audit.store as _a

    _a._singleton = None
    yield


@pytest.fixture
def app_client():
    """TestClient pointed at a freshly-booted glc.main:app.

    The data-plane bearer check (glc/security/auth.py) is bypassed here via a
    dependency override so existing route-shape/behavior tests don't need to
    carry a token, and control-plane tests keep their own auth semantics
    untouched. The real bearer enforcement is covered end-to-end in
    tests/test_data_plane_auth.py, which uses its own un-overridden client.
    """
    from fastapi.testclient import TestClient

    import glc.main as m
    from glc.security.auth import require_data_plane_auth

    m.app.dependency_overrides[require_data_plane_auth] = lambda: None
    try:
        with TestClient(m.app) as c:
            yield c
    finally:
        m.app.dependency_overrides.pop(require_data_plane_auth, None)


@pytest.fixture
def install_token(app_client):
    """Returns the per-installation token created during boot."""
    from glc.config import install_token_path

    return install_token_path().read_text().strip()
