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
    # The generated docs surface is disabled by default in prod (A2). Tests,
    # however, read /openapi.json (see test_v9_compat.py) to assert the route
    # shape, so the test session opts docs back in explicitly.
    monkeypatch.setenv("GLC_ENABLE_DOCS", "1")

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
    # A6: volume sync hooks are process-global; clear so a prior test's
    # register_volume_sync cannot leak into the next.
    _a._volume_commit = None
    _a._volume_reload = None
    # B2: production's remote writer callbacks are also process-global.
    # Tests default to the local SQLite backend unless they opt in explicitly.
    _a._remote_initialize = None
    _a._remote_append = None

    # B4: bootstrap a digest-only install token for this isolated config dir.
    # The raw value is kept only in the env for fixtures/adapters — never on disk.
    from scripts.bootstrap_install_token import create_install_token

    raw_install_token = create_install_token()
    monkeypatch.setenv("GLC_INSTALL_TOKEN", raw_install_token)
    yield


@pytest.fixture
def app_client():
    """TestClient pointed at a freshly-built glc.main app.

    The app is constructed via create_app() so it picks up the per-test
    environment (config dir, docs flag) rather than the module-level app that
    was built once at import time.

    The data-plane bearer check (glc/security/auth.py) is bypassed here via a
    dependency override so existing route-shape/behavior tests don't need to
    carry a token, and control-plane tests keep their own auth semantics
    untouched. The real bearer enforcement is covered end-to-end in
    tests/test_data_plane_auth.py, which uses its own un-overridden client.
    """
    from fastapi.testclient import TestClient

    import glc.main as m
    from glc.security.auth import require_data_plane_auth

    app = m.create_app()
    app.dependency_overrides[require_data_plane_auth] = lambda: None
    with TestClient(app) as c:
        yield c


@pytest.fixture
def install_token():
    """Returns the per-installation token from the test env (not from disk)."""
    import os

    return os.environ["GLC_INSTALL_TOKEN"]
