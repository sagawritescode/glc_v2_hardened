"""A6 (audit on Modal Volume) — deploy wiring regression tests.

Locks the single-writer + Volume-backed audit path without needing a live
Modal deploy. A4 secret split must remain unchanged.
"""

from __future__ import annotations

import inspect


def test_modal_audit_db_on_volume():
    import modal_app as deploy

    assert deploy.AUDIT_DB_PATH == "/data/glc/audit.sqlite"
    assert deploy.AUDIT_DB_PATH.startswith("/data/")


def test_modal_max_containers_is_one():
    """SQLite on a shared Volume needs exactly one writer under autoscale."""
    import modal_app as deploy

    assert deploy.MAX_CONTAINERS == 1


def test_modal_function_secrets_unchanged():
    """A4 regression: Function mounts auth only; Sandbox mounts provider keys."""
    import modal_app as deploy

    assert deploy.FUNCTION_SECRETS == [deploy.auth_secret]
    assert deploy.llm_secret not in deploy.FUNCTION_SECRETS
    assert deploy.SANDBOX_SECRETS == [deploy.llm_secret]


def test_fastapi_app_registers_volume_sync():
    """Startup must wire Volume commit/reload before the FastAPI app loads."""
    import modal_app as deploy

    src = inspect.getsource(deploy.fastapi_app.get_raw_f())
    assert "register_volume_sync" in src
    assert "data_volume.commit" in src
    assert "data_volume.reload" in src
