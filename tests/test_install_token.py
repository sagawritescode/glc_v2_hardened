"""B4: runtime stores only a hash of the install token; cannot recover the raw secret."""

from __future__ import annotations

import ast
import os
from pathlib import Path

import pytest

import glc.config as config
from scripts.bootstrap_install_token import create_install_token

ROOT = Path(__file__).resolve().parents[1]


def test_runtime_stores_digest_only_not_plaintext(install_token):
    hash_path = config.install_token_hash_path()
    legacy = config.legacy_install_token_path()

    assert hash_path.exists()
    assert not legacy.exists()
    stored = hash_path.read_text().strip()
    assert stored == config.hash_install_token(install_token)
    assert install_token not in stored
    assert install_token not in hash_path.read_text()


def test_verify_install_token_constant_time_match(install_token):
    assert config.verify_install_token(install_token) is True
    assert config.verify_install_token("wrong-token") is False
    assert config.verify_install_token("") is False
    assert config.verify_install_token(None) is False


def test_runtime_has_no_raw_token_getter():
    assert not hasattr(config, "get_or_create_install_token")
    assert not hasattr(config, "get_install_token")
    assert not hasattr(config, "read_install_token")


def test_runtime_cannot_recover_raw_token_from_disk(install_token):
    """Section 2-style probe: in-process code reading config storage gets no secret."""
    hash_path = config.install_token_hash_path()
    digest = hash_path.read_text()
    assert install_token not in digest

    # verify works, but nothing in glc.config returns the raw value
    assert config.verify_install_token(install_token)
    allowed = {
        "verify_install_token",
        "hash_install_token",
        "store_install_token_hash",
        "ensure_install_token_configured",
        "require_install_token_from_env",
        "install_token_hash_path",
        "install_token_path",
        "legacy_install_token_path",
        "_migrate_legacy_plaintext_token",
    }
    for name in dir(config):
        if "token" in name.lower() and callable(getattr(config, name)):
            if name in allowed:
                continue
            pytest.fail(f"unexpected token-related callable in glc.config: {name}")


def test_require_install_token_from_env_only(monkeypatch, install_token):
    assert config.require_install_token_from_env() == install_token
    monkeypatch.delenv("GLC_INSTALL_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="GLC_INSTALL_TOKEN"):
        config.require_install_token_from_env()


def test_legacy_plaintext_migrates_to_hash(tmp_path, monkeypatch):
    cfg = tmp_path / "legacy_cfg"
    cfg.mkdir()
    monkeypatch.setenv("GLC_CONFIG_DIR", str(cfg))
    config.CONFIG_DIR = cfg

    raw = "legacy-plaintext-token-value"
    legacy = cfg / "install_token"
    legacy.write_text(raw)

    assert config.verify_install_token(raw) is True
    assert not legacy.exists()
    assert config.install_token_hash_path().exists()
    assert config.install_token_hash_path().read_text().strip() == config.hash_install_token(raw)


def test_rotate_replaces_digest(install_token):
    new_token = create_install_token(rotate=True)
    assert new_token != install_token
    assert config.verify_install_token(new_token) is True
    assert config.verify_install_token(install_token) is False
    # Keep the session fixture's env in sync for later tests in this process.
    os.environ["GLC_INSTALL_TOKEN"] = new_token


def test_ensure_fails_closed_without_hash(tmp_path, monkeypatch):
    cfg = tmp_path / "empty"
    cfg.mkdir()
    monkeypatch.setenv("GLC_CONFIG_DIR", str(cfg))
    config.CONFIG_DIR = cfg
    with pytest.raises(RuntimeError, match="install token not configured"):
        config.ensure_install_token_configured()


def test_installer_writer_is_excluded_from_gateway_image():
    modal_source = (ROOT / "modal_app.py").read_text()
    project_source = (ROOT / "pyproject.toml").read_text()

    assert '.add_local_dir(str(Path(__file__).parent / "glc")' in modal_source
    assert 'packages = ["glc"]' in project_source
    assert "bootstrap_install_token" not in modal_source


def test_gateway_runtime_does_not_expose_raw_token_apis():
    runtime_files = [
        ROOT / "glc/main.py",
        ROOT / "glc/config.py",
        *sorted((ROOT / "glc/routes").glob("*.py")),
        *sorted((ROOT / "glc/security").glob("*.py")),
    ]
    banned = {"get_or_create_install_token", "get_install_token", "read_install_token"}
    violations: list[str] = []
    for path in runtime_files:
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in banned:
                violations.append(f"{path.relative_to(ROOT)} defines {node.name}")
            elif isinstance(node, ast.Attribute) and node.attr in banned:
                violations.append(f"{path.relative_to(ROOT)} references {node.attr}")
            elif isinstance(node, ast.Name) and node.id in banned:
                violations.append(f"{path.relative_to(ROOT)} references {node.id}")
    assert violations == []


def test_control_plane_still_accepts_bearer(app_client, install_token):
    headers = {"Authorization": f"Bearer {install_token}"}
    r = app_client.get("/v1/control/presence", headers=headers)
    assert r.status_code == 200
    bad = app_client.get("/v1/control/presence", headers={"Authorization": "Bearer nope"})
    assert bad.status_code == 403
