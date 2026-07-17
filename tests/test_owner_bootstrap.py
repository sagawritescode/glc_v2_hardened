"""B3: first-owner bootstrap is installer-only, not a runtime API."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

import glc.security as security
from glc.security.pairing import PairingStore, get_pairing_store
from scripts.bootstrap_owner import bootstrap_owner

ROOT = Path(__file__).resolve().parents[1]


def test_installer_bootstraps_first_owner_only():
    record = bootstrap_owner("telegram", "owner-1", user_handle="alice")

    assert record.trust_level == "owner_paired"
    assert get_pairing_store().lookup("telegram", "owner-1") == record

    with pytest.raises(RuntimeError, match="already has an owner"):
        bootstrap_owner("telegram", "owner-2", user_handle="mallory")

    assert get_pairing_store().lookup("telegram", "owner-2") is None


def test_runtime_pairing_api_has_no_force_owner_primitive():
    store = PairingStore()

    assert not hasattr(store, "force_pair_owner")
    assert not hasattr(security, "force_pair_owner")
    assert not hasattr(security, "bootstrap_owner")
    with pytest.raises(PermissionError, match="installation token"):
        store.issue_code(
            "telegram",
            "attacker",
            requested_trust_level="owner_paired",
        )


def test_installer_writer_is_excluded_from_gateway_image():
    modal_source = (ROOT / "modal_app.py").read_text()
    project_source = (ROOT / "pyproject.toml").read_text()

    assert '.add_local_dir(str(Path(__file__).parent / "glc")' in modal_source
    assert 'packages = ["glc"]' in project_source
    assert "bootstrap_owner" not in modal_source


def test_gateway_runtime_does_not_import_installer_bootstrap():
    runtime_files = [
        ROOT / "glc/main.py",
        ROOT / "glc/channels/registry.py",
        *sorted((ROOT / "glc/routes").glob("*.py")),
        *sorted((ROOT / "glc/security").glob("*.py")),
        *sorted((ROOT / "glc/channels/catalogue").glob("*/adapter.py")),
    ]

    violations: list[str] = []
    for path in runtime_files:
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("glc.install"):
                violations.append(f"{path.relative_to(ROOT)} imports {node.module}")
            elif isinstance(node, ast.ImportFrom) and (node.module or "").startswith("scripts.bootstrap_owner"):
                violations.append(f"{path.relative_to(ROOT)} imports {node.module}")
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith(("glc.install", "scripts.bootstrap_owner")):
                        violations.append(f"{path.relative_to(ROOT)} imports {alias.name}")
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in {
                "bootstrap_owner",
                "force_pair_owner",
            }:
                violations.append(f"{path.relative_to(ROOT)} defines {node.name}")
            elif isinstance(node, ast.Attribute) and node.attr == "force_pair_owner":
                violations.append(f"{path.relative_to(ROOT)} calls force_pair_owner")

    assert violations == []
