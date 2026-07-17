"""A5 (reproducible image) — regression tests.

The Modal gateway image must not drift across deploys: base pinned by digest,
third-party deps installed from the committed uv.lock (not floating >= ranges).
These are static checks on modal_app.py — no live Modal image build required.
"""

from __future__ import annotations

from pathlib import Path

MODAL_APP = Path(__file__).resolve().parent.parent / "modal_app.py"


def _modal_app_source() -> str:
    return MODAL_APP.read_text(encoding="utf-8")


def test_base_image_pinned_by_digest() -> None:
  src = _modal_app_source()
  assert "@sha256:" in src, "base image must be pinned by digest"
  assert "from_registry" in src, "base must come from from_registry, not debian_slim"


def test_deps_installed_from_lockfile() -> None:
  src = _modal_app_source()
  assert "uv_sync" in src, "deps must install via uv_sync from uv.lock"
  assert "frozen=True" in src, "uv_sync must be frozen so the lock is not re-resolved"


def test_no_floating_pip_install_ranges() -> None:
  src = _modal_app_source()
  assert "pip_install" not in src, "modal_app must not use pip_install (use uv_sync)"
  assert "debian_slim" not in src, "gateway image must not use rolling debian_slim"
