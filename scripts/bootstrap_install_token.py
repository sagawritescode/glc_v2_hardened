"""Trusted installer-only install-token create / rotate.

This script is deliberately outside the ``glc`` package. The Modal gateway
image copies and installs ``glc`` only, so this helper is not present in the
live gateway runtime. It prints the raw token once; the runtime stores only
a SHA-256 digest and cannot recover the secret later.

Usage:

    uv run python scripts/bootstrap_install_token.py
    uv run python scripts/bootstrap_install_token.py --rotate

Export the printed value for adapters:

    export GLC_INSTALL_TOKEN='...'
"""

from __future__ import annotations

import argparse
import secrets
import sys

from glc.config import (
    install_token_hash_path,
    legacy_install_token_path,
    store_install_token_hash,
)


def create_install_token(*, rotate: bool = False) -> str:
    """Generate a new install token, persist only its digest, return the raw value."""
    path = install_token_hash_path()
    if path.exists() and not rotate:
        raise RuntimeError(
            f"install token already configured at {path}; "
            "pass --rotate to replace it (invalidates the previous token)"
        )
    tok = secrets.token_urlsafe(32)
    store_install_token_hash(tok)
    legacy = legacy_install_token_path()
    if legacy.exists():
        try:
            legacy.unlink()
        except OSError:
            pass
    return tok


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Create or rotate the per-installation control token. "
            "Prints the raw token once; only a hash is stored on disk."
        )
    )
    parser.add_argument(
        "--rotate",
        action="store_true",
        help="replace an existing token (invalidates adapters still using the old one)",
    )
    args = parser.parse_args(argv)
    try:
        token = create_install_token(rotate=args.rotate)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(token)
    print(
        "\nSave this token now — it cannot be recovered from the gateway. "
        "Export it for adapters as GLC_INSTALL_TOKEN.",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
