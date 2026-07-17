"""Loads channels.yaml and policy.yaml. Resolves user-config directory.

The default config lives in `~/.glc/`. Override with GLC_CONFIG_DIR for
tests and CI. The directory is created on import if missing.

Install-token custody (B4): the runtime stores only a SHA-256 digest of the
per-installation control token. Request-handling code can verify a presented
bearer value but cannot recover the original secret. Create/rotate lives in
``scripts/bootstrap_install_token.py`` (installer-only; not in the Modal image).
"""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path

import yaml

DEFAULT_DIR = Path(os.path.expanduser("~/.glc"))
CONFIG_DIR = Path(os.getenv("GLC_CONFIG_DIR", str(DEFAULT_DIR)))
CONFIG_DIR.mkdir(parents=True, exist_ok=True)

# Packaged defaults shipped with glc (under the policy/ subpackage).
PACKAGED_POLICY = Path(__file__).parent / "policy" / "policy.yaml"
PACKAGED_CHANNELS = Path(__file__).parent / "channels.yaml"

ENV_INSTALL_TOKEN = "GLC_INSTALL_TOKEN"


def policy_yaml_path() -> Path:
    user = CONFIG_DIR / "policy.yaml"
    return user if user.exists() else PACKAGED_POLICY


def channels_yaml_path() -> Path:
    user = CONFIG_DIR / "channels.yaml"
    return user if user.exists() else PACKAGED_CHANNELS


def load_channels() -> dict:
    p = channels_yaml_path()
    if not p.exists():
        return {"channels": {}}
    return yaml.safe_load(p.read_text()) or {"channels": {}}


def install_token_hash_path() -> Path:
    """Path to the digest-only install-token file (runtime-readable)."""
    return CONFIG_DIR / "install_token.hash"


def legacy_install_token_path() -> Path:
    """Pre-B4 plaintext path. Migrated away on first configure/verify."""
    return CONFIG_DIR / "install_token"


# Back-compat alias used by older docs/tests; prefer install_token_hash_path.
def install_token_path() -> Path:
    return install_token_hash_path()


def hash_install_token(token: str) -> str:
    """Return the hex SHA-256 digest of ``token`` (UTF-8)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def store_install_token_hash(raw_token: str) -> None:
    """Persist only the digest of ``raw_token``. Never writes the plaintext."""
    digest = hash_install_token(raw_token.strip())
    path = install_token_hash_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(digest + "\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    legacy = legacy_install_token_path()
    if legacy.exists():
        try:
            legacy.unlink()
        except OSError:
            pass


def _migrate_legacy_plaintext_token() -> None:
    """If a pre-B4 plaintext token file remains, replace it with its digest."""
    legacy = legacy_install_token_path()
    hashed = install_token_hash_path()
    if hashed.exists() or not legacy.exists():
        return
    raw = legacy.read_text().strip()
    if not raw:
        return
    store_install_token_hash(raw)


def verify_install_token(presented: str | None) -> bool:
    """Constant-time check that ``presented`` matches the stored digest.

    Fails closed when no digest is configured or ``presented`` is empty/None.
    """
    _migrate_legacy_plaintext_token()
    path = install_token_hash_path()
    if not path.exists():
        return False
    expected = path.read_text().strip()
    if not expected or not presented:
        return False
    actual = hash_install_token(presented.strip())
    return hmac.compare_digest(actual, expected)


def ensure_install_token_configured() -> None:
    """Lifespan guard: migrate legacy plaintext, then require a digest file.

    Does not create or return a raw token — that is an installer operation.
    """
    _migrate_legacy_plaintext_token()
    if not install_token_hash_path().exists():
        raise RuntimeError(
            "install token not configured. Create one with: "
            "uv run python scripts/bootstrap_install_token.py "
            "(then set GLC_INSTALL_TOKEN for adapters)."
        )


def require_install_token_from_env() -> str:
    """Return the raw install token from ``GLC_INSTALL_TOKEN`` for adapters.

    Adapters and out-of-process bridges must receive the secret via the
    environment (operator-supplied after bootstrap). Runtime code must not
    recover it from the digest file.
    """
    tok = os.getenv(ENV_INSTALL_TOKEN)
    if tok is None or not tok.strip():
        raise RuntimeError(
            f"{ENV_INSTALL_TOKEN} is not set. Create a token with "
            "scripts/bootstrap_install_token.py and export it for adapters."
        )
    return tok.strip()
