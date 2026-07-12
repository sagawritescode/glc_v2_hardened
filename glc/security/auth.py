"""Data-plane authentication.

The public HTTP data plane (chat, batch, vision, embed, speak, transcribe,
and the read-only listing/status routes) must not run for anyone who merely
knows the URL. Every request to those routes carries a bearer token that is
checked here before any provider budget is spent.

The token is read from the GLC_DATA_PLANE_TOKEN environment variable, which
on Modal is injected from a Secret. It is deliberately separate from the
per-installation control-plane token (see glc/routes/control.py) so the
public API credential can be rotated independently of the admin credential.

The check fails closed: if no token is configured, protected routes return
503 rather than silently serving unauthenticated traffic.
"""

from __future__ import annotations

import hmac
import os

from fastapi import Header, HTTPException

ENV_VAR = "GLC_DATA_PLANE_TOKEN"


def get_data_plane_token() -> str | None:
    """Return the configured data-plane token, or None if unset/empty."""
    tok = os.getenv(ENV_VAR)
    if tok is None:
        return None
    tok = tok.strip()
    return tok or None


def require_data_plane_auth(authorization: str | None = Header(default=None)) -> None:
    """FastAPI dependency enforcing bearer-token auth on the data plane.

    - No token configured  -> 503 (fail closed; deployment misconfiguration).
    - Missing/non-Bearer    -> 401 with WWW-Authenticate: Bearer.
    - Token mismatch        -> 401 (constant-time comparison).
    """
    expected = get_data_plane_token()
    if expected is None:
        raise HTTPException(
            503,
            f"data-plane auth not configured (set {ENV_VAR})",
        )
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            401,
            "missing bearer token (Authorization: Bearer <token>)",
            headers={"WWW-Authenticate": "Bearer"},
        )
    presented = authorization.removeprefix("Bearer ").strip()
    if not hmac.compare_digest(presented, expected):
        raise HTTPException(
            401,
            "invalid data-plane token",
            headers={"WWW-Authenticate": "Bearer"},
        )
