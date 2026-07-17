"""Test-only helpers for creating pairings through the runtime code flow."""

from glc.security.pairing import PairingRecord, PairingStore
from scripts.bootstrap_owner import bootstrap_owner


def confirm_owner(
    _store: PairingStore,
    channel: str,
    channel_user_id: str,
    user_handle: str = "owner",
) -> PairingRecord:
    """Seed an isolated test database through the installer-only helper."""
    return bootstrap_owner(channel, channel_user_id, user_handle)
