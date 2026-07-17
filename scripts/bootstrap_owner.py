"""Trusted installer-only first-owner bootstrap.

This script is deliberately outside the ``glc`` package. The Modal gateway
image copies and installs ``glc`` only, so this direct database writer is not
present in the live gateway runtime.

Usage:

    uv run python scripts/bootstrap_owner.py telegram 123456789
    uv run python scripts/bootstrap_owner.py gmail owner@example.com --handle alice
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import sys
import time
from pathlib import Path

from glc.security.pairing import PairingRecord, get_pairing_store

DEFAULT_DIR = Path(os.path.expanduser("~/.glc"))


def _db_path() -> str:
    return os.getenv("GLC_PAIRING_DB", str(DEFAULT_DIR / "pairings.sqlite"))


def bootstrap_owner(
    channel: str,
    channel_user_id: str,
    user_handle: str = "owner",
) -> PairingRecord:
    """Create the first owner for a channel, refusing later owner writes."""
    store = get_pairing_store()
    existing = store.owners(channel=channel)
    if existing:
        raise RuntimeError(
            f"channel {channel!r} already has an owner "
            f"({existing[0].channel_user_id!r}); refuse to force-create another"
        )

    paired_at = time.time()
    path = _db_path()
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path, isolation_level=None) as connection:
        connection.execute(
            """INSERT OR REPLACE INTO pairings
               (channel, channel_user_id, user_handle, trust_level, paired_at)
               VALUES (?,?,?,?,?)""",
            (channel, channel_user_id, user_handle, "owner_paired", paired_at),
        )
    return PairingRecord(
        channel=channel,
        channel_user_id=channel_user_id,
        user_handle=user_handle,
        trust_level="owner_paired",
        paired_at=paired_at,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bootstrap a channel's first owner.")
    parser.add_argument("channel", help="channel name, e.g. telegram")
    parser.add_argument("user_id", help="channel-native user id")
    parser.add_argument("--handle", default="owner", help="display handle")
    args = parser.parse_args(argv)
    try:
        record = bootstrap_owner(args.channel, args.user_id, args.handle)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(
        f"Bootstrapped owner_paired on channel {record.channel!r}: "
        f"user_id={record.channel_user_id!r} handle={record.user_handle!r}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
