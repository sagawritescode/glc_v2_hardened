"""Append-only SQLite audit log.

Every channel message, agent decision, policy verdict, and tool dispatch
lands here. Append-only is enforced at the application layer: only
`append()` is exposed; there is no update or delete function. The schema
ships with `audit_schema` version 1; bumping it requires a documented
migration step (see schema.sql).

Each append commits immediately so writes survive a hard kill.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_DIR = Path(os.path.expanduser("~/.glc"))

# Audit events cross a process boundary in production. Keep the accepted
# surface deliberately small and reject oversized data instead of silently
# truncating security evidence.
MAX_CHANNEL_BYTES = 128
MAX_CHANNEL_USER_ID_BYTES = 512
MAX_EVENT_FIELD_BYTES = 128
MAX_OPTIONAL_FIELD_BYTES = 512
MAX_PAYLOAD_BYTES = 64 * 1024

# Optional Modal Volume sync (A6). Registered by modal_app at startup; no-op
# locally and in tests. reload() must run with no SQLite file open; commit()
# runs after the connection is closed.
_volume_commit: Callable[[], None] | None = None
_volume_reload: Callable[[], None] | None = None

# B2: production registers only these two narrow operations. Exceptions from
# either callable intentionally propagate so startup and audited request
# processing fail closed.
RemoteInitialize = Callable[[], None]
RemoteAppend = Callable[[dict[str, Any]], int]
_remote_initialize: RemoteInitialize | None = None
_remote_append: RemoteAppend | None = None


class AuditValidationError(ValueError):
    """An audit event is malformed or exceeds a persistence limit."""


@dataclass(frozen=True, slots=True)
class AuditEvent:
    channel: str
    channel_user_id: str
    trust_level: str
    event_type: str
    session_id: str | None = None
    tool: str | None = None
    policy_verdict: str | None = None
    params_json: str | None = None
    result_json: str | None = None

    def remote_payload(self) -> dict[str, Any]:
        """Return the narrow payload accepted by the remote append method."""
        return {
            "channel": self.channel,
            "channel_user_id": self.channel_user_id,
            "trust_level": self.trust_level,
            "event_type": self.event_type,
            "session_id": self.session_id,
            "tool": self.tool,
            "policy_verdict": self.policy_verdict,
            "params": self.params_json,
            "result": self.result_json,
        }


def register_remote_backend(
    *,
    initialize: RemoteInitialize,
    append: RemoteAppend,
) -> None:
    """Route production initialization and appends to a trusted writer.

    No query or arbitrary-SQL callback is accepted. Once registered, failures
    propagate; the gateway never falls back to its local filesystem.
    """
    if not callable(initialize) or not callable(append):
        raise TypeError("remote audit backend operations must be callable")

    global _remote_initialize, _remote_append
    _remote_initialize = initialize
    _remote_append = append


def register_volume_sync(
    *,
    commit: Callable[[], None],
    reload: Callable[[], None],
) -> None:
    """Wire Modal Volume commit/reload for cross-container persistence."""
    global _volume_commit, _volume_reload
    _volume_commit = commit
    _volume_reload = reload


def _sync_reload() -> None:
    if _volume_reload is not None:
        _volume_reload()


def _sync_commit() -> None:
    if _volume_commit is not None:
        _volume_commit()


def _resolve_path() -> str:
    """Resolve at call time, not import time, so tests that swap the env
    var see the change."""
    return os.getenv("GLC_AUDIT_DB", str(DEFAULT_DIR / "audit.sqlite"))


@contextmanager
def _conn():
    p = _resolve_path()
    Path(p).parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(p, isolation_level=None)  # autocommit; each insert flushes
    c.row_factory = sqlite3.Row
    try:
        yield c
    finally:
        c.close()


_SCHEMA_PATH = Path(__file__).parent / "schema.sql"


def init_store() -> None:
    if _remote_initialize is not None:
        _remote_initialize()
        return

    _sync_reload()
    with _conn() as c:
        c.executescript(_SCHEMA_PATH.read_text())


def _jsonify(v: Any) -> str | None:
    if v is None:
        return None
    if isinstance(v, str):
        return v
    try:
        return json.dumps(v, default=str)
    except Exception:
        return json.dumps({"_repr": repr(v)})


def _validate_required_text(
    name: str,
    value: Any,
    *,
    max_bytes: int,
) -> str:
    if not isinstance(value, str):
        raise AuditValidationError(f"{name} must be a string")
    if not value.strip():
        raise AuditValidationError(f"{name} must not be empty")
    if len(value.encode("utf-8")) > max_bytes:
        raise AuditValidationError(f"{name} exceeds {max_bytes} UTF-8 bytes")
    return value


def _validate_optional_text(name: str, value: Any, *, max_bytes: int) -> str | None:
    if value is None:
        return None
    return _validate_required_text(name, value, max_bytes=max_bytes)


def validate_event(
    *,
    channel: Any,
    channel_user_id: Any,
    trust_level: Any,
    event_type: Any,
    session_id: Any = None,
    tool: Any = None,
    policy_verdict: Any = None,
    params: Any = None,
    result: Any = None,
) -> AuditEvent:
    """Validate and normalize an event before local or remote persistence."""
    params_json = _jsonify(params)
    result_json = _jsonify(result)
    if params_json is not None and len(params_json.encode("utf-8")) > MAX_PAYLOAD_BYTES:
        raise AuditValidationError(f"params exceeds {MAX_PAYLOAD_BYTES} UTF-8 bytes")
    if result_json is not None and len(result_json.encode("utf-8")) > MAX_PAYLOAD_BYTES:
        raise AuditValidationError(f"result exceeds {MAX_PAYLOAD_BYTES} UTF-8 bytes")

    return AuditEvent(
        channel=_validate_required_text("channel", channel, max_bytes=MAX_CHANNEL_BYTES),
        channel_user_id=_validate_required_text(
            "channel_user_id",
            channel_user_id,
            max_bytes=MAX_CHANNEL_USER_ID_BYTES,
        ),
        trust_level=_validate_required_text(
            "trust_level",
            trust_level,
            max_bytes=MAX_EVENT_FIELD_BYTES,
        ),
        event_type=_validate_required_text(
            "event_type",
            event_type,
            max_bytes=MAX_EVENT_FIELD_BYTES,
        ),
        session_id=_validate_optional_text(
            "session_id",
            session_id,
            max_bytes=MAX_OPTIONAL_FIELD_BYTES,
        ),
        tool=_validate_optional_text("tool", tool, max_bytes=MAX_OPTIONAL_FIELD_BYTES),
        policy_verdict=_validate_optional_text(
            "policy_verdict",
            policy_verdict,
            max_bytes=MAX_OPTIONAL_FIELD_BYTES,
        ),
        params_json=params_json,
        result_json=result_json,
    )


class AuditStore:
    """Application-layer write-once store. The class deliberately exposes
    no update or delete methods. Reads (for the replay viewer) live in
    query() which is read-only."""

    def append(
        self,
        *,
        channel: str,
        channel_user_id: str,
        trust_level: str,
        event_type: str,
        session_id: str | None = None,
        tool: str | None = None,
        policy_verdict: str | None = None,
        params: Any = None,
        result: Any = None,
    ) -> int:
        event = validate_event(
            channel=channel,
            channel_user_id=channel_user_id,
            trust_level=trust_level,
            event_type=event_type,
            session_id=session_id,
            tool=tool,
            policy_verdict=policy_verdict,
            params=params,
            result=result,
        )
        return _append_event(event)

    def _append_local(self, event: AuditEvent) -> int:
        _sync_reload()
        with _conn() as c:
            cur = c.execute(
                """INSERT INTO audit_log
                   (ts, session_id, channel, channel_user_id, trust_level,
                    event_type, tool, policy_verdict, params_json, result_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    time.time(),
                    event.session_id,
                    event.channel,
                    event.channel_user_id,
                    event.trust_level,
                    event.event_type,
                    event.tool,
                    event.policy_verdict,
                    event.params_json,
                    event.result_json,
                ),
            )
            row_id = int(cur.lastrowid or 0)
        _sync_commit()
        return row_id


_singleton: AuditStore | None = None


def get_store() -> AuditStore:
    global _singleton
    if _singleton is None:
        init_store()
        _singleton = AuditStore()
    return _singleton


def append(**kwargs: Any) -> int:
    return _append_event(validate_event(**kwargs))


def _append_event(event: AuditEvent) -> int:
    if _remote_append is not None:
        row_id = _remote_append(event.remote_payload())
        if isinstance(row_id, bool) or not isinstance(row_id, int) or row_id <= 0:
            raise RuntimeError("remote audit writer returned an invalid row id")
        return row_id
    return get_store()._append_local(event)


def query(limit: int = 100, session_id: str | None = None, channel: str | None = None) -> list[dict]:
    if _remote_initialize is not None:
        raise RuntimeError("audit query is unavailable through the remote backend")

    q = "SELECT * FROM audit_log"
    where: list[str] = []
    args: list[Any] = []
    if session_id:
        where.append("session_id=?")
        args.append(session_id)
    if channel:
        where.append("channel=?")
        args.append(channel)
    if where:
        q += " WHERE " + " AND ".join(where)
    q += " ORDER BY ts DESC LIMIT ?"
    args.append(limit)
    _sync_reload()
    with _conn() as c:
        return [dict(r) for r in c.execute(q, args).fetchall()]


def schema_version() -> int:
    if _remote_initialize is not None:
        raise RuntimeError("schema version is unavailable through the remote backend")

    _sync_reload()
    with _conn() as c:
        row = c.execute("SELECT MAX(version) AS v FROM audit_schema").fetchone()
        return int(row["v"] or 0)
