"""Append-only audit log — write correctness, restart survival,
no-update/no-delete surface, and A6 Volume sync hooks."""

from __future__ import annotations

from glc.audit import store
from glc.audit.store import (
    AuditStore,
    append,
    init_store,
    query,
    register_volume_sync,
    schema_version,
)


def test_init_then_append():
    init_store()
    rid = append(
        channel="telegram",
        channel_user_id="42",
        trust_level="owner_paired",
        event_type="inbound_message",
        session_id="s1",
        params={"text": "hi"},
    )
    assert rid > 0
    rows = query(limit=5)
    assert len(rows) == 1
    assert rows[0]["channel"] == "telegram"
    assert rows[0]["event_type"] == "inbound_message"


def test_write_survives_restart(monkeypatch, tmp_path):
    init_store()
    append(channel="x", channel_user_id="1", trust_level="owner_paired", event_type="boot")
    store._singleton = None  # simulate process restart
    rows = query(limit=10)
    assert len(rows) == 1


def test_store_exposes_no_update_or_delete():
    s = AuditStore()
    assert not hasattr(s, "update")
    assert not hasattr(s, "delete")
    public = [n for n in dir(s) if not n.startswith("_")]
    assert "append" in public
    assert len([n for n in public if n in ("update", "delete", "modify")]) == 0


def test_schema_version_is_one():
    init_store()
    assert schema_version() == 1


def test_query_filters_by_session_and_channel():
    init_store()
    append(
        channel="discord", channel_user_id="1", trust_level="owner_paired", event_type="x", session_id="s-A"
    )
    append(
        channel="telegram", channel_user_id="1", trust_level="owner_paired", event_type="x", session_id="s-B"
    )
    rows = query(session_id="s-A")
    assert len(rows) == 1
    assert rows[0]["channel"] == "discord"
    rows = query(channel="telegram")
    assert len(rows) == 1


def test_jsonifies_complex_params():
    init_store()
    append(
        channel="x",
        channel_user_id="1",
        trust_level="owner_paired",
        event_type="x",
        params={"nested": {"k": [1, 2, 3]}},
    )
    rows = query(limit=1)
    assert "nested" in rows[0]["params_json"]


# ── A6: optional Volume commit/reload hooks ─────────────────────────────────


def test_volume_sync_noop_without_registration():
    """Local/dev path: no hooks registered → append still works."""
    assert store._volume_commit is None
    assert store._volume_reload is None
    init_store()
    rid = append(
        channel="x",
        channel_user_id="1",
        trust_level="owner_paired",
        event_type="noop",
    )
    assert rid > 0
    assert len(query(limit=5)) == 1


def test_volume_sync_reload_on_init_and_query():
    events: list[str] = []

    def commit() -> None:
        events.append("commit")

    def reload() -> None:
        events.append("reload")

    register_volume_sync(commit=commit, reload=reload)
    events.clear()
    init_store()
    assert events == ["reload"]

    events.clear()
    query(limit=1)
    assert events == ["reload"]


def test_volume_sync_commit_after_append():
    """Append must reload before open and commit after the connection closes."""
    events: list[str] = []

    def commit() -> None:
        events.append("commit")

    def reload() -> None:
        events.append("reload")

    register_volume_sync(commit=commit, reload=reload)
    init_store()
    store._singleton = None
    events.clear()

    rid = append(
        channel="x",
        channel_user_id="1",
        trust_level="owner_paired",
        event_type="inbound_message",
    )
    assert rid > 0
    # get_store → init_store (reload) then AuditStore.append (reload, commit)
    assert events == ["reload", "reload", "commit"]
    assert events[-1] == "commit"


def test_volume_sync_query_does_not_commit():
    events: list[str] = []

    def commit() -> None:
        events.append("commit")

    def reload() -> None:
        events.append("reload")

    register_volume_sync(commit=commit, reload=reload)
    init_store()
    append(channel="x", channel_user_id="1", trust_level="owner_paired", event_type="x")
    events.clear()
    rows = query(limit=10)
    assert len(rows) == 1
    assert events == ["reload"]
    assert "commit" not in events
