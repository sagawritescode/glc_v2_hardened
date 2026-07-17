"""B2 remote audit dispatch and fail-closed request behavior."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from glc.audit.store import (
    AuditStore,
    AuditValidationError,
    append,
    init_store,
    query,
    register_remote_backend,
)
from glc.channels.envelope import ChannelMessage


def _event(**overrides):
    event = {
        "channel": "webhook",
        "channel_user_id": "42",
        "trust_level": "owner_paired",
        "event_type": "inbound_message",
    }
    event.update(overrides)
    return event


def test_remote_backend_handles_init_and_append_without_local_db(monkeypatch, tmp_path):
    local_path = tmp_path / "must-not-exist.sqlite"
    monkeypatch.setenv("GLC_AUDIT_DB", str(local_path))
    calls = []

    def remote_init():
        calls.append(("initialize", None))

    def remote_append(event):
        calls.append(("append", event))
        return 17

    register_remote_backend(initialize=remote_init, append=remote_append)
    init_store()
    row_id = append(**_event(params={"text": "hello"}))

    assert row_id == 17
    assert calls[0] == ("initialize", None)
    assert calls[1][0] == "append"
    assert calls[1][1]["params"] == '{"text": "hello"}'
    assert not local_path.exists()


def test_audit_store_instance_also_uses_remote_backend():
    received = []
    register_remote_backend(initialize=lambda: None, append=lambda event: received.append(event) or 9)

    assert AuditStore().append(**_event()) == 9
    assert received[0]["event_type"] == "inbound_message"


def test_remote_append_failure_propagates_without_local_fallback(monkeypatch, tmp_path):
    local_path = tmp_path / "must-not-exist.sqlite"
    monkeypatch.setenv("GLC_AUDIT_DB", str(local_path))

    def unavailable(_event):
        raise ConnectionError("audit writer unavailable")

    register_remote_backend(initialize=lambda: None, append=unavailable)

    with pytest.raises(ConnectionError, match="audit writer unavailable"):
        append(**_event())

    assert not local_path.exists()


def test_remote_initialization_failure_propagates_without_local_fallback(monkeypatch, tmp_path):
    local_path = tmp_path / "must-not-exist.sqlite"
    monkeypatch.setenv("GLC_AUDIT_DB", str(local_path))

    def unavailable():
        raise ConnectionError("audit writer unavailable")

    register_remote_backend(initialize=unavailable, append=lambda _event: 1)

    with pytest.raises(ConnectionError, match="audit writer unavailable"):
        init_store()

    assert not local_path.exists()


def test_validation_runs_before_remote_submission():
    submitted = []
    register_remote_backend(initialize=lambda: None, append=lambda event: submitted.append(event) or 1)

    with pytest.raises(AuditValidationError):
        append(**_event(channel=""))

    assert submitted == []


@pytest.mark.parametrize("invalid_row_id", [None, 0, -1, True, "1"])
def test_invalid_remote_row_id_fails_closed(invalid_row_id):
    register_remote_backend(initialize=lambda: None, append=lambda _event: invalid_row_id)

    with pytest.raises(RuntimeError, match="invalid row id"):
        append(**_event())


def test_remote_mode_does_not_fall_back_for_reads(monkeypatch, tmp_path):
    local_path = tmp_path / "must-not-exist.sqlite"
    monkeypatch.setenv("GLC_AUDIT_DB", str(local_path))
    register_remote_backend(initialize=lambda: None, append=lambda _event: 1)

    with pytest.raises(RuntimeError, match="query is unavailable"):
        query()

    assert not local_path.exists()


def test_webhook_does_not_send_reply_when_required_audit_append_fails(
    app_client, monkeypatch
):
    from glc.routes import channels

    class AuditUnavailable(RuntimeError):
        pass

    class FakeAdapter:
        def __init__(self):
            self.sent = []

        async def on_message(self, _raw):
            return ChannelMessage(
                channel="webhook",
                channel_user_id="42",
                user_handle="owner",
                text="security-relevant message",
                trust_level="owner_paired",
                arrived_at=datetime.now(UTC),
            )

        async def send(self, reply):
            self.sent.append(reply)

    class FakePairings:
        @staticmethod
        def owners(*, channel):
            return []

    class FakeLimiter:
        @staticmethod
        def check_message(_channel, _channel_user_id):
            return True, ""

    adapter = FakeAdapter()
    monkeypatch.setattr(channels.registry, "instantiate", lambda _name: adapter)
    monkeypatch.setattr(channels, "get_pairing_store", lambda: FakePairings())
    monkeypatch.setattr(channels, "get_rate_limiter", lambda: FakeLimiter())
    monkeypatch.setattr(channels, "allowed", lambda *_args, **_kwargs: (True, ""))

    def fail_audit(**_event):
        raise AuditUnavailable("audit writer unavailable")

    monkeypatch.setattr(channels, "audit_append", fail_audit)

    with pytest.raises(AuditUnavailable, match="audit writer unavailable"):
        app_client.post("/v1/channels/webhook/webhook", content=b"payload")

    assert adapter.sent == []
