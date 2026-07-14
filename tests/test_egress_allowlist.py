"""A3 (egress wall) — step 1 regression.

The gateway ran as a single Modal Function with unrestricted outbound network
access, so a prompt-injection / SSRF / compromised-dependency path could reach
any host. The fix runs outbound provider calls inside a Modal Sandbox created
with `outbound_domain_allowlist` limited to the provider domains.

These tests pin the pieces that can be verified without a live Modal network:

- the allowlist is minimal and specific (provider hosts only, no wildcards, no
  attacker-controllable/dynamic hosts),
- the client hands that exact allowlist to `modal.Sandbox.create`, and
- the sandbox-side worker's `egress_probe` reports reachable vs blocked
  correctly (blocked == the transport error a non-allowlisted domain raises).

End-to-end enforcement of the wall (Modal actually blocking a non-allowlisted
domain) is validated against the deployment; see FINDINGS.md A3.
"""

from __future__ import annotations

import json

import httpx
import pytest

from glc.egress import worker
from glc.egress.allowlist import PROVIDER_EGRESS_ALLOWLIST
from glc.egress.sandbox_client import SandboxEgressClient, SandboxEgressError

EXPECTED_PROVIDER_DOMAINS = {
    "generativelanguage.googleapis.com",
    "api.groq.com",
    "api.cerebras.ai",
    "integrate.api.nvidia.com",
    "openrouter.ai",
    "models.github.ai",
    "api.cartesia.ai",
    "api.elevenlabs.io",
}

# Hosts that must NOT be on the provider wall: attacker-controllable or
# request-time-chosen destinations that would reopen the exfiltration surface.
FORBIDDEN_DOMAINS = {
    "example.com",
    "attacker.example.com",
    "graph.facebook.com",  # WhatsApp channel
    "api.telegram.org",  # Telegram channel
    "discord.com",  # Discord channel
    "api.twilio.com",  # Twilio SMS/voice channel
    "login.microsoftonline.com",  # Teams channel
}


def test_allowlist_is_the_minimal_provider_set():
    assert set(PROVIDER_EGRESS_ALLOWLIST) == EXPECTED_PROVIDER_DOMAINS


def test_allowlist_has_no_wildcards():
    # Exact hosts only — `*.` would widen the wall to every subdomain.
    assert all(not d.startswith("*") for d in PROVIDER_EGRESS_ALLOWLIST)


def test_allowlist_excludes_dynamic_and_attacker_hosts():
    for bad in FORBIDDEN_DOMAINS:
        assert bad not in PROVIDER_EGRESS_ALLOWLIST


def test_create_kwargs_carry_the_allowlist():
    client = SandboxEgressClient()
    kwargs = client.sandbox_create_kwargs()
    assert kwargs["outbound_domain_allowlist"] == list(PROVIDER_EGRESS_ALLOWLIST)


def test_create_kwargs_forward_deploy_objects():
    sentinel_app = object()
    sentinel_image = object()
    sentinel_secret = object()
    client = SandboxEgressClient(
        allowlist=["api.groq.com"],
        app=sentinel_app,
        image=sentinel_image,
        secrets=[sentinel_secret],
    )
    kwargs = client.sandbox_create_kwargs()
    assert kwargs["outbound_domain_allowlist"] == ["api.groq.com"]
    assert kwargs["app"] is sentinel_app
    assert kwargs["image"] is sentinel_image
    assert kwargs["secrets"] == [sentinel_secret]


class _FakeStdin:
    def __init__(self):
        self.written = ""

    def write(self, data):
        self.written += data

    def write_eof(self):
        pass

    def drain(self):
        pass


class _FakeStdout:
    def __init__(self, payload: str):
        self._payload = payload

    def read(self):
        return self._payload


class _FakeProc:
    def __init__(self, response: dict):
        self.stdin = _FakeStdin()
        self.stdout = _FakeStdout(json.dumps(response))

    def wait(self):
        return 0


class _FakeSandbox:
    def __init__(self, response: dict, exec_calls: list):
        self._response = response
        self._exec_calls = exec_calls
        self.terminated = False
        self.last_proc: _FakeProc | None = None

    def exec(self, *args):
        self._exec_calls.append(args)
        self.last_proc = _FakeProc(self._response)
        return self.last_proc

    def terminate(self):
        self.terminated = True


def _patch_sandbox_create(monkeypatch, response: dict):
    """Replace modal.Sandbox.create with a recorder returning a fake sandbox."""
    import modal

    recorded: dict = {}
    exec_calls: list = []
    created: list[_FakeSandbox] = []

    def fake_create(**kwargs):
        recorded.update(kwargs)
        sb = _FakeSandbox(response, exec_calls)
        created.append(sb)
        return sb

    monkeypatch.setattr(modal.Sandbox, "create", staticmethod(fake_create))
    return recorded, exec_calls, created


def test_run_passes_allowlist_to_sandbox_create(monkeypatch):
    recorded, exec_calls, created = _patch_sandbox_create(
        monkeypatch, {"ok": True, "status": 200, "final_url": "https://api.groq.com/"}
    )
    client = SandboxEgressClient(allowlist=["api.groq.com"])

    result = client.egress_probe("https://api.groq.com")

    assert result == {"ok": True, "status": 200, "final_url": "https://api.groq.com/"}
    # The A3 invariant: the wall is applied at sandbox creation.
    assert recorded["outbound_domain_allowlist"] == ["api.groq.com"]
    # The worker command was launched and the sandbox torn down.
    assert exec_calls == [("python", "-m", "glc.egress.worker")]
    assert created and created[0].terminated is True
    # The payload was serialized into the worker's stdin.
    assert json.loads(created[0].last_proc.stdin.written)["command"] == "egress_probe"


def test_run_terminates_sandbox_on_worker_failure(monkeypatch):
    import modal

    created: list[_FakeSandbox] = []

    class _BoomProc:
        def __init__(self):
            self.stdin = _FakeStdin()

        @property
        def stdout(self):
            raise RuntimeError("stream broke")

    class _BoomSandbox(_FakeSandbox):
        def exec(self, *args):
            return _BoomProc()

    def fake_create(**kwargs):
        sb = _BoomSandbox({}, [])
        created.append(sb)
        return sb

    monkeypatch.setattr(modal.Sandbox, "create", staticmethod(fake_create))
    client = SandboxEgressClient(allowlist=["api.groq.com"])

    with pytest.raises(SandboxEgressError):
        client.egress_probe("https://api.groq.com")
    assert created and created[0].terminated is True


def test_worker_probe_reports_success(monkeypatch):
    class _Resp:
        status_code = 200
        url = "https://api.groq.com/"

    class _Client:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get(self, url):
            return _Resp()

    monkeypatch.setattr(httpx, "Client", _Client)
    out = worker.handle({"command": "egress_probe", "url": "https://api.groq.com"})
    assert out == {"ok": True, "status": 200, "final_url": "https://api.groq.com/"}


def test_worker_probe_reports_blocked_host(monkeypatch):
    class _Client:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get(self, url):
            # What a Modal-blocked, non-allowlisted domain looks like to httpx.
            raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx, "Client", _Client)
    out = worker.handle({"command": "egress_probe", "url": "https://example.com"})
    assert out["ok"] is False
    assert out["error_type"] == "ConnectError"


def test_worker_probe_requires_url():
    out = worker.handle({"command": "egress_probe"})
    assert out["ok"] is False
    assert "url" in out["error"]


def test_worker_rejects_unknown_command():
    out = worker.handle({"command": "definitely-not-real"})
    assert out["ok"] is False
    assert "unknown command" in out["error"]
