"""Function-side client for the A3 egress wall.

Runs in the public Modal Function. It creates a Modal Sandbox constrained by
`outbound_domain_allowlist` (the minimal provider list) and ships a JSON
command to the Sandbox-side `glc.egress.worker`, then reads the JSON result
back across the process boundary.

`import modal` is deferred to sandbox-creation time so this module (and the
tests that exercise the command shape / allowlist) import cleanly in a plain
local environment. The Modal-specific create + exec I/O is isolated in small
methods so it can be faked in tests and validated for real against a live
deployment.
"""

from __future__ import annotations

import json
from typing import Any

from glc.egress.allowlist import PROVIDER_EGRESS_ALLOWLIST

# Sandbox lifetime knobs. Kept short to stay free-tier friendly: the wall must
# not keep a container alive after the request that needed it is done.
DEFAULT_SANDBOX_TIMEOUT = 300  # hard ceiling on a single sandbox (seconds)
DEFAULT_SANDBOX_IDLE_TIMEOUT = 30  # reap the sandbox after this much inactivity

WORKER_MODULE = "glc.egress.worker"

# The deploy image sets GLC_CONFIG_DIR=/data/glc for the Function (Volume-backed).
# Sandboxes do not mount that Volume by default, and `glc.config` mkdir's the
# config dir on import — so without an override the worker can die before it
# writes any JSON (which surfaces as "empty response from sandbox worker").
# PYTHONPATH=/root matches add_local_dir(..., remote_path="/root/glc").
DEFAULT_SANDBOX_ENV: dict[str, str] = {
    "GLC_CONFIG_DIR": "/tmp/glc",
    "PYTHONPATH": "/root",
}
DEFAULT_SANDBOX_WORKDIR = "/root"


class SandboxEgressError(RuntimeError):
    """Raised when the sandbox boundary itself fails (not a provider error)."""


class SandboxEgressClient:
    """Creates domain-allowlisted Sandboxes and runs worker commands in them.

    The `app`, `image`, and `secrets` are supplied by the deploy wrapper
    (`modal_app.py`) so the Sandbox runs the same code image and provider keys
    as the Function, minus the data-plane auth secret it does not need.
    """

    def __init__(
        self,
        *,
        allowlist: tuple[str, ...] | list[str] = PROVIDER_EGRESS_ALLOWLIST,
        app: Any = None,
        image: Any = None,
        secrets: Any = None,
        volumes: Any = None,
        workdir: str | None = DEFAULT_SANDBOX_WORKDIR,
        env: dict[str, str] | None = None,
        timeout: int = DEFAULT_SANDBOX_TIMEOUT,
        idle_timeout: int = DEFAULT_SANDBOX_IDLE_TIMEOUT,
    ) -> None:
        self.allowlist = list(allowlist)
        self.app = app
        self.image = image
        self.secrets = secrets
        self.volumes = volumes
        self.workdir = workdir
        self.env = dict(DEFAULT_SANDBOX_ENV if env is None else env)
        self.timeout = timeout
        self.idle_timeout = idle_timeout

    def sandbox_create_kwargs(self) -> dict[str, Any]:
        """Build the exact kwargs handed to `modal.Sandbox.create`.

        Pure and side-effect free so tests can assert the egress wall is
        applied without touching Modal. `outbound_domain_allowlist` is the
        A3 invariant made concrete.
        """
        kwargs: dict[str, Any] = {
            "outbound_domain_allowlist": list(self.allowlist),
            "timeout": self.timeout,
            "idle_timeout": self.idle_timeout,
            "env": dict(self.env),
        }
        if self.app is not None:
            kwargs["app"] = self.app
        if self.image is not None:
            kwargs["image"] = self.image
        if self.secrets is not None:
            kwargs["secrets"] = self.secrets
        if self.volumes is not None:
            kwargs["volumes"] = self.volumes
        if self.workdir is not None:
            kwargs["workdir"] = self.workdir
        return kwargs

    def _create_sandbox(self) -> Any:
        import modal

        return modal.Sandbox.create(**self.sandbox_create_kwargs())

    def _exec_json(self, sandbox: Any, payload: dict[str, Any]) -> dict[str, Any]:
        """Send one JSON payload to the worker and read one JSON reply.

        The exact Modal stream API is exercised for real only against a live
        deployment; it is isolated here so the rest of the client stays
        testable with a fake sandbox.
        """
        try:
            proc = sandbox.exec(
                "python", "-m", WORKER_MODULE, workdir=self.workdir, env=self.env
            )
        except TypeError:
            # Unit-test fakes only accept positional args; live Modal accepts
            # workdir/env.
            proc = sandbox.exec("python", "-m", WORKER_MODULE)
        try:
            proc.stdin.write(json.dumps(payload))
            proc.stdin.write_eof()
            proc.stdin.drain()
            out = proc.stdout.read()
            err = ""
            try:
                err = proc.stderr.read() or ""
            except Exception:  # noqa: BLE001 - stderr is diagnostic only
                err = ""
            proc.wait()
        except SandboxEgressError:
            raise
        except Exception as exc:  # noqa: BLE001 - normalize boundary failures
            raise SandboxEgressError(f"sandbox exec failed: {exc}") from exc
        if not out:
            detail = (err.strip() or f"exit={getattr(proc, 'returncode', None)}")[:500]
            raise SandboxEgressError(f"empty response from sandbox worker: {detail}")
        try:
            return json.loads(out)
        except json.JSONDecodeError as exc:
            raise SandboxEgressError(f"non-JSON worker output: {out[:200]!r}") from exc

    def _terminate(self, sandbox: Any) -> None:
        try:
            sandbox.terminate()
        except Exception:  # noqa: BLE001 - teardown is best-effort
            pass

    def run(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Run a single worker command in a fresh domain-allowlisted Sandbox."""
        sandbox = self._create_sandbox()
        try:
            return self._exec_json(sandbox, payload)
        finally:
            self._terminate(sandbox)

    def egress_probe(self, url: str, timeout: float = 10.0) -> dict[str, Any]:
        """Attempt an outbound GET from inside the wall (reachability check)."""
        return self.run({"command": "egress_probe", "url": url, "timeout": timeout})
