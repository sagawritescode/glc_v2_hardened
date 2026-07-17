from pathlib import Path, PurePosixPath

import modal

from glc.egress.allowlist import PROVIDER_EGRESS_ALLOWLIST

app = modal.App("glc-v2-gateway")

# A5: reproducible image — immutable base digest + frozen uv.lock (not >= ranges).
# Refresh intentionally: pick a new python:3.11-slim-bookworm amd64 digest,
# run `uv lock`, bump _UV_VERSION when upgrading uv.
_BASE_IMAGE = (
    "python:3.11-slim-bookworm"
    "@sha256:28255a3ace7eb4c48bc1b57b90af29e1bc82b4fd6c60614a8e3dce61b87ff941"
)
_UV_VERSION = "0.8.14"

# B2: audit SQLite lives on a dedicated Volume that the public gateway never
# mounts. The writer serializes access because SQLite plus Volume reload/commit
# is unsafe with concurrent inputs or containers.
AUDIT_VOLUME_MOUNT = "/audit"
AUDIT_DB_PATH = f"{AUDIT_VOLUME_MOUNT}/glc/audit.sqlite"
AUDIT_WRITER_MAX_CONTAINERS = 1
AUDIT_WRITER_MAX_INPUTS = 1
MAX_CONTAINERS = 1

image = (
    modal.Image.from_registry(_BASE_IMAGE)
    .uv_sync(uv_project_dir=".", frozen=True, uv_version=_UV_VERSION)
    .env({
        "GLC_CONFIG_DIR": "/data/glc",
    })
    # copy=True bakes glc into an Image layer so A3 Sandboxes (same Image) can
    # `import glc`. Default copy=False only mounts for the Function at startup,
    # which is why the worker hit ModuleNotFoundError: No module named 'glc'.
    .add_local_dir(str(Path(__file__).parent / "glc"), remote_path="/root/glc", copy=True)
)
data_volume = modal.Volume.from_name("glc-data", create_if_missing=True)
audit_volume = modal.Volume.from_name("glc-audit", create_if_missing=True)

# Named mappings keep the security boundary reviewable and are used directly
# by the decorators below. No public gateway or egress Sandbox receives the
# audit mapping.
VolumeMounts = dict[str | PurePosixPath, modal.Volume | modal.CloudBucketMount]
GATEWAY_VOLUMES: VolumeMounts = {"/data": data_volume}
AUDIT_WRITER_VOLUMES: VolumeMounts = {AUDIT_VOLUME_MOUNT: audit_volume}

# A4: provider API keys (GEMINI_API_KEY, …) live ONLY on the Sandbox below.
# The public Function must not mount this Secret — otherwise any in-process
# code can steal keys via os.environ (Section 2 theft).
llm_secret = modal.Secret.from_name("glc-llm-keys")   # created below, mock values
# Data-plane bearer token. Gates /v1/chat, /embed, /vision, /speak,
# /transcribe and the read-only listing routes (see glc/security/auth.py).
# Create it (never hardcode the token) with, e.g.:
#   modal secret create glc-gateway-auth GLC_DATA_PLANE_TOKEN=$(openssl rand -hex 32)
auth_secret = modal.Secret.from_name("glc-gateway-auth")

# A4 wiring: named lists so tests can assert identity without digging into
# Modal decorator internals. Function = auth only; Sandbox = provider keys.
FUNCTION_SECRETS = [auth_secret]
SANDBOX_SECRETS = [llm_secret]


@app.cls(
    image=image,
    env={"GLC_AUDIT_DB": AUDIT_DB_PATH},
    volumes=AUDIT_WRITER_VOLUMES,
    max_containers=AUDIT_WRITER_MAX_CONTAINERS,
)
@modal.concurrent(max_inputs=AUDIT_WRITER_MAX_INPUTS)
class AuditWriter:
    """Trusted, serialized owner of the audit SQLite file.

    Only schema initialization and validated append are remotely callable.
    Volume synchronization and filesystem access stay inside this container.
    """

    @modal.enter()
    def _configure(self) -> None:
        from glc.audit.store import get_store, register_volume_sync

        register_volume_sync(commit=audit_volume.commit, reload=audit_volume.reload)
        # Ensure every fresh writer container has a committed schema before an
        # append can reload the Volume. get_store() also primes the singleton.
        get_store()
        audit_volume.commit()

    @modal.method()
    def initialize(self) -> None:
        from glc.audit.store import init_store

        init_store()
        audit_volume.commit()

    @modal.method()
    def append(self, event: dict) -> int:
        from glc.audit.store import append as append_audit

        # Validation runs again here, inside the trusted boundary.
        return append_audit(**event)


audit_writer = AuditWriter()


def initialize_remote_audit() -> None:
    """Narrow gateway-side callback registered with the audit facade."""
    audit_writer.initialize.remote()


def append_remote_audit(event: dict) -> int:
    """Synchronously append or raise; never degrade to local persistence."""
    return audit_writer.append.remote(event)


def build_sandbox_egress_client():
    """A3 egress wall + A4 secret isolation: Function-side client that runs
    outbound provider calls inside a Modal Sandbox restricted to
    PROVIDER_EGRESS_ALLOWLIST.

    The Sandbox gets the provider-keys secret (``llm_secret``). The public
    Function does not — it only mounts ``auth_secret``. Auth is enforced here;
    the sandboxed worker never needs the data-plane token. Constructed lazily
    (not at import) so deploy/import stays side-effect free.
    """
    from glc.egress.sandbox_client import SandboxEgressClient

    return SandboxEgressClient(
        allowlist=PROVIDER_EGRESS_ALLOWLIST,
        app=app,
        image=image,
        secrets=SANDBOX_SECRETS,
    )


@app.function(
    image=image,
    volumes=GATEWAY_VOLUMES,
    secrets=FUNCTION_SECRETS,  # A4: no llm_secret
    min_containers=0,  # scale to zero when idle
    max_containers=MAX_CONTAINERS,
)
@modal.asgi_app()
def fastapi_app():
    import os

    os.makedirs("/data/glc", exist_ok=True)
    # B2: production audit operations cross the writer boundary synchronously.
    # Any failure propagates into startup/request handling; there is no local
    # SQLite fallback in the public Function.
    from glc.audit.store import register_remote_backend

    register_remote_backend(
        initialize=initialize_remote_audit,
        append=append_remote_audit,
    )

    from glc.main import app as web  # the unchanged glc_v1 app
    # A3: route all provider egress through a domain-allowlisted Sandbox.
    # A4: that Sandbox is the only place that receives glc-llm-keys.
    # The lifespan builds keyless catalogs and wraps providers/embedders.
    web.state.egress_client = build_sandbox_egress_client()
    return web
