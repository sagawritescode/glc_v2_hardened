from pathlib import Path

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

# A6: audit SQLite must live on the Volume (not ~/.glc ephemeral), and only
# one container may write it — SQLite cannot safely share a Volume across
# concurrent writers. Named constants so tests can assert without digging into
# Modal decorator internals.
AUDIT_DB_PATH = "/data/glc/audit.sqlite"
MAX_CONTAINERS = 1

image = (
    modal.Image.from_registry(_BASE_IMAGE)
    .uv_sync(uv_project_dir=".", frozen=True, uv_version=_UV_VERSION)
    .env({
        "GLC_CONFIG_DIR": "/data/glc",
        "GLC_AUDIT_DB": AUDIT_DB_PATH,  # A6: explicit Volume-backed audit path
    })
    # copy=True bakes glc into an Image layer so A3 Sandboxes (same Image) can
    # `import glc`. Default copy=False only mounts for the Function at startup,
    # which is why the worker hit ModuleNotFoundError: No module named 'glc'.
    .add_local_dir(str(Path(__file__).parent / "glc"), remote_path="/root/glc", copy=True)
)
data_volume = modal.Volume.from_name("glc-data", create_if_missing=True)
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
    volumes={"/data": data_volume},
    secrets=FUNCTION_SECRETS,  # A4: no llm_secret
    min_containers=0,  # scale to zero when idle
    max_containers=MAX_CONTAINERS,  # A6: single SQLite writer on the Volume
)
@modal.asgi_app()
def fastapi_app():
    import os

    os.makedirs("/data/glc", exist_ok=True)
    # A6: Volume writes are not visible across containers/restarts until
    # commit/reload. Register before any audit open so init/append see the
    # committed trail after scale-to-zero.
    from glc.audit.store import register_volume_sync

    register_volume_sync(commit=data_volume.commit, reload=data_volume.reload)

    from glc.main import app as web  # the unchanged glc_v1 app
    # A3: route all provider egress through a domain-allowlisted Sandbox.
    # A4: that Sandbox is the only place that receives glc-llm-keys.
    # The lifespan builds keyless catalogs and wraps providers/embedders.
    web.state.egress_client = build_sandbox_egress_client()
    return web
