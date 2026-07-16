from pathlib import Path

import modal

from glc.egress.allowlist import PROVIDER_EGRESS_ALLOWLIST

app = modal.App("glc-v2-gateway")

image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install("fastapi>=0.110", "uvicorn[standard]>=0.27", "httpx>=0.27",
                 "python-dotenv>=1.0", "pydantic>=2.6", "jsonschema>=4.21",
                 "pyyaml>=6.0", "websockets>=12.0")
    .env({"GLC_CONFIG_DIR": "/data/glc"})            # databases land on the Volume
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


@app.function(image=image, volumes={"/data": data_volume},
              secrets=FUNCTION_SECRETS, min_containers=0)  # A4: no llm_secret; scale to zero
@modal.asgi_app()
def fastapi_app():
    import os
    os.makedirs("/data/glc", exist_ok=True)
    from glc.main import app as web    # the unchanged glc_v1 app
    # A3: route all provider egress through a domain-allowlisted Sandbox.
    # A4: that Sandbox is the only place that receives glc-llm-keys.
    # The lifespan builds keyless catalogs and wraps providers/embedders.
    web.state.egress_client = build_sandbox_egress_client()
    return web
