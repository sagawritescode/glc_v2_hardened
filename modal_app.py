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
    .add_local_dir(str(Path(__file__).parent / "glc"), remote_path="/root/glc")
)
data_volume = modal.Volume.from_name("glc-data", create_if_missing=True)
llm_secret = modal.Secret.from_name("glc-llm-keys")   # created below, mock values
# Data-plane bearer token. Gates /v1/chat, /embed, /vision, /speak,
# /transcribe and the read-only listing routes (see glc/security/auth.py).
# Create it (never hardcode the token) with, e.g.:
#   modal secret create glc-gateway-auth GLC_DATA_PLANE_TOKEN=$(openssl rand -hex 32)
auth_secret = modal.Secret.from_name("glc-gateway-auth")


def build_sandbox_egress_client():
    """A3 egress wall: build the Function-side client that runs the gateway's
    outbound provider calls inside a Modal Sandbox restricted to the provider
    domains in PROVIDER_EGRESS_ALLOWLIST.

    The Sandbox reuses the same code image and the provider-keys secret, but
    NOT the data-plane auth secret — auth is enforced by the public Function,
    so the sandboxed worker never needs it. Constructed lazily (not at import)
    so deploy/import stays side-effect free; routes begin using it in a later
    checkpoint.
    """
    from glc.egress.sandbox_client import SandboxEgressClient

    return SandboxEgressClient(
        allowlist=PROVIDER_EGRESS_ALLOWLIST,
        app=app,
        image=image,
        secrets=[llm_secret],
    )


@app.function(image=image, volumes={"/data": data_volume},
              secrets=[llm_secret, auth_secret], min_containers=0)  # scale to zero -> free tier
@modal.asgi_app()
def fastapi_app():
    import os
    os.makedirs("/data/glc", exist_ok=True)
    from glc.main import app as web    # the unchanged glc_v1 app
    # A3: route all provider egress through a domain-allowlisted Sandbox. The
    # lifespan reads this and wraps the providers/embedders before serving.
    web.state.egress_client = build_sandbox_egress_client()
    return web
