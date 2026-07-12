import modal
from pathlib import Path

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

@app.function(image=image, volumes={"/data": data_volume},
              secrets=[llm_secret, auth_secret], min_containers=0)  # scale to zero -> free tier
@modal.asgi_app()
def fastapi_app():
    import os
    os.makedirs("/data/glc", exist_ok=True)
    from glc.main import app as web    # the unchanged glc_v1 app
    return web
