# FINDINGS

Security findings for the migrated, hardened `glc_v1` gateway. Each entry
names the finding, the invariant it broke, the fix, and how to reproduce it
before and after.

## A1 — Public data plane, no auth

**Severity:** critical (abuse, cost amplification, DoS)

**Finding.** The HTTP data plane ran for anyone who knew the URL. `POST
/v1/chat`, `/v1/chat/batch`, `/v1/vision`, `/v1/embed`, `/v1/speak`, and
`/v1/transcribe` had no authentication in front of them, so an unauthenticated
caller could spend provider budget at will. The read-only listing/status
routes (`/v1/status`, `/v1/calls`, `/v1/cost/by_agent`, `/v1/providers`,
`/v1/capabilities`, `/v1/embedders`, `/v1/routers`) likewise leaked usage and
provider configuration. A `curl` against `/v1/chat` returned a provider error,
not `401`.

**Invariant broken.** No unauthenticated access to the data plane — every
request that can spend provider budget (or reveal usage/config) must present a
valid credential before any provider work happens.

**Fix.**
- Added a bearer-token dependency in [glc/security/auth.py](glc/security/auth.py)
  (`require_data_plane_auth`). It reads `GLC_DATA_PLANE_TOKEN`, compares with
  `hmac.compare_digest`, and **fails closed**: if no token is configured,
  protected routes return `503` rather than serving traffic.
- Attached the dependency to the chat, speak, and transcribe routers in
  [glc/main.py](glc/main.py). `/healthz` and `/` stay public; `/v1/control/*`
  keeps its own separate install token.
- The token is a distinct credential from the control-plane install token so
  it can be rotated independently.
- On Modal the token is injected from a Secret (see
  [modal_app.py](modal_app.py)); it is never hardcoded. Create it with:

  ```bash
  modal secret create glc-gateway-auth GLC_DATA_PLANE_TOKEN=$(openssl rand -hex 32)
  ```

**Reproduce (before → after).**

```bash
# Before the fix: reaches the providers, returns a provider error (not 401).
# After the fix: 401 before any provider work.
curl -i -X POST "$URL/v1/chat" \
  -H 'Content-Type: application/json' \
  -d '{"messages":[{"role":"user","content":"hi"}]}'
# => HTTP/1.1 401 Unauthorized

# With the token, the request is admitted to normal gateway handling.
curl -i -X POST "$URL/v1/chat" \
  -H "Authorization: Bearer $GLC_DATA_PLANE_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"messages":[{"role":"user","content":"hi"}]}'

# Health probe stays public.
curl -i "$URL/healthz"
# => HTTP/1.1 200 OK
```

Automated coverage lives in
[tests/test_data_plane_auth.py](tests/test_data_plane_auth.py).

## A2 — Unauthenticated info disclosure

**Severity:** high (recon / info disclosure)

**Finding.** Two surfaces leaked recon-worthy detail to anyone who knew the
URL. The read-only JSON routes (`/v1/status`, `/v1/providers`,
`/v1/capabilities`, `/v1/cost/by_agent`, `/v1/calls`, `/v1/embedders`,
`/v1/routers`) expose provider order, models, rate limits, and usage; and
FastAPI's auto-generated docs (`/docs`, `/redoc`, `/openapi.json`) publish the
full route map. Verified with `curl`: the JSON routes were **already gated by
the A1 data-plane dependency** (they live on `chat_route.router`, so they
return `401` without a bearer token), but the generated docs routes were still
public and returned `200`.

**Invariant broken.** No unauthenticated recon — the route map, provider/model
configuration, rate limits, and usage must not be readable without a
credential. Docs must be secure-by-default (off in production).

**Fix.**
- Confirmed the JSON info routes need no change: A1's
  `require_data_plane_auth` already returns `401` for them without a token.
- Gated the generated docs surface behind an explicit `GLC_ENABLE_DOCS` flag
  in [glc/main.py](glc/main.py). A new `create_app()` factory reads
  `docs_enabled()` and, when the flag is not truthy, constructs the app with
  `docs_url=None`, `redoc_url=None`, and `openapi_url=None` so `/docs`,
  `/redoc`, and `/openapi.json` all return `404`. **Secure by default:** unset
  means off.
- A capability flag (not a `dev`/`prod` stage name) was chosen deliberately so
  the exposure decision is explicit and can't be enabled implicitly by a stage
  label leaking onto a public URL.
- Kept a module-level `app = create_app()` so
  [modal_app.py](modal_app.py) (`from glc.main import app as web`) and the
  `glc.main:app` uvicorn target keep working. Production stays docs-disabled
  because the Modal deploy never sets `GLC_ENABLE_DOCS`.
- Tests opt docs back in (`GLC_ENABLE_DOCS=1` in
  [tests/conftest.py](tests/conftest.py)) because
  [tests/test_v9_compat.py](tests/test_v9_compat.py) reads `/openapi.json` to
  assert the route shape.

**Reproduce (before → after).**

```bash
# Docs route map — public before, 404 after (no GLC_ENABLE_DOCS in prod).
curl -i "$URL/openapi.json"   # before: 200 (full route map) → after: 404
curl -i "$URL/docs"           # before: 200 (Swagger UI)     → after: 404
curl -i "$URL/redoc"          # before: 200 (ReDoc)          → after: 404

# JSON info routes — already gated by A1; 401 without a token.
curl -i "$URL/v1/status"      # => HTTP/1.1 401 Unauthorized
curl -i "$URL/v1/providers"   # => HTTP/1.1 401 Unauthorized

# Health probe stays public.
curl -i "$URL/healthz"        # => HTTP/1.1 200 OK

# Local dev / tests can opt the docs back in explicitly.
GLC_ENABLE_DOCS=1 uvicorn glc.main:app  # /docs, /redoc, /openapi.json → 200
```

Automated coverage lives in
[tests/test_info_disclosure.py](tests/test_info_disclosure.py).

## A3 — Single Function = no egress wall

**Severity:** critical (exfiltration / SSRF / cost & data abuse)

**Finding.** The gateway ran as one Modal Function with unrestricted outbound
network access. A `/v1/chat` error revealed the Function could reach
`googleapis.com`; it could just as easily reach `attacker.example.com`. There
was no egress allowlist, so a prompt-injection / SSRF / compromised-dependency
path could exfiltrate data or call arbitrary hosts.

**Invariant broken.** Egress is restricted to declared provider domains —
untrusted / outbound provider calls must not be able to reach arbitrary hosts.

**Fix.**
- Declared a minimal provider allowlist in
  [glc/egress/allowlist.py](glc/egress/allowlist.py):
  `generativelanguage.googleapis.com`, `api.groq.com`, `api.cerebras.ai`,
  `integrate.api.nvidia.com`, `openrouter.ai`, `models.github.ai`,
  `api.cartesia.ai`, `api.elevenlabs.io`. Exact hostnames only (no `*.`
  wildcards). Dynamic / request-time hosts (user image URLs, webhook targets,
  channel APIs, local Ollama) are deliberately excluded.
- Kept the public FastAPI ASGI app in the Modal Function (auth, validation,
  routing, rate state, DB logging). Relocated the *network* calls into a Modal
  Sandbox created with
  `modal.Sandbox.create(outbound_domain_allowlist=PROVIDER_EGRESS_ALLOWLIST)`.
- Function↔Sandbox boundary:
  [glc/egress/sandbox_client.py](glc/egress/sandbox_client.py) ships a JSON
  command; [glc/egress/worker.py](glc/egress/worker.py) runs inside the
  Sandbox and executes `egress_probe` / `chat` / `embed` / `speak` /
  `transcribe`.
- Chat/embed use drop-in proxies
  ([glc/egress/remote_providers.py](glc/egress/remote_providers.py)) so
  `Router` / failover / retries stay unchanged. Speak/transcribe send
  network-backed prefers through the Sandbox and keep local prefers
  (kokoro, system_fallback, whisper.cpp) in-process.
- [modal_app.py](modal_app.py) injects the egress client into `app.state` at
  deploy time and reuses the same image + `glc-llm-keys` secret (not the
  data-plane auth secret). Scale-to-zero is unchanged (`min_containers=0`).

**Reproduce (before → after).**

Local automated coverage (no live Modal network required):

```bash
GLC_CONFIG_DIR="$PWD/.pytest_glc" GLC_DATA_PLANE_TOKEN=boot-token \
  GLC_ENABLE_DOCS=1 uv run pytest \
  tests/test_egress_allowlist.py \
  tests/test_egress_providers.py \
  tests/test_egress_voice.py -q
rm -rf .pytest_glc
```

These assert the allowlist is passed to `Sandbox.create`, that chat/embed/
speak/transcribe route through the client when the wall is on, and that
local voice prefers skip the Sandbox.

Live Modal verification (the network wall itself; CI cannot enforce this):

```bash
# Against a deployed app / Modal shell: probe a non-provider domain from the
# Sandbox-side worker path. Before A3 the Function could reach it; after A3
# Modal blocks the TLS connection and the worker returns ok=false.
# Example shape (run from a container that has the egress client wired):
python - <<'PY'
from modal_app import build_sandbox_egress_client
c = build_sandbox_egress_client()
print(c.egress_probe("https://example.com"))
# => {"ok": false, "error_type": "ConnectError", ...}   # blocked
print(c.egress_probe("https://api.groq.com"))
# => {"ok": true, "status": ...} or an HTTP response from the host  # allowed
PY

# Legitimate gateway call still reaches a provider domain (mock keys):
curl -i -X POST "$URL/v1/chat" \
  -H "Authorization: Bearer $GLC_DATA_PLANE_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"messages":[{"role":"user","content":"hi"}],"provider":"gemini"}'
# => provider result or provider auth error for the *allowlisted* host —
#    never a successful call to an arbitrary non-provider domain
```

**Residual limitations (documented, out of A3's provider wall).**
- `_resolve_image_urls` in [glc/routes/chat.py](glc/routes/chat.py) can still
  fetch caller-supplied `http(s)` image URLs from the Function. That is a
  separate SSRF surface and is intentionally not on the provider allowlist.
- Channel / webhook outbound hosts remain outside this wall until given their
  own explicit, separately reviewed policy.
- Incremental SSE token streaming across the Sandbox boundary is deferred;
  streaming chat currently returns the full text as one chunk while keeping
  the SSE response envelope.

## A4 — One Secret for the whole Function (leak 1, not closed)

**Severity:** critical (silent key theft)

**Finding.** Provider API keys lived in `os.environ` of the public Modal
Function because [modal_app.py](modal_app.py) mounted `glc-llm-keys`
(`llm_secret`) on the Function alongside the data-plane auth secret. A3 moved
outbound provider HTTP into an allowlisted Sandbox and already passed
`secrets=[llm_secret]` into that Sandbox — but left the same Secret on the
Function. Any in-process code (hostile channel adapter, poisoned dependency,
agent-run / RCE) could still steal every provider key with
`os.environ["GEMINI_API_KEY"]` (Section 2 theft). Move 1 (wrap the monolith)
did not close the leak.

**Invariant broken.** Provider API keys must not appear in the public
Function’s environment. They belong only where provider network calls run
(the A3 Sandbox). The data-plane bearer token may stay on the Function (A1).

**Fix.**
- Named the provider secret env vars in
  [glc/egress/provider_secrets.py](glc/egress/provider_secrets.py)
  (`PROVIDER_SECRET_ENV_VARS`: `GEMINI_API_KEY`, `NVIDIA_API_KEY`,
  `GROQ_API_KEY`, `CEREBRAS_API_KEY`, `OPEN_ROUTER_API_KEY`,
  `GITHUB_ACCESS_TOKEN`, `CARTESIA_API_KEY`, `ELEVENLABS_API_KEY`).
- Added keyless Function-side catalogs in
  [glc/egress/catalog.py](glc/egress/catalog.py)
  (`build_egress_provider_catalog`, `build_egress_router_catalog`,
  `build_egress_embedder_catalog`) so lifespan can register metadata
  (name / model / capabilities / embed rate state) without reading keys.
- [glc/main.py](glc/main.py) lifespan: when `egress_client` is set, use those
  catalogs then `wrap_for_egress`; without egress (local/dev), keep
  `build_providers` / `build_embedders` from env.
- [modal_app.py](modal_app.py): public Function mounts
  `FUNCTION_SECRETS = [auth_secret]` only. Sandbox mounts
  `SANDBOX_SECRETS = [llm_secret]` via `build_sandbox_egress_client()`.
  Real provider objects with real keys are still built inside
  [glc/egress/worker.py](glc/egress/worker.py).

**Reproduce (before → after).**

Local automated coverage:

```bash
GLC_CONFIG_DIR="$PWD/.pytest_glc" GLC_DATA_PLANE_TOKEN=boot-token \
  GLC_ENABLE_DOCS=1 uv run pytest tests/test_secret_isolation.py -q
rm -rf .pytest_glc
```

These assert the secret name set, keyless catalogs, Section 2 probe empty
when egress is on with no provider keys in env, chat/embed still route through
the egress client, and Function vs Sandbox Modal secret wiring
(`llm_secret` not in `FUNCTION_SECRETS`, present in `SANDBOX_SECRETS`).

Section 2 theft probe (Function process / any in-process code):

```python
import os
from glc.egress.provider_secrets import PROVIDER_SECRET_ENV_VARS
stolen = {k: os.environ[k][:4] + "…" for k in PROVIDER_SECRET_ENV_VARS if k in os.environ}
print(stolen)
# Before A4 (Function mounted glc-llm-keys): non-empty → theft succeeds
# After A4: {} → theft fails on the Function path
```

Live Modal note: after redeploy, the same probe inside the public Function
container must be empty; the Sandbox worker process (which mounts
`glc-llm-keys`) still has the keys and can call providers.

**Residual limitations (documented, out of A4).**
- Channel / webhook / OAuth secrets are a separate surface; A4 only isolates
  provider API keys listed in `PROVIDER_SECRET_ENV_VARS`.
- In-process Function code can still *invoke* the Sandbox (cost abuse), but
  cannot read provider keys from Function `os.environ`.
- Local `.env` via `load_dotenv` in [glc/main.py](glc/main.py) can still put
  keys in a non-Modal process; the hardened path is the Modal deploy.
