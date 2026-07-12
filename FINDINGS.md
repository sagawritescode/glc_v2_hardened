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
