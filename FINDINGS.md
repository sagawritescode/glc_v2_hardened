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
