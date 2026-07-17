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

**B1 status — resolved.** The earlier B1 observation (“the environment holds
all keys”) described the deployment before this A4 fix. The current Modal
wiring gives the public Function only `auth_secret`; provider credentials in
`llm_secret` are mounted only in the egress Sandbox. In-process gateway code
can still read the data-plane bearer token and invoke the Sandbox, but it can
no longer read the provider API keys from the Function's `os.environ`.

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

## A6 — Audit db on a Volume with min_containers=0 + autoscale

**Severity:** high (corrupted / split audit trail)

**Finding.** The append-only audit log is SQLite
([glc/audit/store.py](glc/audit/store.py)). On Modal the public Function mounts
`data_volume` at `/data` and sets `min_containers=0` (scale to zero) with no
upper bound, so under load Modal can run **multiple containers at once**.
SQLite does not support concurrent writers safely on a shared filesystem: two
containers appending to the same `audit.sqlite` can corrupt the DB or produce a
**split audit trail** (each container sees different rows). Separately,
`GLC_AUDIT_DB` was unset while only `GLC_CONFIG_DIR=/data/glc` was set, so
audit defaulted to `~/.glc/audit.sqlite` — ephemeral per container — and
Volume writes were never synced with `Volume.commit()` / `Volume.reload()`, so
even a single-writer assumption could lose visibility across restarts.

**Invariant broken.** Invariant 7 — append-only audit trail integrity: every
action is logged, the trail is replayable, and it survives restarts. A
split or corrupted log silently breaks that guarantee.

**Fix.**
- Set `GLC_AUDIT_DB=/data/glc/audit.sqlite` on the deploy image so the audit
  path is explicitly Volume-backed (`AUDIT_DB_PATH` in
  [modal_app.py](modal_app.py)).
- Cap the Function at `max_containers=MAX_CONTAINERS` with `MAX_CONTAINERS = 1`
  so only one process can open the SQLite writer under autoscale.
  (`min_containers=1` alone is not enough — Modal can still scale up.)
- Added optional Volume sync hooks in [glc/audit/store.py](glc/audit/store.py)
  (`register_volume_sync`): `reload()` before any SQLite open,
  `commit()` after append once the connection is closed. Modal’s
  `fastapi_app` registers `data_volume.commit` / `data_volume.reload` at
  startup. Local/dev and tests leave hooks unset (no-op).

**Tradeoff.** The gateway Function no longer horizontally scales past one
container. That is acceptable for coursework / free tier; a dedicated audit
writer Function or a server DB would be needed to scale writers later.

**Reproduce (before → after).**

Local automated coverage:

```bash
GLC_CONFIG_DIR="$PWD/.pytest_glc" GLC_DATA_PLANE_TOKEN=boot-token \
  GLC_ENABLE_DOCS=1 uv run pytest tests/test_audit_log.py \
  tests/test_audit_modal_wiring.py -q
rm -rf .pytest_glc
```

These assert Volume sync hook order (reload before open, commit after append,
query does not commit), no-op without registration, and Modal wiring
(`AUDIT_DB_PATH` under `/data/glc`, `MAX_CONTAINERS == 1`, A4 secrets
unchanged, `register_volume_sync` in `fastapi_app`).

Live Modal (after redeploy):

```bash
# Before: parallel channel WS/webhook traffic while Modal ran 2+ containers
# could leave missing/split rows or a malformed audit.sqlite; audit may also
# have lived under ~/.glc/ and vanished on scale-to-zero.
#
# After: max_containers=1 + GLC_AUDIT_DB on the Volume + commit/reload —
# hammer the same endpoints, then scale to zero and cold-start; row count
# matches events and prior rows are still visible at /data/glc/audit.sqlite.
```

**Residual limitations (documented, out of A6).**
- The gateway call ledger ([glc/db.py](glc/db.py)) and pairing store
  ([glc/security/pairing.py](glc/security/pairing.py)) are the same class of
  SQLite-on-Volume risk under autoscale; A6 scopes to audit only.
- `max_containers=1` serializes all gateway traffic through one container;
  horizontal scale requires a different audit backend or a dedicated writer.

## B2 — Public gateway and adapters could rewrite the audit database

**Severity:** high (audit-history destruction / anti-forensics)

**Status:** partially mitigated; not a complete security-domain separation

**Finding.** The Python audit API exposed only `append()`, but that was an
application convention rather than a storage control. The public Modal Function
mounted the Volume containing `/data/glc/audit.sqlite` and set
`GLC_AUDIT_DB` to that path. Any code running in the gateway process could
bypass [glc/audit/store.py](glc/audit/store.py), open the SQLite file directly,
and issue `UPDATE`, `DELETE`, or `DROP` statements (or unlink the file).

Adapters are explicitly part of this threat model. External adapters should
never receive the audit Volume. More importantly, webhook adapters are loaded
and instantiated inside the public gateway by
[glc/channels/registry.py](glc/channels/registry.py) and
[glc/routes/channels.py](glc/routes/channels.py), so a compromised in-process
adapter inherited every filesystem mount available to that Function. Moving
the audit file to a persistent Volume in A6 fixed restart/concurrent-writer
correctness, but did not stop this operating-system-layer access.

Before B2, code in the public Function could destroy the trail directly:

```python
import sqlite3

sqlite3.connect("/data/glc/audit.sqlite").execute("DELETE FROM audit_log")
```

The equivalent local-development path defaults to `~/.glc/audit.sqlite`.

**Invariant broken.** Invariant 7 — append-only audit trail integrity. Code
being audited must not also have unrestricted filesystem/SQL authority to
rewrite its own evidence.

**Fix.**
- [modal_app.py](modal_app.py) now defines a separate `glc-audit` Volume,
  mounted at `/audit` only on a serialized `AuditWriter` Modal Class. The
  public FastAPI Function keeps the unrelated `glc-data` mount for gateway
  configuration but no longer receives the audit Volume or `GLC_AUDIT_DB`.
- The writer's remotely callable surface is exactly `initialize` and `append`.
  It exposes no arbitrary SQL, update, delete, drop, query, or filesystem
  operation. It is limited to one container and one concurrent input, and it
  owns Volume reload/commit synchronization.
- Production startup registers narrow synchronous callbacks through
  `register_remote_backend()` in [glc/audit/store.py](glc/audit/store.py).
  `init_store()` and `append()` then call the writer and never silently fall
  back to a gateway-local SQLite file.
- Local development and unit tests retain the SQLite backend. Production
  remote mode deliberately disables local `query()`/`schema_version()` rather
  than accidentally creating a second audit database.
- Events are validated before remote submission and again inside the writer.
  Required identity/event fields must be non-empty strings and are bounded to
  128 UTF-8 bytes (`channel`, `trust_level`, `event_type`) or 512 bytes
  (`channel_user_id`). Optional string fields are bounded to 512 bytes.
  Serialized `params` and `result` are limited to 64 KiB each; oversized data
  is rejected, not truncated.

**Failure behavior.** Audit initialization and append calls are synchronous.
Writer/Volume failure aborts application startup or propagates before the
channel reply/adapter send, so required security-relevant processing fails
closed instead of continuing with a missing event. This trades availability
for audit completeness. A response lost after a successful commit remains
ambiguous: a caller retry can create a duplicate because schema v1 has no
idempotency/event key.

**Reproduce / verify.**

```bash
uv run pytest tests/test_audit_log.py tests/test_audit_modal_wiring.py \
  tests/test_audit_remote.py tests/test_secret_isolation.py \
  tests/test_egress_allowlist.py -q
```

The tests verify local SQLite continuity, field/payload validation, no local
fallback in remote mode, propagation of writer failures before adapter send,
the writer's narrow method set, the actual gateway/writer decorator mounts,
and unchanged A3 egress/A4 secret wiring. In particular, the public Function
spec contains only `/data`, while only `AuditWriter` receives
`AUDIT_WRITER_VOLUMES`.

**Residual limitation — B2 is not fully closed in one Modal security domain.**
The repository proves declarative mount separation, but it contains no Modal
workspace role/ACL policy proving that the public Function's runtime identity
cannot resolve `glc-audit`. The gateway already uses that identity to create
Modal Sandboxes dynamically for A3. If the same identity is permitted to call
`Volume.from_name("glc-audit")` and launch another Function/Sandbox with that
Volume mounted, compromised in-process code can regain filesystem access.
This must be checked with a controlled live permission probe in the deployed
workspace; static tests cannot establish the answer.

If that lookup/mount is allowed, this change is only a partial mitigation.
Full isolation requires the writer and Volume to live in a separately
permissioned Modal environment/account, or an external audit service whose
gateway credential grants append-only access. Hash chaining may add tamper
evidence, but does not close this boundary by itself: an attacker with complete
SQLite write access can rebuild or truncate an unanchored chain. A trustworthy
chain head/checkpoint must be stored outside the attacker's security domain.
Local SQLite remains intentionally writable by the local process, and trusted
writer code/operators still retain administrative storage authority.

## B3 — Gateway runtime could force-create an owner

**Severity:** high (in-process privilege escalation)

**Status:** application API fixed; storage and install-token risks remain

**Finding.** `PairingStore.force_pair_owner()` was part of
[glc/security/pairing.py](glc/security/pairing.py), which is imported by the
live gateway and its in-process channel adapters. Any code executing in that
process could call the method and immediately insert an `owner_paired` record
without an installation token, pairing code, or confirmation.

Removing that one method was not sufficient by itself. The same runtime store
also accepted `requested_trust_level="owner_paired"` through `issue_code()`,
after which in-process code could call `confirm_code()` directly. Route-level
authentication did not protect direct Python calls to the store.

**Invariant broken.** First-owner bootstrap must be an installer operation.
The live gateway must neither contain a direct owner writer nor allow owner
pairing to be initiated without the installation token.

**Fix.**
- Removed `force_pair_owner()` from `PairingStore` and from the
  [glc/security](glc/security) export surface.
- Moved the direct first-owner writer to
  [scripts/bootstrap_owner.py](scripts/bootstrap_owner.py). It creates only
  the first owner for a channel and refuses if one already exists.
- Kept the installer writer outside the `glc` package. The Modal image installs
  only the `glc` wheel and copies only the `glc/` directory, so the public
  gateway image does not contain this script.
- `PairingStore.issue_code()` now requires the installation token when
  `owner_paired` is requested. [glc/routes/control.py](glc/routes/control.py)
  passes the already-validated bearer token; normal token-protected owner and
  user pairing continue to work.
- Removed runtime startup owner writes from Gmail, Twilio SMS, and Telegram.
  These processes now verify pre-existing owners and print the trusted setup
  command. Telegram no longer assigns ownership to the first sender.
- Updated setup utilities, development harnesses, documentation, and tests.

For a local installation, bootstrap the first owner before starting the
gateway:

```bash
uv run python scripts/bootstrap_owner.py telegram 123456789 --handle owner
```

For an already-deployed gateway, the operator may retain the existing
token-protected `/v1/control/pair` and `/v1/control/pair/confirm` flow.

**Reproduce / verify.**

```bash
uv run pytest tests/test_owner_bootstrap.py tests/test_pairing.py \
  tests/test_control_plane.py -q
```

The tests prove that the runtime store has no force-owner method, owner code
issuance fails without the install token, the installer writer is excluded
from the gateway image/import graph, first-owner bootstrap refuses a second
owner, and token-protected owner pairing remains functional.

**Residual risks.**
- The pairing SQLite database is also on storage writable by the gateway.
  Compromised in-process code can bypass Python APIs and issue SQL directly.
- Therefore this fix removes the unauthenticated runtime capability and the
  first-sender takeover, but does not create a complete security-domain
  boundary. Full isolation requires pairing writes and token custody in a
  separately permissioned service or Modal environment that the gateway
  identity cannot mount, resolve, or invoke administratively.

## B4 — Install token readable from in-process code

**Severity:** high (control-plane credential theft)

**Status:** application API fixed; residual storage-domain risks remain

**Finding.** `get_or_create_install_token()` in
[glc/config.py](glc/config.py) generated a `secrets.token_urlsafe(32)` once
and persisted the **plaintext** to `$GLC_CONFIG_DIR/install_token` (on Modal,
`/data/glc/install_token`). Any code running inside the gateway process could
read that file or call the helper and obtain the control-plane / WebSocket
credential — then mint owner pairings, connect as any adapter, or enumerate
presence.

**Invariant broken.** The live gateway must be able to *verify* a presented
install token without being able to *recover* the original secret. Token
creation and display are installer operations, not request-handling APIs.

**Fix.**
- Runtime stores only a SHA-256 digest at
  `$GLC_CONFIG_DIR/install_token.hash`. Verification uses
  `hmac.compare_digest` over digests ([glc/config.py](glc/config.py)
  `verify_install_token`).
- Removed `get_or_create_install_token()` and any runtime API that returns the
  raw token. Lifespan calls `ensure_install_token_configured()` (fails closed
  if no digest is present).
- Create / rotate lives in
  [scripts/bootstrap_install_token.py](scripts/bootstrap_install_token.py)
  (outside the `glc` package; not copied into the Modal image). `uv run glc
  token [--rotate]` delegates to that script when available.
- Adapters and bridges read the raw secret from `GLC_INSTALL_TOKEN` via
  `require_install_token_from_env()` — never from the digest file.
- Legacy plaintext `install_token` files are migrated to a digest and deleted
  on first verify/configure.
- Control-plane and channel WebSocket auth continue to accept
  `Authorization: Bearer <token>` (or `?token=` for WS).

Bootstrap (local):

```bash
uv run python scripts/bootstrap_install_token.py
export GLC_INSTALL_TOKEN='<printed-once-value>'
uv run glc serve
```

**Reproduce / verify.**

```bash
uv run pytest tests/test_install_token.py tests/test_control_plane.py \
  tests/test_owner_bootstrap.py tests/test_pairing.py -q
```

The install-token tests prove the digest file never contains the raw secret,
runtime has no raw-token getter, verification is constant-time, legacy
plaintext migrates away, the installer writer is excluded from the gateway
image, and the control plane still accepts a valid bearer.

**Residual risks.**
- Compromised in-process code that can *call* the installer script (or delete
  the digest and coerce an operator re-bootstrap) can still learn a *new*
  token. B4 closes recovery of the *existing* secret from runtime storage.
- If `GLC_INSTALL_TOKEN` is set in the gateway process environment (not only
  in out-of-process adapters), in-process code can read it from `os.environ`.
  Keep that env var on adapter hosts, not on the Modal Function, when possible.
- Overwriting `install_token.hash` on the writable data Volume can lock out
  legitimate operators (availability), analogous to other Volume integrity
  risks (B2).
- Full isolation still requires token verification (and pairing writes) in a
  separately permissioned service that the gateway identity cannot
  administratively remount or rewrite.
