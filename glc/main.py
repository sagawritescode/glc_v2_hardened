"""FastAPI app for glc_v1. Port 8111 by default. V9 routes are mounted
as-is (S9 Browser / S10 Computer-Use clients work unchanged); the new
S11 surfaces (transcribe, speak, channels WS, control) sit alongside.
"""

from __future__ import annotations

import os
import signal
import time
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import Depends, FastAPI
from fastapi.responses import HTMLResponse

ROOT = Path(__file__).parent
load_dotenv(ROOT.parent / ".env")  # repo .env, if present

from glc import db  # noqa: E402
from glc import embedders as E  # noqa: E402
from glc import providers as P  # noqa: E402
from glc.audit import init_store as init_audit  # noqa: E402
from glc.cache import GeminiCache  # noqa: E402
from glc.config import get_or_create_install_token  # noqa: E402
from glc.policy import reload_engine  # noqa: E402
from glc.routes import channels as channels_route  # noqa: E402
from glc.routes import chat as chat_route  # noqa: E402
from glc.routes import control as control_route  # noqa: E402
from glc.routes import speak as speak_route  # noqa: E402
from glc.routes import transcribe as transcribe_route  # noqa: E402
from glc.routing import Router, RouterPool  # noqa: E402
from glc.security.auth import require_data_plane_auth  # noqa: E402

PORT = int(os.getenv("GLC_PORT", "8111"))

# Truthy values that enable the generated OpenAPI docs surface. Anything else
# (including the variable being unset) keeps docs disabled.
_DOCS_TRUTHY = {"1", "true", "yes", "on"}


def docs_enabled() -> bool:
    """Whether the generated OpenAPI/Swagger/ReDoc surface is exposed.

    A2 (info disclosure): the auto-generated docs routes (/docs, /redoc,
    /openapi.json) publish the full route map, provider order, models, and
    rate limits to anyone who knows the URL. They are disabled by default and
    only enabled when GLC_ENABLE_DOCS is explicitly truthy, so production is
    secure-by-default (the Modal deploy simply never sets the flag) while
    local dev and the test suite can opt in.
    """
    return os.getenv("GLC_ENABLE_DOCS", "").strip().lower() in _DOCS_TRUTHY


def _install_sighup_reload() -> None:
    """Hot-reload policy.yaml on SIGHUP. Windows lacks SIGHUP so this is
    a no-op there."""
    if not hasattr(signal, "SIGHUP"):
        return

    def _handler(signum, frame):  # noqa: ARG001
        try:
            reload_engine()
            print("[glc] policy.yaml reloaded via SIGHUP")
        except Exception as e:
            print(f"[glc] SIGHUP reload failed: {e!r}")

    try:
        signal.signal(signal.SIGHUP, _handler)
    except ValueError:
        # signal() only works on the main thread; tests using TestClient
        # spawn lifespan from a worker thread. Silent skip is correct here.
        pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init()
    init_audit()
    get_or_create_install_token()
    _install_sighup_reload()
    app.state.cache = GeminiCache(ttl_seconds=300)

    # A3 (egress wall) + A4 (secret isolation): when an egress client is present
    # (Modal deploy or a test), build keyless metadata catalogs and wrap them so
    # network calls run in the Sandbox — the Function never needs provider keys
    # in its env. Without a client (local/dev / existing tests), keep the
    # in-process builders that read keys from the environment.
    egress_client = getattr(app.state, "egress_client", None)
    if egress_client is not None:
        from glc.egress.catalog import (
            build_egress_embedder_catalog,
            build_egress_provider_catalog,
            build_egress_router_catalog,
        )
        from glc.egress.remote_providers import wrap_for_egress

        providers = build_egress_provider_catalog()
        router_providers = build_egress_router_catalog()
        embedders, embed_order = build_egress_embedder_catalog()
        providers, router_providers, embedders = wrap_for_egress(
            providers=providers,
            router_providers=router_providers,
            embedders=embedders,
            client=egress_client,
        )
    else:
        providers = P.build_providers(app.state.cache)
        router_providers = P.build_router_providers()
        embedders, embed_order = E.build_embedders()

    app.state.providers = providers
    app.state.router = Router(providers, chat_route.ORDER)
    app.state.router_providers = router_providers
    app.state.router_pool = RouterPool(router_providers, chat_route.ROUTER_ORDER)
    app.state.embedders, app.state.embed_order = embedders, embed_order
    app.state.started_at = time.time()
    app.state.registered_channels = []
    yield


def create_app() -> FastAPI:
    """Build a fresh FastAPI app.

    A factory (rather than a single module-level app) keeps the docs-exposure
    decision testable: each test environment can construct an app with docs on
    or off without cross-test state pollution. modal_app.py and uvicorn still
    import the module-level `app` built from this factory below.
    """
    # A2: disable the generated docs surface unless explicitly enabled. Passing
    # None for these URLs makes /docs, /redoc, and /openapi.json return 404.
    show_docs = docs_enabled()
    fastapi_app = FastAPI(
        title="GLC v2 — Gateway for LLMs and Channels",
        lifespan=lifespan,
        docs_url="/docs" if show_docs else None,
        redoc_url="/redoc" if show_docs else None,
        openapi_url="/openapi.json" if show_docs else None,
    )

    # The data plane (chat/batch/vision/embed/speak/transcribe and the read-only
    # listing/status routes) is gated by a bearer token so it never runs for
    # anyone who merely knows the URL. /healthz and /v1/control/* are exempt:
    # healthz must stay public for probes, and control has its own install token.
    data_plane_auth = [Depends(require_data_plane_auth)]
    fastapi_app.include_router(chat_route.router, dependencies=data_plane_auth)
    fastapi_app.include_router(transcribe_route.router, dependencies=data_plane_auth)
    fastapi_app.include_router(speak_route.router, dependencies=data_plane_auth)
    fastapi_app.include_router(control_route.router)
    fastapi_app.include_router(channels_route.router)

    docs_hint = (
        "<p>Open <code>/docs</code> for the OpenAPI explorer.</p>" if show_docs else ""
    )

    @fastapi_app.get("/", response_class=HTMLResponse)
    async def index() -> str:
        return (
            "<html><body style='font-family:sans-serif;max-width:680px;margin:2em auto'>"
            "<h1>GLC v2</h1>"
            "<p>Gateway for LLMs and Channels — Session 11 scaffold.</p>"
            f"{docs_hint}"
            "<p>Channel adapters connect over <code>WS /v1/channels/&lt;name&gt;</code>."
            " V9 callers should point at this port unchanged: chat, vision, embed,"
            " batch, cost-by-agent, providers, capabilities, status, calls."
            "</p>"
            "</body></html>"
        )

    @fastapi_app.get("/healthz")
    async def healthz():
        return {"ok": True, "port": PORT}

    return fastapi_app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("glc.main:app", host="0.0.0.0", port=PORT, reload=False)
